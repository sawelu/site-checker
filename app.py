import concurrent.futures
import datetime
import ipaddress
import socket
import ssl
import subprocess
import time

import dns.resolver
import dns.reversename
import whois
from flask import Flask, render_template, request

app = Flask(__name__)

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]

PORTS = [
    (21, "FTP"), (22, "SSH"), (25, "SMTP"), (80, "HTTP"), (110, "POP3"),
    (143, "IMAP"), (443, "HTTPS"), (993, "IMAPS"), (995, "POP3S"),
    (3306, "MySQL"), (5432, "PostgreSQL"), (8080, "HTTP-альтернативный"),
]

USER_AGENT = "SiteChecker/1.0"

STATUS_LABELS = {"ok": "OK", "warn": "Внимание", "bad": "Проблема", "info": "Инфо"}


# ---------- DNS ----------

def _resolve(name, rdtype, nameserver=None, timeout=5):
    resolver = dns.resolver.Resolver(configure=True)
    resolver.lifetime = timeout
    if nameserver:
        resolver.nameservers = [nameserver]
    try:
        answer = resolver.resolve(name, rdtype)
        records = []
        for rdata in answer:
            if rdtype == "MX":
                records.append({"priority": rdata.preference, "value": rdata.exchange.to_text()})
            elif rdtype == "SOA":
                records.append({
                    "value": str(rdata),
                    "mname": rdata.mname.to_text(),
                    "rname": rdata.rname.to_text(),
                    "serial": rdata.serial,
                })
            elif rdtype == "TXT":
                records.append({"value": b"".join(rdata.strings).decode("utf-8", "replace")})
            else:
                records.append({"value": rdata.to_text()})
        return {"ok": True, "records": records, "ttl": answer.rrset.ttl if answer.rrset else None}
    except dns.resolver.NXDOMAIN:
        return {"ok": False, "error": "Домен не существует (NXDOMAIN)", "records": []}
    except dns.resolver.NoAnswer:
        return {"ok": False, "error": "Записей нет (NoAnswer)", "records": []}
    except dns.resolver.NoNameservers:
        return {"ok": False, "error": "NS-серверы не ответили", "records": []}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "records": []}


def check_dns_records(domain):
    results = {}
    for rtype in RECORD_TYPES:
        results[rtype] = _resolve(domain, rtype)
    return results


def check_mail_auth(domain):
    return {
        "SPF": _resolve(domain, "TXT"),
        "DMARC": _resolve(f"_dmarc.{domain}", "TXT"),
        "DKIM": _resolve(f"default._domainkey.{domain}", "TXT"),
    }


def check_ns_servers(domain):
    ns_result = _resolve(domain, "NS")
    if not ns_result["ok"]:
        return {"list_ok": False, "error": ns_result["error"], "servers": []}

    nameservers = sorted({r["value"].rstrip(".") for r in ns_result["records"]})
    servers = []

    def probe(ns):
        ips = _resolve(ns, "A")
        if ips["ok"]:
            ip_list = [r["value"] for r in ips["records"]]
        else:
            ip_list = []
        ips6 = _resolve(ns, "AAAA")
        if ips6["ok"]:
            ip_list += [r["value"] for r in ips6["records"]]

        ns_answer = None
        latency = None
        for ip in ip_list:
            start = time.monotonic()
            ns_answer = _resolve(domain, "A", nameserver=ip, timeout=5)
            latency = round((time.monotonic() - start) * 1000, 1)
            if ns_answer.get("ok"):
                break
        return {
            "name": ns,
            "ips": ip_list,
            "ips_ok": bool(ip_list),
            "answers_ok": bool(ns_answer and ns_answer.get("ok")),
            "answer": ns_answer,
            "latency_ms": latency,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        servers = list(pool.map(probe, nameservers))

    return {"list_ok": True, "servers": servers}


# ---------- HTTP / https ----------

def _host_ips(host):
    ips = []
    a = _resolve(host, "A")
    if a["ok"]:
        ips += [r["value"] for r in a["records"]]
    aaaa = _resolve(host, "AAAA")
    if aaaa["ok"]:
        ips += [r["value"] for r in aaaa["records"]]
    return ips or [host]


def _http_request(host, scheme, ip, path="/", timeout=8, level=0):
    ctx = None
    port = 443 if scheme == "https" else 80
    if scheme == "https":
        ctx = ssl.create_default_context()
    sock = socket.create_connection((ip, port), timeout=timeout)
    try:
        if ctx:
            sock = ctx.wrap_socket(sock, server_hostname=host)
        import http.client
        conn = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
        c = conn(host, port, timeout=timeout)
        c.sock = sock
        c.request("GET", path, headers={
            "User-Agent": USER_AGENT,
            "Accept-Encoding": "identity",
            "Host": host,
            "Connection": "close",
        })
        resp = c.getresponse()
        body = resp.read(200_000)
        return {
            "status": resp.status,
            "reason": resp.reason,
            "headers": dict((k.lower(), v) for k, v in resp.getheaders()),
            "body_len": len(body),
        }
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _fetch_with_redirects(host, scheme, path, timeout=8, max_hops=5):
    chain = []
    cur_host, cur_scheme, cur_path = host, scheme, path
    for _ in range(max_hops + 1):
        ips = _host_ips(cur_host)
        last_err = None
        for ip in ips:
            start = time.monotonic()
            try:
                res = _http_request(cur_host, cur_scheme, ip, cur_path, timeout)
                elapsed = round((time.monotonic() - start) * 1000, 1)
                break
            except Exception as e:
                last_err = f"{type(e).__name__}: {e}"
                elapsed = round((time.monotonic() - start) * 1000, 1)
        else:
            return {"ok": False, "chain": chain, "last_err": last_err}

        loc = res["headers"].get("location", res["headers"].get("Location"))
        if res["status"] in (301, 302, 303, 307, 308) and loc:
            chain.append({"scheme": cur_scheme, "host": cur_host, "status": res["status"],
                          "reason": res["reason"], "time_ms": elapsed})
            from urllib.parse import urlparse
            p = urlparse(loc)
            cur_host = p.hostname or cur_host
            cur_scheme = p.scheme or cur_scheme
            cur_path = p.path or "/"
            if p.query:
                cur_path += "?" + p.query
            continue
        return {"ok": True, "chain": chain, "final": {
            "scheme": cur_scheme, "host": cur_host, "url": f"{cur_scheme}://{cur_host}{cur_path}",
            "status": res["status"], "reason": res["reason"],
            "server": res["headers"].get("server"), "content_type": res["headers"].get("content-type"),
            "last_modified": res["headers"].get("last-modified"),
            "size": res["body_len"], "time_ms": elapsed,
        }}
    return {"ok": False, "chain": chain, "last_err": "Слишком много редиректов"}


def check_http(domain):
    result = {"checks": [], "final": None, "reachable": False}
    for scheme in ("https", "http"):
        entry = {"scheme": scheme, "url": f"{scheme}://{domain}/", "ok": False}
        try:
            res = _fetch_with_redirects(domain, scheme, "/")
            if res["ok"]:
                entry.update({"ok": True, "chain": res["chain"], **res["final"]})
                result["reachable"] = True
                if result["final"] is None:
                    result["final"] = res["final"]
            else:
                entry["reason"] = res.get("last_err") or "недоступен"
                if res["chain"]:
                    entry["chain"] = res["chain"]
        except Exception as e:
            entry["reason"] = f"{type(e).__name__}: {e}"
        request_start = time.monotonic()
        result["checks"].append(entry)
        if result["reachable"]:
            break
    return result


# ---------- SSL ----------

def check_ssl(hostname, timeout=8):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                chain = []
                try:
                    raw_chain = tls.getpeercertchain()
                    chain = raw_chain or []
                except (AttributeError, ssl.SSLError):
                    pass

                def flat(tuples):
                    parts = []
                    for group in tuples or ():
                        if not isinstance(group, (list, tuple)):
                            parts.append(str(group))
                            continue
                        for item in group:
                            if isinstance(item, (list, tuple)) and len(item) >= 2:
                                parts.append(f"{item[0]}={item[1]}")
                            elif isinstance(item, (list, tuple)):
                                parts.append(" ".join(str(x) for x in item))
                            else:
                                parts.append(str(item))
                    return ", ".join(parts)

                not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                not_before = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                days_left = (not_after - now).days
                san = [item for _, item in cert.get("subjectAltName", ())]

                status = "ok"
                if days_left < 0:
                    status = "bad"
                elif days_left <= 30:
                    status = "warn"

                return {
                    "has_ssl": True,
                    "status": status,
                    "issuer": flat(cert.get("issuer", ())),
                    "subject": flat(cert.get("subject", ())),
                    "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "days_left": days_left,
                    "san": san,
                    "tls_version": tls.version(),
                    "chain_len": len(chain),
                    "chain_ok": ctx.verify_flags == ssl.VERIFY_DEFAULT,
                    "error": None,
                }
    except socket.timeout:
        return {"has_ssl": False, "status": "bad", "error": "Таймаут подключения к порту 443"}
    except ssl.SSLError as e:
        return {"has_ssl": False, "status": "bad", "error": f"SSL-ошибка: {e}"}
    except Exception as e:
        return {"has_ssl": False, "status": "bad", "error": f"{type(e).__name__}: {e}"}


# ---------- Ping ----------

def check_ping(host, timeout=4):
    flags = ["-c", "1", "-W", "3"]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        host_ping = host
    cmd = ["ping", *flags, host]
    start = time.monotonic()
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = round((time.monotonic() - start) * 1000, 1)
        if out.returncode == 0:
            m = [line for line in out.stdout.splitlines() if "time=" in line]
            detail = m[0].strip() if m else out.stdout.strip().splitlines()[-1]
            return {"ok": True, "status": "ok", "time_ms": elapsed, "detail": detail,
                    "host": host}
        last = out.stderr.strip().splitlines()
        return {"ok": False, "status": "bad", "reason": (last[-1] if last else "пинг не прошёл"),
                "detail": "", "host": host, "time_ms": elapsed}
    except subprocess.TimeoutExpired:
        return {"ok": False, "status": "bad", "reason": "таймаут", "detail": "", "host": host}
    except FileNotFoundError:
        return {"ok": False, "status": "info", "reason": "утилита ping недоступна", "detail": "", "host": host}


# ---------- Ports ----------

def check_ports(host, timeout=2.5):
    results = []

    def probe(port, name):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.monotonic()
        try:
            s.connect((host, port))
            state = "open"
            detail = "открыт"
            status = "ok"
        except (socket.timeout, TimeoutError, ConnectionRefusedError, OSError):
            state = "closed"
            detail = "закрыт/недоступен"
            status = "info" if port in (25, 110, 143, 3306, 5432) else "info"
        finally:
            elapsed = round((time.monotonic() - start) * 1000, 1)
            s.close()
        if port in (80, 443) and state == "closed":
            status = "bad"
        return {"port": port, "name": name, "state": state, "detail": detail,
                "time_ms": elapsed, "status": status}

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda p: probe(*p), PORTS))

    open_count = sum(1 for r in results if r["state"] == "open")
    return {"results": results, "open_count": open_count}


# ---------- WHOIS ----------

def check_whois(domain):
    try:
        info = whois.whois(domain)
        clean = []
        seen = set()
        for key, value in info.items():
            if value in (None, [], "", "None"):
                continue
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value)
            entry = (str(key), str(value))
            if entry in seen:
                continue
            seen.add(entry)
            clean.append({"key": str(key), "value": str(value)})
        return {"ok": True, "records": clean, "error": None}
    except Exception as e:
        return {"ok": False, "records": [], "error": f"{type(e).__name__}: {e}"}


# ---------- Summary ----------

def build_summary(report):
    dns_have = report["records"]["A"]["ok"] and bool(report["records"]["A"]["records"])
    ns_have = report["ns_check"]["list_ok"]
    issues = []

    ssl = report["ssl"]
    http = report["http"]
    ping = report["ping"]
    ports = report["ports"]

    if dns_have:
        issues.append({"status": "ok", "title": "DNS: A-записи найдены",
                       "detail": "домен резолвится в IP"})
    else:
        issues.append({"status": "bad", "title": "DNS: A-записи не найдены",
                       "detail": report["records"]["A"].get("error", "")})

    if ns_have:
        bad_ns = [s for s in report["ns_check"]["servers"] if s["ips_ok"] and not s["answers_ok"]]
        if bad_ns:
            issues.append({"status": "warn", "title": "NS-серверы не отвечают",
                           "detail": ", ".join(s["name"] for s in bad_ns)})
        else:
            issues.append({"status": "ok", "title": "NS-серверы отвечают",
                           "detail": f"{len(report['ns_check']['servers'])} шт."})

    mail = report["mail_auth"]
    spf_ok = any("v=spf1" in r["value"] for r in mail["SPF"]["records"])
    dmarc_ok = any("v=DMARC1" in r["value"] for r in mail["DMARC"]["records"])
    dkim_ok = any("v=DKIM1" in r["value"] for r in mail["DKIM"]["records"])
    if spf_ok and dmarc_ok and dkim_ok:
        issues.append({"status": "ok", "title": "Почтовая защита",
                       "detail": "SPF, DMARC и DKIM настроены"})
    elif spf_ok or dmarc_ok or dkim_ok:
        missing = [k for k, ok in (("SPF", spf_ok), ("DMARC", dmarc_ok), ("DKIM", dkim_ok)) if not ok]
        issues.append({"status": "warn", "title": "Почтовая защита неполная",
                       "detail": "нет " + ", ".join(missing)})
    else:
        issues.append({"status": "info", "title": "Почтовая защита",
                       "detail": "SPF/DMARC/DKIM не найдены"})

    if http["reachable"]:
        f = http["final"]
        if f["status"] < 400:
            issues.append({"status": "ok", "title": f"HTTP {f['status']}",
                           "detail": f"{f['scheme'].upper()}: {f['time_ms']} мс, {f['size']} байт"})
        else:
            issues.append({"status": "bad", "title": f"HTTP {f['status']}",
                           "detail": f"{f['scheme'].upper()}: {f['reason']}"})
    else:
        issues.append({"status": "bad", "title": "Сайт недоступен",
                       "detail": "нет ответа ни по HTTP, ни по HTTPS"})

    if ssl["has_ssl"]:
        if ssl["status"] == "ok":
            issues.append({"status": "ok", "title": "SSL валиден",
                           "detail": f"истекает через {ssl['days_left']} дн."})
        elif ssl["status"] == "warn":
            issues.append({"status": "warn", "title": "SSL истекает скоро",
                           "detail": f"осталось {ssl['days_left']} дн."})
        else:
            issues.append({"status": "bad", "title": "SSL просрочен",
                           "detail": f"истёк {abs(ssl['days_left'])} дн. назад"})
    else:
        issues.append({"status": "bad", "title": "SSL отсутствует",
                       "detail": ssl.get("error", "порт 443 не отвечает")})

    if ping.get("ok"):
        issues.append({"status": "ok", "title": "Пинг работает", "detail": f"{ping['time_ms']} мс"})
    else:
        issues.append({"status": "info", "title": "Пинг", "detail": ping.get("reason", "недоступен")})

    web_open = any(r["port"] in (80, 443) and r["state"] == "open" for r in ports["results"])
    if web_open:
        issues.append({"status": "ok", "title": "Веб-порты открыты",
                       "detail": f"открыто портов: {ports['open_count']}/{len(PORTS)}"})
    else:
        issues.append({"status": "bad", "title": "Веб-порты закрыты",
                       "detail": "80/443 недоступны"})

    counts = {"ok": 0, "warn": 0, "bad": 0, "info": 0}
    for i in issues:
        counts[i["status"]] += 1

    if counts["bad"]:
        verdict = {"status": "bad", "label": "Сайт неисправен", "hint": "есть проблемы, требующие внимания"}
    elif counts["warn"]:
        verdict = {"status": "warn", "label": "Есть замечания", "hint": "некоторые параметры требуют внимания"}
    else:
        verdict = {"status": "ok", "label": "Сайт в порядке", "hint": "все основные проверки пройдены"}

    return {"issues": issues, "counts": counts, "verdict": verdict}


# ---------- Routes ----------

def normalize_domain(raw):
    domain = raw.strip().lower()
    for prefix in ("http://", "https://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0].split("?")[0].split("#")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    return domain.rstrip(".")


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", domain=None, report=None, error=None)


@app.route("/check", methods=["POST"])
def check():
    domain = normalize_domain(request.form.get("domain", ""))
    if not domain:
        return render_template(
            "index.html", domain=domain, report=None,
            error="Введите доменное имя, например example.com"
        )
    try:
        ipaddress.ip_address(domain)
        return render_template(
            "index.html", domain=domain, report=None,
            error=f"«{domain}» — это IP-адрес, а не домен. Введите доменное имя, например example.com"
        )
    except ValueError:
        pass
    if "." not in domain:
        return render_template(
            "index.html", domain=domain, report=None,
            error="Введите корректное доменное имя, например example.com"
        )

    report = {
        "domain": domain,
        "records": check_dns_records(domain),
        "mail_auth": check_mail_auth(domain),
        "ns_check": check_ns_servers(domain),
        "whois": check_whois(domain),
        "http": check_http(domain),
        "ssl": check_ssl(domain),
        "ping": check_ping(domain),
        "ports": check_ports(domain),
    }
    report["summary"] = build_summary(report)
    return render_template("index.html", domain=domain, report=report, error=None)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)