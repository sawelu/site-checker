# CLI-инструкции: те же проверки без программы

Всё, что делает Site Checker, доступно стандартными утилитами Linux/macOS.
Под каждым заголовком указано, какой модуль приложения он заменяет, и итоговый пайплайн команд.

> Домен в примерах — `example.com`. Команды ниже выполняются в редактируемой оболочке или одной строкой.

---

## 1. DNS-записи (модуль «Записи домена»)

**Утилита:** `dig` (входит в `dnsutils` / `bind9-utils`), есть также `host` и `nslookup`.

```bash
dig +short example.com A          # IP-адреса сайта (IPv4)
dig +short example.com AAAA       # IP-адреса (IPv6)
dig +short example.com CNAME      # каноническое имя (если есть)
dig +short example.com MX         # почтовые серверы + приоритеты
dig +short example.com NS         # DNS-серверы домена
dig +short example.com TXT        # TXT-записи (SPF, проверки владения и т.п.)
dig +short example.com SOA        # SOA (серийный номер и т.п.)
dig +short example.com CAA        # какие CA могут выпускать сертификаты
```

Детальный вывод (с TTL, «хвостами» имён):

```bash
dig example.com ANY               # все записи сразу (внимание: не все серверы отвечают)
dig +noall +answer example.com MX
```

## 2. Проверка NS-серверов напрямую (модуль «NS-серверы»)

Запрос проходит через системный резолвер по умолчанию. Чтобы узнать, **какой результат
отдаёт каждый NS**, опрашивай его напрямую:

```bash
# список NS-серверов
dig +short example.com NS

# прямой опрос конкретного NS (например ns1.example.com):
dig @ns1.example.com example.com A +noall +answer
dig @ns1.example.com example.com MX +noall +answer

# полный путь от корня DNS — можно убедиться, что домен делегирован корректно
dig +trace example.com
```

Время ответа (модуль показывает задержку в мс):

```bash
time dig @ns1.example.com example.com A +noall +answer +time=3 +tries=1
```

## 3. Почта: SPF / DMARC / DKIM (модуль «Почта»)

Все три — это TXT-записи в разных местах:

```bash
# SPF — в TXT домена, строка должна начинаться с v=spf1
dig +short example.com TXT | grep -i spf

# DMARC — TXT у поддомена _dmarc, строка v=DMARC1
dig +short _dmarc.example.com TXT

# DKIM — TXT у <selector>._domainkey; селектор указывает домен в подписи письма
dig +short default._domainkey.example.com TXT    # частый селектор
dig +short mail._domainkey.example.com TXT       # другой частый вариант
```

## 4. WHOIS (модуль «WHOIS»)

```bash
whois example.com                  # регистратор, даты, статусы, NS
whois example.com | grep -E "Creation|Expiry|Registrar" | head
```

## 5. HTTP/HTTPS: статус, редиректы, скорость, заголовки (модуль «HTTP/HTTPS»)

**Утилита:** `curl`.

```bash
# статус-код и заголовки (без загрузки тела)
curl -sI https://example.com/

# код ответа числом
curl -s -o /dev/null -w "%{http_code}\n" https://example.com/

# следовать за редиректами и показать всю цепочку
curl -sIL https://example.com/

# время до ответа, общее время, размер в байтах
curl -s -o /dev/null -w "DNS: %{time_namelookup}s\nConnect: %{time_connect}s\nTLS: %{time_appconnect}s\nTotal: %{time_total}s\nSize: %{size_download} байт\n" https://example.com/

# показать только заголовок сервера
curl -sI https://example.com/ | grep -i ^server

# проверить конкретный IP из пула (как приложение перебирает все A-записи)
dig +short example.com A | xargs -I{} curl -s -o /dev/null -w "{}\tHTTP %{http_code} %{time_total}s\n" -H "Host: example.com" https://{}/ --resolve example.com:443:{}
```

## 6. SSL-сертификат (модуль «SSL»)

**Утилита:** `openssl s_client`.

```bash
# полная информация: сертификат в PEM
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -serial

# SAN-домены (к каким именам выпущен сертификат)
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -ext subjectAltName

# версия TLS и выбранный шифр
echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | grep -E "New,|Protocol|Cipher"

# проверка валидности цепочки (сверка с корневыми центрами)
echo | openssl s_client -connect example.com:443 -servername example.com -verify_return_error 2>&1 | grep -E "Verify return code"

# дней до истечения (скриптом)
DAYS=$(echo | openssl s_client -connect example.com:443 -servername example.com 2>/dev/null \
  | openssl x509 -noout -enddate | cut -d= -f2)
echo $(( ( $(date -d "$DAYS" +%s) - $(date +%s) ) / 86400 )) "дней до истечения"
```

## 7. Пинг (модуль «Пинг»)

```bash
ping -c 4 example.com              # ICMP: потери, задержка (apt install iputils-ping)
ping -c 1 -W 3 example.com | tail -1   # мини-проверка
```

## 8. Порты (модуль «Порты»)

```bash
# nc: проверить порт
nc -zv -w 3 example.com 443        # -v verbose, -w таймаут, -z без отправки данных

# цикл по списку портов как у приложения
for p in 21 22 25 80 110 143 443 993 995 3306 5432 8080; do
  nc -zv -w 2 example.com $p 2>&1 | grep -E "succeeded|open" && echo "  порт $p открыт"
done

# ещё вариант — bash-проверка без установки пакетов
(echo > /dev/tcp/example.com/443) 2>/dev/null && echo "443 открыт" || echo "443 закрыт"
```

---

## Итоговый «скрипт»: все проверки одной командой

```bash
D=example.com

echo "== A/AAAA/MX/NS/TXT ==";   dig +short $D A; dig +short $D AAAA; dig +short $D MX; dig +short $D NS; dig +short $D TXT
echo "== SPF/DMARC/DKIM ==";     dig +short $D TXT | grep -i spf; dig +short _dmarc.$D TXT; dig +short default._domainkey.$D TXT
echo "== NS напрямую ==";        for ns in $(dig +short $D NS); do dig @$ns $D A +noall +answer +time=3 +tries=1; done
echo "== HTTP ==";                curl -sIL -o /dev/null -w "%{http_code} %{time_total}s %{size_download}B\n" https://$D/
echo "== SSL ==";                 echo | openssl s_client -connect $D:443 -servername $D 2>/dev/null | openssl x509 -noout -issuer -dates
echo "== Пинг ==";                ping -c 1 -W 3 $D | tail -1
echo "== Порты 80/443/25 ==";     for p in 80 443 25; do nc -zv -w 2 $D $p 2>&1 | grep succeeded; done
echo "== WHOIS ==";               whois $D | grep -Ei "creation|expir|registrar" | head -5
```