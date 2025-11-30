# Полезные команды для анализа PCAP файлов

## Оглавление
- [TShark - консольный анализ](#tshark---консольный-анализ)
- [Wireshark - фильтры отображения](#wireshark---фильтры-отображения)
- [Bash скрипты для автоматизации](#bash-скрипты-для-автоматизации)

---

## TShark - консольный анализ

### Статистика и общий анализ

#### 1. Статистика по IP-адресам (Endpoints)
```bash
tshark -r file.pcap -q -z endpoints,ip
```
**Что делает:** Выводит список всех IP-адресов в pcap файле с количеством отправленных/полученных пакетов и байт.

**Применение:** Определение самого активного узла в сети (зараженного хоста).

---

#### 2. Статистика по MAC-адресам
```bash
tshark -r file.pcap -q -z endpoints,eth
```
**Что делает:** Выводит список всех MAC-адресов с количеством пакетов и байт.

**Применение:** Идентификация физических устройств в сети.

---

#### 3. Статистика TCP-соединений
```bash
tshark -r file.pcap -q -z conv,tcp
```
**Что делает:** Показывает все TCP-соединения между хостами (IP:Port ↔ IP:Port) с количеством переданных данных.

**Применение:** Анализ сетевых соединений и выявление подозрительных коммуникаций с C2-серверами.

---

#### 4. Статистика HTTP-запросов
```bash
tshark -r file.pcap -q -z http,tree
```
**Что делает:** Выводит дерево всех HTTP-запросов с группировкой по хостам и путям.

**Применение:** Быстрый обзор всех посещенных сайтов.

---

### Извлечение DNS-данных

#### 5. Список всех DNS-запросов
```bash
tshark -r file.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name
```
**Что делает:** Извлекает доменные имена из всех DNS-запросов (не ответов).

**Применение:** Получение списка всех доменов, к которым обращались хосты.

---

#### 6. Уникальные DNS-запросы (без повторов)
```bash
tshark -r file.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u
```
**Что делает:** Извлекает уникальные доменные имена и сортирует их.

**Применение:** Создание списка уникальных доменов для анализа.

---

#### 7. DNS-запросы от конкретного хоста
```bash
tshark -r file.pcap -Y "ip.src == 192.168.1.100 && dns" -T fields -e dns.qry.name | sort -u
```
**Что делает:** Показывает только DNS-запросы от указанного IP-адреса.

**Применение:** Анализ DNS-активности подозрительного хоста.

---

#### 8. Топ-10 наиболее запрашиваемых доменов
```bash
tshark -r file.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -10
```
**Что делает:** Подсчитывает количество запросов к каждому домену и выводит топ-10.

**Применение:** Выявление доменов с частыми запросами (может указывать на C2-beacon).

---

### Извлечение HTTP-данных

#### 9. Список всех HTTP хостов
```bash
tshark -r file.pcap -Y "http.request" -T fields -e http.host | sort -u
```
**Что делает:** Извлекает все уникальные HTTP хосты (доменные имена) из запросов.

**Применение:** Определение всех посещенных веб-сайтов.

---

#### 10. HTTP хосты и URI (полные URL)
```bash
tshark -r file.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
```
**Что делает:** Показывает HTTP хосты вместе с путями (URI).

**Применение:** Анализ полных URL для обнаружения вредоносных путей.

---

#### 11. HTTP User-Agent
```bash
tshark -r file.pcap -Y "http.user_agent" -T fields -e http.user_agent | sort -u
```
**Что делает:** Извлекает все User-Agent строки из HTTP-запросов.

**Применение:** Определение типа браузера и ОС зараженного хоста.

---

#### 12. HTTP Referer (цепочка переходов)
```bash
tshark -r file.pcap -Y "http.referer" -T fields -e http.host -e http.referer
```
**Что делает:** Показывает HTTP хосты и откуда пришел пользователь (Referer).

**Применение:** Реконструкция цепочки перенаправлений (infection chain).

---

#### 13. HTTP POST-запросы
```bash
tshark -r file.pcap -Y "http.request.method == POST" -T fields -e ip.dst -e http.host -e http.request.uri
```
**Что делает:** Выводит все POST-запросы с IP назначения, хостом и URI.

**Применение:** Обнаружение передачи данных к C2-серверу.

---

#### 14. HTTP перенаправления (редиректы 301/302)
```bash
tshark -r file.pcap -Y "http.response.code == 302 || http.response.code == 301" -T fields -e http.host -e http.location
```
**Что делает:** Находит HTTP-ответы с кодами 301/302 и показывает куда происходит перенаправление.

**Применение:** Анализ цепочки HTTP-редиректов в drive-by download атаках.

---

### Извлечение других данных

#### 15. NetBIOS имена
```bash
tshark -r file.pcap -Y "nbns" -T fields -e nbns.name | sort -u
```
**Что делает:** Извлекает NetBIOS-имена из NBNS-трафика.

**Применение:** Определение имени компьютера в локальной сети.

---

#### 16. Список всех IP-адресов назначения
```bash
tshark -r file.pcap -Y "ip" -T fields -e ip.dst | sort -u
```
**Что делает:** Выводит все уникальные IP-адреса назначения.

**Применение:** Создание списка всех внешних IP для проверки на вредоносность.

---

#### 17. Экспорт HTTP-объектов (файлов)
```bash
tshark -r file.pcap --export-objects http,output_folder/
```
**Что делает:** Экспортирует все HTTP-объекты (загруженные файлы) в указанную папку.

**Применение:** Извлечение всех загруженных файлов для анализа на вредоносность.

---

### Поиск вредоносной активности

#### 18. Запросы напрямую к IP (минуя DNS)
```bash
tshark -r file.pcap -Y "http.request" -T fields -e http.host | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
```
**Что делает:** Находит HTTP-запросы напрямую к IP-адресам (без доменных имен).

**Применение:** Обнаружение C2-коммуникаций, которые часто используют прямые IP.

---

#### 19. Подозрительные User-Agent
```bash
tshark -r file.pcap -Y "http.user_agent" -T fields -e http.user_agent | grep -iE "(curl|wget|python|powershell)"
```
**Что делает:** Ищет User-Agent с признаками автоматизированных инструментов.

**Применение:** Обнаружение скриптовых загрузок и вредоносных запросов.

---

#### 20. Длинные URL (обфусцированные)
```bash
tshark -r file.pcap -Y "http.request.uri" -T fields -e http.host -e http.request.uri | awk 'length($2) > 100'
```
**Что делает:** Выводит HTTP-запросы с URI длиннее 100 символов.

**Применение:** Обнаружение обфусцированных URL от exploit kit'ов.

---

#### 21. Timeline событий (хронология)
```bash
tshark -r file.pcap -Y "ip.src == 192.168.1.100 && (http || dns)" -T fields -e frame.time -e dns.qry.name -e http.host
```
**Что делает:** Выводит хронологию DNS и HTTP-запросов с временными метками.

**Применение:** Построение временной шкалы (timeline) атаки.

---

## Wireshark - фильтры отображения

### Базовые фильтры по IP

#### 22. Трафик от конкретного IP
```
ip.src == 192.168.1.100
```
**Что делает:** Показывает только пакеты, отправленные с указанного IP.

---

#### 23. Трафик к конкретному IP
```
ip.dst == 10.0.0.1
```
**Что делает:** Показывает только пакеты, направленные к указанному IP.

---

#### 24. Трафик с/на IP (любое направление)
```
ip.addr == 192.168.1.100
```
**Что делает:** Показывает пакеты, где указанный IP является источником ИЛИ назначением.

---

#### 25. Исключение трафика
```
!(ip.addr == 192.168.1.1)
```
**Что делает:** Показывает весь трафик, КРОМЕ указанного IP.

---

#### 26. Трафик из подсети
```
ip.src == 192.168.1.0/24
```
**Что делает:** Показывает пакеты из указанной подсети.

---

### Фильтры по протоколам

#### 27. HTTP трафик от хоста
```
ip.src == 192.168.1.100 && http
```
**Что делает:** Показывает HTTP-пакеты от конкретного IP.

---

#### 28. DNS трафик от хоста
```
ip.src == 192.168.1.100 && dns
```
**Что делает:** Показывает DNS-пакеты от конкретного IP.

---

#### 29. Комбинация протоколов
```
ip.src == 192.168.1.100 && (http || dns || nbns)
```
**Что делает:** Показывает HTTP, DNS и NBNS трафик от конкретного хоста.

---

#### 30. Трафик на TCP порт
```
tcp.port == 80
```
**Что делает:** Показывает TCP-трафик на порту 80 (источник или назначение).

---

### HTTP-фильтры

#### 31. Запросы к конкретному домену
```
http.host == "example.com"
```
**Что делает:** Показывает HTTP-трафик к указанному домену.

---

#### 32. Запросы к нескольким доменам
```
http.host == "malicious.com" || http.host == "evil.net"
```
**Что делает:** Показывает запросы к любому из указанных доменов.

---

#### 33. Домен содержит подстроку
```
http.host contains "malicious"
```
**Что делает:** Показывает запросы к доменам, содержащим указанную подстроку.

---

#### 34. POST-запросы
```
http.request.method == "POST"
```
**Что делает:** Показывает только HTTP POST-запросы.

---

#### 35. GET-запросы
```
http.request.method == "GET"
```
**Что делает:** Показывает только HTTP GET-запросы.

---

#### 36. Фильтр по URI (путь)
```
http.request.uri contains "/malware/"
```
**Что делает:** Показывает HTTP-запросы с указанным путем в URI.

---

#### 37. Фильтр по Referer
```
http.referer contains "malicious.com"
```
**Что делает:** Показывает запросы, где Referer содержит указанный домен.

---

#### 38. Фильтр по User-Agent
```
http.user_agent contains "MSIE"
```
**Что делает:** Показывает HTTP-запросы с User-Agent, содержащим "MSIE" (Internet Explorer).

---

#### 39. HTTP ответы с кодом 200
```
http.response.code == 200
```
**Что делает:** Показывает HTTP-ответы с кодом 200 (OK).

---

#### 40. HTTP редиректы (301/302)
```
http.response.code == 302 || http.response.code == 301
```
**Что делает:** Показывает HTTP-перенаправления.

---

#### 41. Фильтр по Content-Type
```
http.content_type contains "javascript"
```
**Что делает:** Показывает HTTP-ответы с JavaScript в Content-Type.

---

### DNS-фильтры

#### 42. Только DNS-запросы
```
dns.flags.response == 0
```
**Что делает:** Показывает только DNS-запросы (не ответы).

---

#### 43. Только DNS-ответы
```
dns.flags.response == 1
```
**Что делает:** Показывает только DNS-ответы.

---

#### 44. DNS-запрос к конкретному домену
```
dns.qry.name == "malicious.com"
```
**Что делает:** Показывает DNS-запросы к указанному домену.

---

#### 45. DNS-запрос содержит подстроку
```
dns.qry.name contains "malicious"
```
**Что делает:** Показывает DNS-запросы, содержащие указанную подстроку.

---

### Продвинутые фильтры

#### 46. Поиск по содержимому пакета
```
frame contains "malware"
```
**Что делает:** Показывает все пакеты, содержащие указанную строку в любом поле.

---

#### 47. Фильтр по размеру пакета
```
frame.len > 1000
```
**Что делает:** Показывает пакеты размером больше 1000 байт.

---

#### 48. TCP пакеты с флагом SYN
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
**Что делает:** Показывает TCP SYN пакеты (начало соединения).

---

#### 49. Комбинированный сложный фильтр
```
(ip.src == 192.168.1.100 && http.request.method == "POST") || (dns.qry.name contains "malicious")
```
**Что делает:** Показывает POST-запросы от конкретного IP ИЛИ DNS-запросы к вредоносным доменам.

---

#### 50. Исключение легитимного трафика
```
!(http.host contains "google.com" || http.host contains "microsoft.com")
```
**Что делает:** Скрывает запросы к легитимным доменам, показывая только подозрительный трафик.

---

## Bash скрипты для автоматизации

### Скрипт 1: Быстрый анализ подозрительного хоста

```bash
#!/bin/bash
# Использование: ./analyze_host.sh <pcap_file> <ip_address>

FILE=$1
IP=$2

echo "=== Анализ хоста $IP ==="
echo ""

echo "1. DNS-запросы:"
tshark -r $FILE -Y "ip.src == $IP && dns.flags.response == 0" -T fields -e dns.qry.name | sort -u
echo ""

echo "2. HTTP хосты:"
tshark -r $FILE -Y "ip.src == $IP && http.request" -T fields -e http.host | sort -u
echo ""

echo "3. POST-запросы:"
tshark -r $FILE -Y "ip.src == $IP && http.request.method == POST" -T fields -e ip.dst -e http.host
echo ""

echo "4. User-Agent:"
tshark -r $FILE -Y "ip.src == $IP && http.user_agent" -T fields -e http.user_agent | sort -u
echo ""

echo "5. TCP-соединения:"
tshark -r $FILE -Y "ip.src == $IP" -q -z conv,tcp
```

**Применение:**
```bash
chmod +x analyze_host.sh
./analyze_host.sh capture.pcap 192.168.1.100
```

---

### Скрипт 2: Экспорт всех IoC (Indicators of Compromise)

```bash
#!/bin/bash
# Использование: ./extract_ioc.sh <pcap_file>

FILE=$1
OUTPUT_DIR="ioc_results"

mkdir -p $OUTPUT_DIR

echo "Экспорт IoC из $FILE..."

# DNS queries
echo "- DNS запросы..."
tshark -r $FILE -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u > $OUTPUT_DIR/dns_queries.txt

# HTTP hosts
echo "- HTTP хосты..."
tshark -r $FILE -Y "http.request" -T fields -e http.host | sort -u > $OUTPUT_DIR/http_hosts.txt

# IP addresses
echo "- IP-адреса..."
tshark -r $FILE -Y "ip" -T fields -e ip.dst | sort -u > $OUTPUT_DIR/ip_addresses.txt

# User-Agents
echo "- User-Agent..."
tshark -r $FILE -Y "http.user_agent" -T fields -e http.user_agent | sort -u > $OUTPUT_DIR/user_agents.txt

# POST destinations
echo "- POST назначения..."
tshark -r $FILE -Y "http.request.method == POST" -T fields -e ip.dst -e http.host | sort -u > $OUTPUT_DIR/post_destinations.txt

# Export HTTP objects
echo "- HTTP объекты..."
mkdir -p $OUTPUT_DIR/http_objects
tshark -r $FILE --export-objects http,$OUTPUT_DIR/http_objects/ 2>/dev/null

echo "Готово! Результаты в $OUTPUT_DIR/"
ls -lh $OUTPUT_DIR/
```

**Применение:**
```bash
chmod +x extract_ioc.sh
./extract_ioc.sh capture.pcap
```

---

### Скрипт 3: Поиск признаков Exploit Kit

```bash
#!/bin/bash
# Использование: ./find_exploit_kit.sh <pcap_file>

FILE=$1

echo "=== Поиск признаков Exploit Kit ==="
echo ""

echo "1. Обфусцированные URL (длинные hex-строки):"
tshark -r $FILE -Y "http.request.uri" -T fields -e http.host -e http.request.uri | \
grep -E "([0-9a-f]{30,}|;[0-9]+)" | \
head -20
echo ""

echo "2. Подозрительные Content-Type:"
tshark -r $FILE -Y "http.content_type" -T fields -e http.host -e http.content_type | \
grep -iE "(javascript|octet-stream|x-msdownload)" | \
sort -u
echo ""

echo "3. Запросы с подозрительными Referer:"
tshark -r $FILE -Y "http.referer" -T fields -e http.host -e http.referer | \
grep -v "google\|facebook\|microsoft" | \
head -20
echo ""

echo "4. Множественные запросы к одному домену (топ-5):"
tshark -r $FILE -Y "http.request" -T fields -e http.host | \
sort | uniq -c | sort -rn | head -5
```

**Применение:**
```bash
chmod +x find_exploit_kit.sh
./find_exploit_kit.sh capture.pcap
```

---

## Полезные комбинации команд

### Однострочники для быстрого анализа

#### Топ-10 HTTP хостов по количеству запросов
```bash
tshark -r file.pcap -Y "http.request" -T fields -e http.host | sort | uniq -c | sort -rn | head -10
```

#### Найти все домены в зоне .ru
```bash
tshark -r file.pcap -Y "dns.qry.name" -T fields -e dns.qry.name | grep "\.ru$" | sort -u
```

#### Список всех IP, к которым были POST-запросы
```bash
tshark -r file.pcap -Y "http.request.method == POST" -T fields -e ip.dst | sort -u
```

#### HTTP-запросы с Referer от конкретного сайта
```bash
tshark -r file.pcap -Y 'http.referer contains "excelforum.com"' -T fields -e http.host -e http.request.uri
```

#### Подсчет пакетов по протоколам
```bash
tshark -r file.pcap -q -z io,phs
```

---

## Советы и рекомендации

### Синтаксис фильтров

✅ **Правильно:**
```
ip.src == 192.168.1.100
http.host == "example.com"
dns.qry.name contains "malicious"
```

❌ **Неправильно:**
```
ip.src==192.168.1.100          # нет пробелов
http.host == example.com       # нет кавычек
dns.qry.name contain malicious # неправильный оператор
```

### Логические операторы

- `&&` - логическое И (AND)
- `||` - логическое ИЛИ (OR)
- `!` - логическое НЕ (NOT)
- `==` - равно
- `!=` - не равно
- `contains` - содержит подстроку

### Оптимизация работы

1. **Для больших файлов** используйте `head` для ограничения вывода:
   ```bash
   tshark -r huge.pcap -Y "http" -T fields -e http.host | head -100
   ```

2. **Подавление вывода пакетов** при статистике:
   ```bash
   tshark -r file.pcap -q -z endpoints,ip
   ```

3. **Перенаправление в файл** для сохранения результатов:
   ```bash
   tshark -r file.pcap -Y "dns" -T fields -e dns.qry.name > dns_queries.txt
   ```

### Полезные ресурсы

- **TShark документация:** `man tshark` или `tshark -h`
- **Wireshark Display Filters:** https://wiki.wireshark.org/DisplayFilters
- **Wireshark User Guide:** https://www.wireshark.org/docs/wsug_html_chunked/
