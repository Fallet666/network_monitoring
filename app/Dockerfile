FROM python:3.9-alpine

# Устанавливаем зависимости для Scapy
RUN apk update && apk add --no-cache tcpdump libpcap-dev gcc musl-dev linux-headers curl

WORKDIR /app

COPY packet_sniffer.py /app/packet_sniffer.py
COPY requirements.txt /app/requirements.txt
COPY wait-for.sh /app/wait-for.sh

# Устанавливаем необходимые Python-пакеты
RUN pip install --no-cache-dir -r requirements.txt

# Предоставляем права на выполнение скрипта
RUN chmod +x /app/wait-for.sh

CMD ["./wait-for.sh", "elasticsearch", "python", "packet_sniffer.py"]