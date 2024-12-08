from scapy.all import sniff, IP, TCP, UDP
from elasticsearch import Elasticsearch, ConnectionError
from prometheus_client import start_http_server, Counter, Gauge
import os
from datetime import datetime
import time
from threading import Thread, Lock
import psutil

# Инициализация метрик Prometheus
packets_captured = Counter("packets_captured_total", "Total number of packets captured")
packets_processed = Counter("packets_processed_total", "Total number of packets processed")
unique_ips = Gauge("unique_ips", "Number of unique IPs observed")
tcp_packets_total = Counter("tcp_packets_total", "Total number of TCP packets captured")
udp_packets_total = Counter("udp_packets_total", "Total number of UDP packets captured")
avg_packet_size = Gauge("avg_packet_size", "Average packet size in bytes")
bytes_per_second = Gauge("bytes_per_second", "Rate of data transfer (bytes per second)")
suspicious_packets = Counter("suspicious_packets_total", "Total number of suspicious packets detected")
elasticsearch_errors = Counter("elasticsearch_errors_total", "Total number of Elasticsearch errors")
cpu_usage = Gauge("cpu_usage", "CPU usage in percentage")
memory_usage = Gauge("memory_usage", "Memory usage in percentage")
dropped_packets = Counter("dropped_packets_total", "Total number of dropped packets")

# Подключение к Elasticsearch
es_host = os.environ.get("ELASTICSEARCH_HOST", "elasticsearch")
es_port = int(os.environ.get("ELASTICSEARCH_PORT", 9200))
es_scheme = os.environ.get("ELASTICSEARCH_SCHEME", "http")

def connect_elasticsearch(host, port, scheme, retries=5, delay=5):
    for attempt in range(1, retries + 1):
        try:
            es = Elasticsearch([{"host": host, "port": port, "scheme": scheme}])
            if es.ping():
                print("Успешно подключились к Elasticsearch")
                return es
            else:
                print(f"Попытка {attempt}: Elasticsearch не отвечает.")
        except ConnectionError as e:
            print(f"Попытка {attempt}: Ошибка подключения к Elasticsearch: {e}")
        if attempt < retries:
            print(f"Ждем {delay} секунд перед следующей попыткой...")
            time.sleep(delay)
    raise Exception("Не удалось подключиться к Elasticsearch после нескольких попыток.")

es = connect_elasticsearch(es_host, es_port, es_scheme)

buffer = []
buffer_lock = Lock()
BUFFER_SIZE = 500
BUFFER_INTERVAL = 15
unique_ip_set = set()

def send_buffered_packets():
    while True:
        time.sleep(BUFFER_INTERVAL)
        with buffer_lock:
            if buffer:
                try:
                    bulk_data = [{"index": {"_index": "network_traffic"}} if i % 2 == 0 else pkt 
                                 for i, pkt in enumerate(buffer * 2)]
                    es.bulk(body=bulk_data, refresh=True)
                    print(f"Отправлено {len(buffer)} пакетов.")
                    buffer.clear()
                except Exception as e:
                    elasticsearch_errors.inc()
                    print(f"Ошибка отправки данных в Elasticsearch: {e}")

def monitor_system_metrics():
    while True:
        cpu_usage.set(psutil.cpu_percent())
        memory_usage.set(psutil.virtual_memory().percent)
        time.sleep(5)

def packet_callback(packet):
    packets_captured.inc()
    if IP in packet:
        packets_processed.inc()
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        length = len(packet)

        unique_ip_set.update([source_ip, destination_ip])
        unique_ips.set(len(unique_ip_set))
        avg_packet_size.set((avg_packet_size._value.get() + length) / 2)

        packet_info = {
            "timestamp": datetime.utcnow().isoformat(),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": packet[IP].proto,
            "length": length
        }

        if TCP in packet:
            tcp_packets_total.inc()
            packet_info.update({
                "source_port": packet[TCP].sport,
                "destination_port": packet[TCP].dport,
                "flags": str(packet[TCP].flags)
            })
            if "S" in str(packet[TCP].flags) and "A" not in str(packet[TCP].flags):
                suspicious_packets.inc()
        elif UDP in packet:
            udp_packets_total.inc()
            packet_info.update({
                "source_port": packet[UDP].sport,
                "destination_port": packet[UDP].dport
            })

        with buffer_lock:
            buffer.append(packet_info)
            if len(buffer) >= BUFFER_SIZE:
                try:
                    bulk_data = [{"index": {"_index": "network_traffic"}} if i % 2 == 0 else pkt 
                                 for i, pkt in enumerate(buffer * 2)]
                    es.bulk(body=bulk_data, refresh=True)
                    buffer.clear()
                except Exception as e:
                    elasticsearch_errors.inc()
                    print(f"Ошибка при отправке данных: {e}")

def update_data_rate():
    prev_processed = 0
    prev_captured = 0
    while True:
        time.sleep(10)
        current_captured = packets_captured._value.get()
        current_processed = packets_processed._value.get()
        bytes_per_second.set((current_processed - prev_processed) * avg_packet_size._value.get())
        dropped_packets.inc(current_captured - current_processed)
        prev_processed = current_processed
        prev_captured = current_captured

def main():
    start_http_server(8000)
    print("HTTP-сервер запущен на порту 8000.")
    Thread(target=monitor_system_metrics, daemon=True).start()
    Thread(target=send_buffered_packets, daemon=True).start()
    Thread(target=update_data_rate, daemon=True).start()
    print("Запуск захвата пакетов...")
    sniff(prn=packet_callback, store=False, filter="tcp or udp")

if __name__ == "__main__":
    main()