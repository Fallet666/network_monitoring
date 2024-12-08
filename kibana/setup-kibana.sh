#!/bin/bash

# Функция для проверки состояния ответа от API
function check_response {
  local response_code=$1
  local success_message=$2
  local error_message=$3

  if [[ $response_code -eq 200 || $response_code -eq 201 ]]; then
    echo "$success_message"
  else
    echo "$error_message HTTP код: $response_code"
    exit 1
  fi
}

# Ожидание запуска Kibana
echo "Ожидание запуска Kibana..."
while true; do
  # Получаем статус от API Kibana
  STATUS=$(curl -s http://kibana:5601/api/status | grep -o '"summary":"[^"]*"' | sed 's/"summary":"//;s/"//')
  
  # Проверяем, доступна ли Kibana
  if [[ "$STATUS" == "All services and plugins are available" ]]; then
    echo "Kibana доступна. Начинаем настройку..."
    break
  fi
  
  echo "Kibana недоступна - ждем 5 секунд..."
  sleep 5
done

# Создание индексного шаблона для network_traffic
echo "Создаем индексный шаблон для network_traffic..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://kibana:5601/api/index_patterns/index_pattern" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
  -d '{
    "index_pattern": {
      "title": "network_traffic",
      "time_field_name": "timestamp"
    }
  }')

check_response "$RESPONSE" "Индексный шаблон успешно создан." "Ошибка при создании индексного шаблона."