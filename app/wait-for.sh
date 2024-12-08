#!/bin/sh

host="$1"
shift
cmd="$@"

until curl -s http://$host:9200 > /dev/null; do
  >&2 echo "Elasticsearch is unavailable - sleeping"
  sleep 5
done

>&2 echo "Elasticsearch is up - executing command"
exec $cmd