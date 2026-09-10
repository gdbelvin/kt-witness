#!/bin/sh
# Open the loopback tunnels the observability stack lives behind, and leave them
# up in the background.
#
#   usage: deploy/loki-tunnel.sh [ssh-host]
#
# Loki, InfluxDB and Grafana all bind 127.0.0.1 on the witness host, because
# Loki runs with auth_enabled:false and exposing it on the LAN would be
# unauthenticated read and delete over the log store. So the way to read logs
# from a laptop is a tunnel, and this is it — `docker compose logs` over ssh
# works but shows one container's tail with no query and no history.
#
#   3100  Loki      curl -sG 127.0.0.1:3100/loki/api/v1/query_range ...
#   3001  Grafana   the dashboards
#   8086  InfluxDB  the counters the rate panels come from
set -eu
HOST="${1:-${KT_WITNESS_HOST:-docker-services-ts}}"
pkill -f "ssh -f -N -L 3100:127.0.0.1:3100" 2>/dev/null || true
ssh -f -N -L 3100:127.0.0.1:3100 -L 3001:127.0.0.1:3001 -L 8086:127.0.0.1:8086 "$HOST"
sleep 1
printf 'loki:    %s\n' "$(curl -s --max-time 5 http://127.0.0.1:3100/ready || echo unreachable)"
printf 'grafana: %s\n' "$(curl -s --max-time 5 http://127.0.0.1:3001/api/health | tr -d '\n ' || echo unreachable)"
