# Nirantara

Edge-native telemetry and messaging infrastructure in C11. Gaming workload as the
test bed; connected vehicle telematics as the long-term target.

See [Project Nirantara document](docs/) for full architecture.

## Quick Start (Codespaces / Ubuntu 22.04)

```bash
make install-deps
make build

# Set up local CA (dev only)
sudo tools/ca/gen_ca.sh

# Run edge agent (needs local Mosquitto on port 1883 for dev)
make run-edge
```

## Build Artifacts

GitHub Actions builds a Linux release artifact on every push to `main`, including
merged pull requests. Download the generated `nirantara-linux-x86_64` tarball from
the completed **Build** workflow run's artifacts section.

## Structure

```
lib/nirantara-net/   Reusable C networking library (mTLS + MQTT)
edge/                Edge sync agent (Mosquitto subscriber + SQLite + Postgres sync)
flutter/             Flutter FFI bindings
tools/ca/            CA setup scripts
```

## Environment Variables (edge agent)

| Variable | Required | Default | Description |
|---|---|---|---|
| `NR_PG_CONNSTR` | yes | — | libpq connection string |
| `NR_MQTT_HOST` | yes | — | Mosquitto broker host |
| `NR_MQTT_PORT` | no | 8883 | Mosquitto broker port |
| `NR_MQTT_CA` | yes | — | Path to CA cert file |
| `NR_MQTT_CERT` | yes | — | Path to edge node cert |
| `NR_MQTT_KEY` | yes | — | Path to edge node key |
| `NR_EDGE_NODE_ID` | no | edge-mumbai-01 | Node identifier (stored in Postgres) |
| `NR_SYNC_INTERVAL` | no | 600 | Postgres sync interval in seconds |
| `NR_DB_PATH` | no | /var/lib/nirantara/edge.db | SQLite DB path |
| `NR_SUBSCRIBE_TOPIC` | no | game/# | MQTT topic pattern |
