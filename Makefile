.PHONY: all build debug clean test install-deps

BUILD_DIR := build
BUILD_DIR_DEBUG := build-debug

all: build

install-deps:
	bash tools/setup_ubuntu.sh

build:
	cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR) --parallel $$(nproc)

debug:
	cmake -B $(BUILD_DIR_DEBUG) -DCMAKE_BUILD_TYPE=Debug
	cmake --build $(BUILD_DIR_DEBUG) --parallel $$(nproc)

clean:
	rm -rf $(BUILD_DIR) $(BUILD_DIR_DEBUG)

# Run the edge agent locally (needs Mosquitto running on localhost:8883)
run-edge: build
	NR_PG_CONNSTR="postgresql://localhost/nirantara" \
	NR_MQTT_HOST="127.0.0.1" \
	NR_MQTT_PORT="1883" \
	NR_MQTT_CA="/etc/nirantara/ca.crt" \
	NR_MQTT_CERT="/etc/nirantara/edge.crt" \
	NR_MQTT_KEY="/etc/nirantara/edge.key" \
	NR_EDGE_NODE_ID="edge-local" \
	NR_SYNC_INTERVAL="60" \
	NR_DB_PATH="/tmp/nirantara-edge.db" \
	NR_SUBSCRIBE_TOPIC="game/#" \
	$(BUILD_DIR)/nirantara-edge

fmt:
	find . -name "*.c" -o -name "*.h" | grep -v build | \
		xargs clang-format -i --style="{BasedOnStyle: llvm, IndentWidth: 4}"

valgrind: debug
	NR_PG_CONNSTR="postgresql://localhost/nirantara" \
	NR_MQTT_HOST="127.0.0.1" \
	NR_MQTT_PORT="1883" \
	NR_MQTT_CA="/etc/nirantara/ca.crt" \
	NR_MQTT_CERT="/etc/nirantara/edge.crt" \
	NR_MQTT_KEY="/etc/nirantara/edge.key" \
	NR_EDGE_NODE_ID="edge-local" \
	NR_SYNC_INTERVAL="30" \
	NR_DB_PATH="/tmp/nirantara-edge.db" \
	NR_SUBSCRIBE_TOPIC="game/#" \
	valgrind --leak-check=full --show-leak-kinds=all \
	    $(BUILD_DIR_DEBUG)/nirantara-edge
