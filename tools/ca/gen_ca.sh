#!/usr/bin/env bash
# tools/ca/gen_ca.sh
#
# Sets up the Nirantara private CA for development/testing.
# Production: CA private key lives in AWS KMS. This script is for local dev only.
#
# Usage: ./tools/ca/gen_ca.sh [output-dir]
#   output-dir defaults to /etc/nirantara/ca
#
# Generates:
#   ca.key      - CA private key (keep secret; in prod this is in KMS)
#   ca.crt      - CA certificate (embed this in the Flutter app)
#   edge.key    - Edge node private key
#   edge.crt    - Edge node certificate (signed by CA, for Mosquitto mTLS)

set -euo pipefail

OUT="${1:-/etc/nirantara/ca}"
mkdir -p "$OUT"
chmod 700 "$OUT"

echo "[CA] output dir: $OUT"

# ── CA key and self-signed cert ───────────────────────────────────────────────
if [ ! -f "$OUT/ca.key" ]; then
    echo "[CA] generating CA private key (ECDSA P-256)..."
    openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/ca.key"
    chmod 600 "$OUT/ca.key"
fi

if [ ! -f "$OUT/ca.crt" ]; then
    echo "[CA] generating CA self-signed certificate (10 years)..."
    openssl req -new -x509 -key "$OUT/ca.key" \
        -out "$OUT/ca.crt" \
        -days 3650 \
        -subj "/CN=Nirantara-CA/O=Nirantara"
fi

# ── Edge node cert ────────────────────────────────────────────────────────────
EDGE_ID="${EDGE_NODE_ID:-edge-local}"

if [ ! -f "$OUT/edge.key" ]; then
    echo "[CA] generating edge node key for $EDGE_ID..."
    openssl ecparam -name prime256v1 -genkey -noout -out "$OUT/edge.key"
    chmod 600 "$OUT/edge.key"
fi

if [ ! -f "$OUT/edge.crt" ]; then
    echo "[CA] signing edge node certificate..."
    openssl req -new -key "$OUT/edge.key" \
        -subj "/CN=$EDGE_ID/O=Nirantara" | \
    openssl x509 -req \
        -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" \
        -CAcreateserial \
        -out "$OUT/edge.crt" \
        -days 365
fi

# ── Copy to standard paths ────────────────────────────────────────────────────
DEST="/etc/nirantara"
mkdir -p "$DEST"

cp "$OUT/ca.crt"   "$DEST/ca.crt"
cp "$OUT/edge.crt" "$DEST/edge.crt"
cp "$OUT/edge.key" "$DEST/edge.key"
chmod 644 "$DEST/ca.crt" "$DEST/edge.crt"
chmod 600 "$DEST/edge.key"

echo ""
echo "[CA] Done. Files:"
echo "   CA cert (embed in app): $DEST/ca.crt"
echo "   Edge cert (Mosquitto):  $DEST/edge.crt"
echo "   Edge key  (Mosquitto):  $DEST/edge.key"
echo ""
echo "[CA] CA cert PEM (paste into nr_config_t.ca_cert_pem):"
echo "---"
cat "$DEST/ca.crt"
