#!/usr/bin/env bash
# Generate a minimal PKI: CA, server certificate, one client certificate.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p certs && cd certs

DAYS=825

echo "[1/3] Creating the Certificate Authority (CA)..."
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days $DAYS \
  -keyout ca.key -out ca.crt \
  -subj "/C=TN/O=PFE-SecureProxy/CN=SecureProxy Internal CA" 2>/dev/null

echo "[2/3] Creating the server certificate (for the proxy)..."
openssl req -newkey rsa:2048 -nodes -sha256 \
  -keyout server.key -out server.csr \
  -subj "/C=TN/O=PFE-SecureProxy/CN=secure-proxy.local" 2>/dev/null
cat > server.ext << 'EXT'
subjectAltName = DNS:localhost, IP:127.0.0.1
extendedKeyUsage = serverAuth
EXT
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days $DAYS -sha256 -extfile server.ext -out server.crt 2>/dev/null

echo "[3/3] Creating one client certificate (for mTLS)..."
openssl req -newkey rsa:2048 -nodes -sha256 \
  -keyout client.key -out client.csr \
  -subj "/C=TN/O=PFE-SecureProxy/CN=test-client" 2>/dev/null
cat > client.ext << 'EXT'
extendedKeyUsage = clientAuth
EXT
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days $DAYS -sha256 -extfile client.ext -out client.crt 2>/dev/null

rm -f ./*.csr ./*.ext ./*.srl
chmod 600 ./*.key
echo "Done. Files in certs/:"
ls -1
