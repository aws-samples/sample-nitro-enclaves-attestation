#!/bin/bash
set -e

echo "======================================"
echo "Starting Nitro Enclave"
echo "======================================"
echo

# Check if enclave image exists
if [ ! -f "enclave-server.eif" ]; then
    echo "Error: enclave-server.eif not found"
    echo "Run ./build.sh first"
    exit 1
fi

# Check if enclave is already running and terminate it
RUNNING=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID // empty')
if [ ! -z "$RUNNING" ]; then
    echo "Found running enclave (ID: $RUNNING)"
    echo "Terminating existing enclave..."
    nitro-cli terminate-enclave --enclave-id "$RUNNING"
    echo "✓ Existing enclave terminated"
    echo
fi

echo "Starting enclave with:"
echo "  Memory: 1024 MB"
echo "  CPUs: 1"
echo "  CID: 16"
echo

# Run the enclave (without debug mode for production PCR values)
nitro-cli run-enclave \
  --eif-path enclave-server.eif \
  --memory 1024 \
  --cpu-count 1 \
  --enclave-cid 16

echo
echo "======================================"
echo "Enclave Started!"
echo "======================================"
echo

# Get enclave info
ENCLAVE_INFO=$(nitro-cli describe-enclaves)
ENCLAVE_ID=$(echo "$ENCLAVE_INFO" | jq -r '.[0].EnclaveID')
ENCLAVE_CID=$(echo "$ENCLAVE_INFO" | jq -r '.[0].EnclaveCID')

echo "Enclave ID: $ENCLAVE_ID"
echo "Enclave CID: $ENCLAVE_CID"
echo
echo "View logs with:"
echo "  nitro-cli console --enclave-id $ENCLAVE_ID"
echo
echo "Test with client:"
echo "  cd client"
echo "  python client.py --cid $ENCLAVE_CID hello"
echo
