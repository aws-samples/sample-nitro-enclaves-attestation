#!/bin/bash

echo "======================================"
echo "Stopping Nitro Enclave"
echo "======================================"
echo

# Get running enclave ID
ENCLAVE_ID=$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID // empty')

if [ -z "$ENCLAVE_ID" ]; then
    echo "No enclave is currently running"
    exit 0
fi

echo "Terminating enclave: $ENCLAVE_ID"
nitro-cli terminate-enclave --enclave-id "$ENCLAVE_ID"

echo
echo "Enclave stopped successfully"
echo
