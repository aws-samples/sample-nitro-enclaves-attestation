#!/bin/bash
set -e

echo "======================================"
echo "Building Nitro Enclave Attestation Demo"
echo "======================================"
echo

# Check if running with sudo
if [ "$EUID" -eq 0 ]; then 
   echo "Error: Do not run this script with sudo"
   exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

# Check if nitro-cli is installed
if ! command -v nitro-cli &> /dev/null; then
    echo "Error: nitro-cli is not installed"
    echo "Install with: sudo yum install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel"
    exit 1
fi

echo "Step 1: Building Docker image..."
cd server
docker build -t enclave-server:latest .
cd ..

echo
echo "Step 2: Converting Docker image to Enclave Image File..."
nitro-cli build-enclave \
  --docker-uri enclave-server:latest \
  --output-file enclave-server.eif > build-output.json

echo
echo "Step 3: Extracting and saving PCR measurements..."
# Extract PCRs and save to pcrs.json
jq '{
  PCR0: .Measurements.PCR0,
  PCR1: .Measurements.PCR1,
  PCR2: .Measurements.PCR2
}' build-output.json > pcrs.json

echo
echo "======================================"
echo "Build Complete!"
echo "======================================"
echo

# Display PCR values
echo "PCR Measurements (saved to pcrs.json):"
echo
jq '.' pcrs.json

echo
echo "Enclave image file: enclave-server.eif"
echo "PCR values saved to: pcrs.json"
echo
echo "Next steps:"
echo "  1. Run the enclave: ./run-enclave.sh"
echo "  2. Test with client: ./run-client.sh"
echo
