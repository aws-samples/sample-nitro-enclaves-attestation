#!/bin/bash
# Script to run the Nitro Enclave client
# This script creates a virtual environment, installs dependencies, and runs the client

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$SCRIPT_DIR/client"
VENV_DIR="$CLIENT_DIR/.venv"
PCRS_FILE="$SCRIPT_DIR/pcrs.json"

echo "================================"
echo "Nitro Enclave Client Runner"
echo "================================"
echo ""

# Check if uv is installed
if ! command -v uv &> /dev/null; then
    echo "Error: uv is not installed"
    echo "Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
    exit 1
fi

# Check if pcrs.json exists
if [ ! -f "$PCRS_FILE" ]; then
    echo "Error: pcrs.json not found"
    echo "Please run ./build-enclave.sh first to generate PCR values"
    exit 1
fi

# Read PCR values from pcrs.json
echo "Reading PCR values from pcrs.json..."
PCR0=$(jq -r '.PCR0' "$PCRS_FILE")
PCR1=$(jq -r '.PCR1' "$PCRS_FILE")
PCR2=$(jq -r '.PCR2' "$PCRS_FILE")

echo "✓ PCR0: ${PCR0:0:32}..."
echo "✓ PCR1: ${PCR1:0:32}..."
echo "✓ PCR2: ${PCR2:0:32}..."
echo ""

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment with uv..."
    cd "$CLIENT_DIR"
    uv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Install requirements
echo "Installing requirements..."
cd "$CLIENT_DIR"
uv pip install -r requirements.txt
echo "✓ Requirements installed"
echo ""

# Run client commands
echo "================================"
echo "Running Client Commands"
echo "================================"
echo ""

# 1. Get attestation document and verify PCRs
echo "1. Getting attestation document with PCR verification..."
echo ""

# Run hello command and capture output and exit code
set +e  # Temporarily disable exit on error
HELLO_OUTPUT=$(python client.py --pcr0 "$PCR0" --pcr1 "$PCR1" --pcr2 "$PCR2" hello 2>&1)
HELLO_EXIT_CODE=$?
set -e  # Re-enable exit on error

# Display the hello output
echo "$HELLO_OUTPUT"

# Check if hello command failed
if [ $HELLO_EXIT_CODE -ne 0 ]; then
    echo ""
    echo "================================"
    echo "⚠ Hello command failed with exit code $HELLO_EXIT_CODE"
    echo "================================"
    echo ""
    echo "Please check:"
    echo "  1. Is the enclave running? Run: ./run-enclave.sh"
    echo "  2. Check enclave status: nitro-cli describe-enclaves"
    echo "  3. View enclave logs: nitro-cli console --enclave-id <ID>"
    echo ""
    exit 1
fi

# Extract the public key using the machine-parseable format
PUBLIC_KEY=$(echo "$HELLO_OUTPUT" | grep -oP '\[PUBLIC_KEY_B64\]\K[^\[]+(?=\[/PUBLIC_KEY_B64\])')

if [ -z "$PUBLIC_KEY" ]; then
    echo ""
    echo "================================"
    echo "⚠ Failed to extract public key from hello command"
    echo "================================"
    echo ""
    echo "The hello command ran but the public key could not be extracted."
    echo "Please check:"
    echo "  1. Is the enclave running? (./run-enclave.sh)"
    echo "  2. Is the enclave at CID 16? (check with: nitro-cli describe-enclaves)"
    echo "  3. Did the attestation verification succeed?"
    echo ""
    exit 1
fi

echo ""
echo "✓ Public key extracted successfully"

echo ""
echo "================================"
echo "2. Sending encrypted message to enclave..."
echo ""

# Run echo command with extracted public key
python client.py echo "$PUBLIC_KEY" "Hello from parent!"

echo ""
echo "================================"
echo "3. Running negative test with wrong public key..."
echo ""

# Run negative test
python client.py echo-negative-test "This should fail"

echo ""
echo "================================"
echo "✓ All client commands completed successfully!"
echo "================================"
echo ""
echo "Virtual environment is still active."
echo "You can run additional commands:"
echo "  - python client.py --pcr0 '$PCR0' --pcr1 '$PCR1' --pcr2 '$PCR2' hello"
echo "  - python client.py echo '<PUBLIC_KEY>' 'Your message'"
echo "  - python client.py echo-negative-test 'Test message'"
echo ""
echo "To deactivate: deactivate"
echo "================================"
