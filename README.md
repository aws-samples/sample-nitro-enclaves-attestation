# AWS Nitro Enclaves Attestation Demo

A complete, working example of AWS Nitro Enclaves attestation with a Python client-server application. This demo shows how to establish trust in an enclave through cryptographic attestation and secure communication.

## 📋 What This Demo Does

1. **Server (Enclave)**: Generates an RSA key pair, creates attestation documents, and decrypts messages
2. **Client (Parent EC2)**: Verifies attestation, validates PCR values, and encrypts messages
3. **Demonstrates**: Complete attestation flow with both positive and negative test cases

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AWS Nitro System                         │
│                                                             │
│  ┌────────────────────┐         ┌─────────────────────┐     │
│  │  Parent EC2        │         │  Nitro Enclave      │     │
│  │                    │ vsock   │                     │     │
│  │  • Client App      │◄───────►│  • Server App       │     │
│  │  • Full Network    │         │  • No Network       │     │
│  │  • Storage         │         │  • No Storage       │     │
│  └────────────────────┘         │  • Isolated CPU/RAM │     │
│                                 └─────────────────────┘     │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### vsock Communication Flow

![vsock Communication](diagrams/vsock_communication.gif)

## 📁 Project Structure

```
.
├── .gitignore                          # Git ignore file
├── README.md                           # This file
├── build-enclave.sh                    # Build enclave image
├── run-client.sh                       # Run client commands
├── run-enclave.sh                      # Start enclave
├── stop-enclave.sh                     # Stop enclave
├── diagrams/                           # Diagrams and visualizations
│   └── vsock_communication.gif
├── client/                             # Parent EC2 client
│   ├── attestation_verifier.py        # Attestation verification logic
│   ├── client.py                      # Client CLI application
│   └── requirements.txt               # Python dependencies
└── server/                             # Enclave server
    ├── app.py                         # Server application
    ├── Dockerfile                     # Enclave image definition
    ├── nsm_client.py                  # Nitro Security Module client
    ├── requirements.txt               # Python dependencies
    └── run.sh                         # Server startup script
```

## 🚀 Prerequisites

> **Important**: After launching your EC2 instance, all subsequent commands in this guide should be run **on the EC2 instance itself**, not on your local machine. You'll need to gain interactive shell access into the instance first (see step 1 below).

### 1. Launch and Connect to EC2 Instance

Launch an EC2 instance:
- **Instance Type**: Must [support](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html#nitro-enclave-reqs) Nitro Enclaves, for example c8g.large
- **AMI**: Amazon Linux 2023
- **Enable Nitro Enclaves**: In Advanced Details section

**Via AWS Console:**
1. Go to EC2 → Launch Instance
2. Choose instance type (e.g., c8g.large)
3. Expand Advanced Details → Nitro Enclave -> Enable


**Via AWS CLI:**
```bash
aws ec2 run-instances \
  --image-id ami-xxxxxxxxx \
  --instance-type c8g.large \
  --enclave-options Enabled=true \
  --key-name your-key-pair \
  --security-group-ids sg-xxxxxx \
  --subnet-id subnet-xxxxxx
```
For more details refer to [doc](https://docs.aws.amazon.com/enclaves/latest/user/getting-started.html#launch-instance).


**Connect to your EC2 instance via SSH:**

Follow this AWS [doc](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-to-linux-instance.html) to connect using an SSH client.
or
Follow this AWS [doc](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-with-systems-manager-session-manager.html) to connect using Session Manager.

**All remaining commands in this guide should be run on the EC2 instance after SSH connection.**

### 2. Install Docker and Nitro Enclaves CLI

**On your EC2 instance, run:**

```bash
# Install Nitro Enclaves CLI and development tools
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel

# Add current user to necessary groups
sudo usermod -aG ne $USER
sudo usermod -aG docker $USER
```

**Important: Log out and log back in** for group changes to take effect:

```bash
# Exit SSH session
exit

# Reconnect via SSH
ssh -i <your-key.pem> ec2-user@<public-ip>
```
or reconnect using SSM session manager again.


### 3. Start and Verify Docker Service

Before proceeding, ensure Docker is running properly:

```bash
# Check Docker service status
sudo systemctl status docker

# Should show "active (running)"
# If not running, start Docker:
sudo systemctl start docker

# Enable Docker to start on boot
sudo systemctl enable docker

# Verify Docker is working
docker ps

# Verify you can run Docker without sudo (after adding user to docker group)
docker run hello-world
```

**If Docker commands require sudo:**
- Ensure you logged out and back in after adding user to docker group
- Verify group membership: `groups` (should show 'docker')
- If still having issues, reboot the instance: `sudo reboot`

### 4. Configure Nitro Enclaves Allocator

```bash
# Edit allocator configuration
sudo vi /etc/nitro_enclaves/allocator.yaml

# Set:
# memory_mib: 1024
# cpu_count: 1

# Restart service
sudo systemctl restart nitro-enclaves-allocator.service
sudo systemctl enable nitro-enclaves-allocator.service
```

### 5. Verify Setup

```bash
# Check Nitro Enclaves allocator is running
sudo systemctl status nitro-enclaves-allocator.service

# Verify enclave resources are allocated
cat /etc/nitro_enclaves/allocator.yaml

# Check for any running enclaves (should be empty initially)
nitro-cli describe-enclaves
# Should return empty list []
```

### 6. Install Additional Tools

```bash
# Install jq for JSON parsing
sudo dnf install -y jq

# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Add uv to PATH (uv installs to ~/.local/bin)
export PATH="$HOME/.local/bin:$PATH"

# Make PATH change permanent (add to ~/.bashrc)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

# Verify installation
uv --version
```

## 🔨 Building the Demo

> **Note**: These commands should be run on your EC2 instance (after SSH connection).

### 1. Clone/Download This Repository

```bash
git clone https://github.com/aws-samples/sample-nitro-enclaves-attestation.git
cd sample-nitro-enclaves-attestation
```

### 2. Build the Enclave Image

```bash
./build-enclave.sh
```

This script:
1. Builds a Docker image with the server application
2. Converts it to an Enclave Image File (.eif)
3. Displays PCR measurements and saves them to `pcrs.json`

Expected output:
```
Building Nitro Enclave Attestation Demo
...
PCR Measurements (saved to pcrs.json):
{
  "PCR0": "...",
  "PCR1": "...",
  "PCR2": "..."
}
```

**Note**: The PCR values are automatically saved to `pcrs.json` and will be used by the client for verification.

## ▶️ Running the Demo

### 1. Start the Enclave

```bash
./run-enclave.sh
```

Expected output:
```
Starting Nitro Enclave
...
Enclave ID: i-xxxxx-encyyyyy
Enclave CID: 16
```

### 2. Run All Client Tests

```bash
./run-client.sh
```

This script automatically:
1. Creates a Python virtual environment using `uv`
2. Installs dependencies
3. Reads PCR values from `pcrs.json` (generated during build)
4. Runs all three test scenarios:
   - **Test 1**: Get attestation document and verify PCR values
   - **Test 2**: Send encrypted message to enclave
   - **Test 3**: Negative test with wrong public key

Expected output:
```
================================
Nitro Enclave Client Runner
================================

Reading PCR values from pcrs.json...
✓ PCR0: abc123...
✓ PCR1: def456...
✓ PCR2: ghi789...

✓ Virtual environment created
Activating virtual environment...
Installing requirements...
✓ Requirements installed

================================
Running Client Commands
================================

1. Getting attestation document with PCR verification...

==============================================================
ATTESTATION DOCUMENT VERIFIED
==============================================================
Module ID: i-xxxxx-encyyyyy
Timestamp: 1234567890

==============================================================
PCR VALUES (Platform Configuration Registers)
==============================================================

PCR0 - Enclave Image File:
  abc123... ✓ MATCHES EXPECTED VALUE

PCR1 - Linux Kernel & Bootstrap:
  def456... ✓ MATCHES EXPECTED VALUE

PCR2 - Application:
  ghi789... ✓ MATCHES EXPECTED VALUE

✓ ATTESTATION VERIFIED SUCCESSFULLY!
✓ Public key extracted successfully

================================
2. Sending encrypted message to enclave...
================================

==============================================================
ECHO - Send Encrypted Message to Enclave
==============================================================

→ Encrypting message: 'Hello from parent!'
→ Sending encrypted message to enclave...

==============================================================
✓ SUCCESS - Enclave decrypted and returned:
==============================================================
  'Hello from parent!'

================================
3. Running negative test with wrong public key...
================================

==============================================================
NEGATIVE TEST - Using Wrong Public Key
==============================================================

✗ ERROR: Decryption failed: ...

This proves the enclave can only decrypt messages encrypted with its own public key!

================================
✓ All client commands completed successfully!
================================
```


## 🛑 Stopping the Demo

### Stop the Enclave

```bash
./stop-enclave.sh
```

This script:
- Checks for any running enclaves
- Terminates the running enclave if found
- Confirms successful shutdown

### Terminate EC2 Instance

When you're done with the demo, don't forget to terminate your EC2 instance to avoid ongoing charges:

```bash
# Via AWS CLI (replace with your instance ID)
aws ec2 terminate-instances --instance-ids i-1234567890abcdef0

# Or via AWS Console
# Go to EC2 → Instances → Select instance → Instance State → Terminate
```

## 📜 Script Reference

### run-enclave.sh

Starts the Nitro Enclave with the following features:
- Checks if `enclave-server.eif` exists (prompts to run build if not)
- Automatically terminates any existing running enclave
- Launches enclave with configured resources:
  - Memory: 1024 MB
  - CPUs: 1
  - CID: 16 (vsock Context ID)
- Displays enclave ID and CID upon successful start
- Provides commands for viewing logs and testing

**Usage:**
```bash
./run-enclave.sh
```

### stop-enclave.sh

Safely stops the running Nitro Enclave:
- Checks for running enclaves
- Terminates the enclave if found
- Exits gracefully if no enclave is running

**Usage:**
```bash
./stop-enclave.sh
```

## 🔍 Understanding the Code

### Server (server/app.py)

The enclave server:
1. Generates an RSA key pair on startup (in-memory only)
2. Handles `hello` requests by generating attestation documents
3. Handles `echo` requests by decrypting messages with private key
4. Listens on vsock port 5000

Key functions:
- `get_attestation_document()`: Calls Nitro Security Module to generate signed attestation
- `handle_hello()`: Returns attestation + public key
- `handle_echo()`: Decrypts message using private key

### Client (client/client.py)

The parent EC2 client:
1. Connects to enclave via vsock
2. Verifies attestation documents
3. Encrypts messages with enclave's public key
4. Provides CLI interface

Key functions:
- `verify_attestation_document()`: Parses and displays PCR values
- `cmd_hello()`: Requests and verifies attestation
- `cmd_echo()`: Encrypts and sends message
- `cmd_echo_negative_test()`: Tests with wrong key

## 🔐 Security Considerations

### Production Checklist

- [ ] **Verify PCR Values**: Supply expected PCR values to client
- [ ] **Verify Signatures**: Use AWS Nitro root certificates to verify attestation signatures
- [ ] **Disable Debug Mode**: Remove `--debug-mode` flag when running enclave
- [ ] **Validate Timestamps**: Check attestation document freshness (3 hour TTL)
- [ ] **Error Handling**: Add robust error handling and logging


## 📚 Additional Resources

- [Blog Post](nitro-enclaves-attestation-blog.md) - Comprehensive guide with detailed explanations
- [AWS Nitro Enclaves Documentation](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
- [Attestation Process](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md)

## 🐛 Troubleshooting

### Running Enclave in Debug Mode

For debugging purposes, you can run the enclave in debug mode using the --attach-console parameter with nitro-cli. This allows the enclave to run without PCR validation.

**1. Run enclave with console attached:**

```bash
nitro-cli run-enclave \
  --eif-path enclave-server.eif \
  --memory 1024 \
  --cpu-count 1 \
  --attach-console
```

This command:
- Attaches to the console immediately (`--attach-console`)
- Returns the console output directly to your terminal
- When using `--attach-console`, the enclave runs in debug mode with PCR 0,1,2 set to zeros.

**2. Run the client:**

```bash
./run-client.sh
```

The client will automatically use the PCR values from `pcrs.json`. In debug mode, the enclave returns all-zero PCRs (except PCR3, PCR4) which will be verified by the client.

**Note**: Debug mode is meant to be used for dev/test.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

---

**Happy Enclave Building! 🚀**
