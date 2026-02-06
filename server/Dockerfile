# Nitro Enclave Dockerfile
# Note: Enclaves run in a highly isolated environment without traditional Docker features

# checkov:skip=CKV_DOCKER_3: Enclaves run in isolated environment, user creation not applicable
# checkov:skip=CKV_DOCKER_2: Enclaves don't support healthchecks, vsock communication only
FROM python:3.9-slim

WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY nsm_client.py .
COPY app.py .
COPY run.sh .

# Make run.sh executable
RUN chmod +x /app/run.sh

# Run the server
CMD ["/app/run.sh"]
