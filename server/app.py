"""
Nitro Enclave Server - Attestation Demo
Runs inside the enclave and provides attestation and decryption services
"""

import json
import socket
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import sys
from nsm_client import NSMClient

class EnclaveServer:
    def __init__(self):
        print("Initializing Enclave Server...")
        
        # Initialize NSM client
        self.nsm = NSMClient()
        if not self.nsm.is_available():
            print("WARNING: NSM device not available - attestation will not work")
            print("This is normal if running outside an enclave for testing")
        else:
            print("✓ NSM device available")
        
        # Generate RSA key pair (kept in memory only)
        print("Generating RSA key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Serialize public key for transmission
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print("Key pair generated successfully")
        print(f"Public key length: {len(self.public_key_pem)} bytes")
    
    def get_attestation_document(self, nonce=None):
        """Generate attestation document with public key embedded using NSM API"""
        try:
            print("Requesting attestation document from NSM...")
            
            # Convert nonce to bytes if provided
            nonce_bytes = None
            if nonce:
                nonce_bytes = base64.b64decode(nonce)
                print(f"Using nonce: {nonce_bytes.hex()[:32]}... ({len(nonce_bytes)} bytes)")
            
            # Request attestation from NSM with public key embedded
            # NSM supports three optional parameters:
            # 1. nonce - for replay attack prevention
            # 2. user_data - arbitrary user data
            # 3. public_key - public key to embed
            attestation_doc_bytes = self.nsm.get_attestation_document(
                public_key=self.public_key_pem,
                nonce=nonce_bytes,  # Include nonce for replay protection
                user_data=None  # Could add custom user data
            )
            
            # Encode as base64 for JSON transmission
            attestation_doc_b64 = base64.b64encode(attestation_doc_bytes).decode('utf-8')
            print(f"✓ Attestation document generated: {len(attestation_doc_bytes)} bytes")
            
            return attestation_doc_b64
            
        except Exception as e:
            print(f"✗ Error generating attestation: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def handle_hello(self, request):
        """Handle hello request - return attestation document"""
        print("\n=== Handling HELLO request ===")
        
        # Extract nonce if provided
        nonce = request.get('nonce')
        if nonce:
            print(f"Client provided nonce for replay protection")
        
        attestation_doc = self.get_attestation_document(nonce)
        if not attestation_doc:
            print("Failed to generate attestation document")
            return {"error": "Failed to generate attestation"}
        
        response = {
            "attestation_document": attestation_doc,
            "public_key": base64.b64encode(self.public_key_pem).decode('utf-8')
        }
        
        print("Sending attestation document and public key to client")
        return response
    
    def handle_echo(self, encrypted_message_b64):
        """Handle echo request - decrypt and return message"""
        print("\n=== Handling ECHO request ===")
        
        try:
            # Decode base64 encrypted message
            encrypted_message = base64.b64decode(encrypted_message_b64)
            print(f"Received encrypted message: {len(encrypted_message)} bytes")
            
            # Decrypt using private key
            print("Attempting decryption with private key...")
            decrypted = self.private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            decrypted_text = decrypted.decode('utf-8')
            print(f"Successfully decrypted message: '{decrypted_text}'")
            
            return {
                "decrypted_message": decrypted_text
            }
            
        except Exception as e:
            print(f"Decryption failed: {str(e)}")
            return {"error": f"Decryption failed: {str(e)}"}
    
    def start(self):
        """Start the vsock server"""
        # vsock configuration
        # CID: VMADDR_CID_ANY allows connection from parent
        # Port: arbitrary high number
        VSOCK_PORT = 5000
        
        print(f"\n{'='*60}")
        print(f"Starting Enclave Server on vsock port {VSOCK_PORT}")
        print(f"{'='*60}\n")
        
        try:
            # Create vsock socket
            s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((socket.VMADDR_CID_ANY, VSOCK_PORT))
            s.listen(5)
            
            print(f"✓ Server listening on vsock port {VSOCK_PORT}")
            print("Waiting for connections from parent instance...")
            print()
            
        except Exception as e:
            print(f"✗ Failed to start server: {e}")
            sys.exit(1)
        
        # Main server loop
        while True:
            try:
                conn, addr = s.accept()
                print(f"\n{'='*60}")
                print(f"New connection from CID {addr[0]}")
                print(f"{'='*60}")
                
                # Receive request
                data = b''
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(chunk) < 4096:
                        break
                
                if not data:
                    print("No data received")
                    conn.close()
                    continue
                
                # Parse request
                request = json.loads(data.decode('utf-8'))
                print(f"Command: {request.get('command', 'unknown')}")
                
                # Route request
                if request['command'] == 'hello':
                    response = self.handle_hello(request)
                elif request['command'] == 'echo':
                    response = self.handle_echo(request['encrypted_message'])
                else:
                    response = {"error": "Unknown command"}
                    print(f"Unknown command: {request.get('command')}")
                
                # Send response
                response_json = json.dumps(response)
                conn.sendall(response_json.encode('utf-8'))
                print(f"Response sent: {len(response_json)} bytes")
                
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
                error_response = {"error": "Invalid JSON"}
                conn.sendall(json.dumps(error_response).encode('utf-8'))
                
            except Exception as e:
                print(f"Error handling request: {e}")
                error_response = {"error": str(e)}
                try:
                    conn.sendall(json.dumps(error_response).encode('utf-8'))
                except OSError as send_error:
                    # Client may have disconnected - log but don't raise
                    # We're already in error handling, so connection issues are expected
                    print(f"Failed to send error response to client: {send_error}")
                    
            finally:
                conn.close()
                print("Connection closed\n")

if __name__ == '__main__':
    print("\n" + "="*60)
    print("AWS NITRO ENCLAVE - ATTESTATION SERVER")
    print("="*60 + "\n")
    
    try:
        server = EnclaveServer()
        server.start()
    except KeyboardInterrupt:
        print("\n\nServer stopped by user")
    except Exception as e:
        print(f"\n\nFatal error: {e}")
        sys.exit(1)
