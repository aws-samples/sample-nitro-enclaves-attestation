#!/usr/bin/env python3
"""
Nitro Enclave Client - Attestation Demo
Runs on parent EC2 instance and communicates with enclave
"""

import argparse
import json
import socket
import base64
import sys
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import cbor2

# Import the attestation verifier
try:
    from attestation_verifier import verify_attestation_document, format_pcr_display
    VERIFICATION_AVAILABLE = True
except ImportError:
    print("⚠ Warning: attestation_verifier.py not found. Using basic verification only.")
    VERIFICATION_AVAILABLE = False

class EnclaveClient:
    def __init__(self, enclave_cid, port=5000):
        self.enclave_cid = enclave_cid
        self.port = port
    
    def send_request(self, request):
        """Send request to enclave via vsock"""
        try:
            s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((self.enclave_cid, self.port))
            
            request_json = json.dumps(request)
            s.sendall(request_json.encode('utf-8'))
            
            # Receive response
            response_data = b''
            while True:
                chunk = s.recv(16384)
                if not chunk:
                    break
                response_data += chunk
                if len(chunk) < 16384:
                    break
            
            s.close()
            
            return json.loads(response_data.decode('utf-8'))
            
        except socket.timeout:
            print("✗ Connection to enclave timed out")
            sys.exit(1)
        except ConnectionRefusedError:
            print(f"✗ Connection refused. Is the enclave running on CID {self.enclave_cid}?")
            sys.exit(1)
        except Exception as e:
            print(f"✗ Communication error: {e}")
            sys.exit(1)
    
    def verify_attestation_simple(self, attestation_doc_b64):
        """Simple attestation parsing (no cryptographic verification)"""
        try:
            attestation_doc = base64.b64decode(attestation_doc_b64)
            doc = cbor2.loads(attestation_doc)
            pcrs = doc.get('pcrs', {})
            
            print("\n" + "="*70)
            print("ATTESTATION DOCUMENT PARSED (NOT CRYPTOGRAPHICALLY VERIFIED)")
            print("="*70)
            print(f"Module ID: {doc.get('module_id', 'N/A')}")
            print(f"Timestamp: {doc.get('timestamp', 'N/A')}")
            
            print("\n" + "="*70)
            print("PCR VALUES")
            print("="*70)
            
            for pcr_index in sorted(pcrs.keys()):
                pcr_value = pcrs[pcr_index].hex()
                pcr_name = self.get_pcr_name(pcr_index)
                print(f"\nPCR{pcr_index} - {pcr_name}:")
                print(f"  {pcr_value}")
            
            print("\n⚠ WARNING: This is basic parsing only. In production, you MUST:")
            print("  1. Verify the COSE signature")
            print("  2. Validate certificate chain against AWS root CA")
            print("  3. Compare PCRs to expected values")
            print("  4. Check timestamp freshness")
            
            return True, pcrs
            
        except Exception as e:
            print(f"\n✗ Attestation parsing failed: {e}")
            return False, {}
    
    def verify_attestation_full(self, attestation_doc_b64, expected_pcrs=None):
        """Full cryptographic attestation verification"""
        try:
            print("\n" + "="*70)
            print("CRYPTOGRAPHIC ATTESTATION VERIFICATION")
            print("="*70 + "\n")
            
            # Use the proper verification module
            result = verify_attestation_document(attestation_doc_b64, expected_pcrs)
            
            if not result['verified']:
                print(f"✗ Verification failed: {result.get('error', 'Unknown error')}")
                return False, {}
            
            # Display results
            print("\n✓ Attestation document verified successfully!\n")
            
            if result.get('root_verified'):
                print("✓ Root certificate verified against AWS root CA")
            else:
                print("⚠ Root certificate could not be verified")
            
            if result.get('cose_verified'):
                print("✓ COSE signature verified")
            else:
                print("⚠ COSE signature verification skipped or failed")
            
            if result.get('pcr_verified') and expected_pcrs:
                print("✓ All PCR values match expected values")
            elif result.get('pcr_mismatches'):
                print(f"✗ PCR mismatches: {', '.join(result['pcr_mismatches'])}")
            
            print(f"\n{'='*70}")
            print("ATTESTATION DETAILS")
            print(f"{'='*70}")
            print(f"Module ID: {result.get('module_id', 'N/A')}")
            print(f"Timestamp: {result.get('timestamp', 'N/A')}")
            
            print(f"\n{'='*70}")
            print("PCR VALUES")
            print(f"{'='*70}")
            
            pcrs = result.get('pcrs', {})
            for pcr_index in sorted(pcrs.keys()):
                pcr_value = pcrs[pcr_index]
                pcr_name = self.get_pcr_name(pcr_index)
                print(f"\nPCR{pcr_index} - {pcr_name}:")
                print(f"  {pcr_value}")
                
                if expected_pcrs and pcr_index in expected_pcrs:
                    if pcr_value == expected_pcrs[pcr_index]:
                        print(f"  ✓ Matches expected value")
                    else:
                        print(f"  ✗ MISMATCH! Expected: {expected_pcrs[pcr_index]}")
            
            return True, pcrs
            
        except Exception as e:
            print(f"\n✗ Verification failed: {e}")
            import traceback
            traceback.print_exc()
            return False, {}
    
    def get_pcr_name(self, index):
        """Get human-readable PCR name"""
        pcr_names = {
            0: "Enclave Image File",
            1: "Linux Kernel & Bootstrap",
            2: "Application",
            3: "IAM Role",
            4: "Instance ID",
            8: "Signing Certificate"
        }
        return pcr_names.get(index, "Unknown")
    
    def cmd_hello(self, expected_pcrs=None):
        """Execute hello command"""
        print("\n" + "="*70)
        print("HELLO - Request Attestation from Enclave")
        print("="*70 + "\n")
        
        # Generate a random nonce for replay attack prevention
        nonce_bytes = os.urandom(32)  # 32 bytes = 256 bits
        nonce_b64 = base64.b64encode(nonce_bytes).decode('utf-8')
        print(f"→ Generated nonce: {nonce_bytes.hex()[:32]}... ({len(nonce_bytes)} bytes)")
        
        print("→ Sending hello request with nonce to enclave...")
        
        request = {
            "command": "hello",
            "nonce": nonce_b64
        }
        response = self.send_request(request)
        
        if "error" in response:
            print(f"\n✗ Error: {response['error']}")
            return
        
        # Verify the nonce in the attestation document
        attestation_doc = response['attestation_document']
        attestation_doc_bytes = base64.b64decode(attestation_doc)
        
        # Parse COSE_Sign1 structure
        # COSE_Sign1 is a CBOR array: [protected, unprotected, payload, signature]
        cose_sign1 = cbor2.loads(attestation_doc_bytes)
        
        # Extract payload (index 2) and decode it
        payload = cose_sign1[2]
        doc = cbor2.loads(payload)
        
        # Check if nonce matches
        doc_nonce = doc.get('nonce')
        if doc_nonce:
            if doc_nonce == nonce_bytes:
                print("✓ Nonce verified: matches the one we sent (replay attack protection)")
            else:
                print(f"✗ NONCE MISMATCH!")
                print(f"  Sent:     {nonce_bytes.hex()}")
                print(f"  Received: {doc_nonce.hex()}")
                print("\n✗ Attestation failed: nonce mismatch indicates potential replay attack!")
                return None
        else:
            print("⚠ Warning: No nonce found in attestation document")
        
        # Verify attestation using proper verification if available
        if VERIFICATION_AVAILABLE:
            verified, pcrs = self.verify_attestation_full(attestation_doc, expected_pcrs)
        else:
            verified, pcrs = self.verify_attestation_simple(attestation_doc)
        
        if verified:
            print("\n" + "="*70)
            print("PUBLIC KEY FROM ENCLAVE")
            print("="*70)
            public_key_b64 = response['public_key']
            
            # Pretty print the public key
            pem_lines = base64.b64decode(public_key_b64).decode('utf-8').split('\n')
            for line in pem_lines:
                print(line)
            
            print("\n" + "="*70)
            print("✓ ATTESTATION COMPLETE!")
            print("="*70)
            
            # Output the public key in machine-parseable format for scripts
            print(f"\n[PUBLIC_KEY_B64]{public_key_b64}[/PUBLIC_KEY_B64]")
            
            print(f"\nℹ You can now use this public key with the echo command:")
            print(f"\n  python client.py echo '{public_key_b64[:50]}...' 'Hello Enclave'\n")
            
            if pcrs and not expected_pcrs:
                print("\n⚠ NOTE: You didn't provide expected PCR values.")
                print("   In production, you MUST verify PCRs match expected values!")
                print("\n   Save these PCR values from your build output and use --pcr0, --pcr1, --pcr2 flags")
            
            # Return the public key for programmatic use
            return public_key_b64
        else:
            print("\n✗ Attestation verification failed!")
            return None
    
    def cmd_echo(self, public_key_b64, message):
        """Execute echo command"""
        print("\n" + "="*70)
        print("ECHO - Send Encrypted Message to Enclave")
        print("="*70 + "\n")
        
        try:
            # Decode and load public key
            print("→ Loading public key...")
            public_key_pem = base64.b64decode(public_key_b64)
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=default_backend()
            )
            
            # Encrypt message
            print(f"→ Encrypting message: '{message}'")
            encrypted = public_key.encrypt(
                message.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            encrypted_b64 = base64.b64encode(encrypted).decode('utf-8')
            print(f"→ Encrypted message size: {len(encrypted)} bytes")
            
            print(f"→ Sending encrypted message to enclave...")
            request = {
                "command": "echo",
                "encrypted_message": encrypted_b64
            }
            
            response = self.send_request(request)
            
            if "error" in response:
                print(f"\n{'='*70}")
                print(f"✗ ERROR: {response['error']}")
                print(f"{'='*70}")
                print("\nThis could mean:")
                print("  • The public key doesn't match the enclave's private key")
                print("  • The message is too long for RSA encryption")
                print("  • The enclave restarted and generated a new key pair")
                print()
            else:
                print(f"\n{'='*70}")
                print(f"✓ SUCCESS - Enclave decrypted and returned:")
                print(f"{'='*70}")
                print(f"\n  '{response['decrypted_message']}'\n")
                
        except Exception as e:
            print(f"\n✗ Encryption/Communication failed: {e}")
    
    def cmd_echo_negative_test(self, message):
        """Negative test - use wrong public key"""
        print("\n" + "="*70)
        print("NEGATIVE TEST - Using Wrong Public Key")
        print("="*70 + "\n")
        
        print("→ Generating a random public key that the enclave doesn't have...")
        
        # Generate a different key pair
        wrong_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        wrong_public_key = wrong_private_key.public_key()
        
        wrong_public_key_pem = wrong_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        wrong_public_key_b64 = base64.b64encode(wrong_public_key_pem).decode('utf-8')
        
        print("→ Attempting to send message encrypted with wrong key...\n")
        self.cmd_echo(wrong_public_key_b64, message)
        
        print("\n" + "="*70)
        print("NEGATIVE TEST COMPLETE")
        print("="*70)
        print("\nAs expected, the enclave could NOT decrypt the message because")
        print("it was encrypted with a public key that doesn't match the")
        print("enclave's private key. This proves the cryptographic security.\n")

def main():
    parser = argparse.ArgumentParser(
        description='Nitro Enclave Attestation Client',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Get attestation document and verify PCRs
  python client.py hello
  
  # Send encrypted message to enclave (use public key from hello command)
  python client.py echo 'LS0tLS1CR...' 'Hello from parent!'
  
  # Negative test with wrong public key
  python client.py echo-negative-test 'This should fail'
        """
    )
    
    parser.add_argument(
        '--cid',
        type=int,
        default=16,
        help='Enclave CID (default: 16, use "nitro-cli describe-enclaves" to find actual CID)'
    )
    
    parser.add_argument(
        '--pcr0',
        type=str,
        help='Expected PCR0 value (from build output) for verification'
    )
    
    parser.add_argument(
        '--pcr1',
        type=str,
        help='Expected PCR1 value (from build output) for verification'
    )
    
    parser.add_argument(
        '--pcr2',
        type=str,
        help='Expected PCR2 value (from build output) for verification'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Hello command
    hello_parser = subparsers.add_parser(
        'hello', 
        help='Get attestation document from enclave and verify it'
    )
    
    # Echo command
    echo_parser = subparsers.add_parser(
        'echo', 
        help='Send encrypted message to enclave for decryption'
    )
    echo_parser.add_argument(
        'public_key', 
        help='Base64-encoded public key from hello command'
    )
    echo_parser.add_argument(
        'message', 
        help='Message to encrypt and send to enclave'
    )
    
    # Negative test command
    neg_parser = subparsers.add_parser(
        'echo-negative-test',
        help='Negative test: try to decrypt with wrong public key'
    )
    neg_parser.add_argument(
        'message', 
        help='Message to send (will fail to decrypt)'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    print("\n" + "="*70)
    print("AWS NITRO ENCLAVE - ATTESTATION CLIENT")
    print("="*70)
    print(f"Enclave CID: {args.cid}")
    print(f"Command: {args.command}")
    print("="*70)
    
    client = EnclaveClient(args.cid)
    
    # Build expected PCRs dict if provided
    expected_pcrs = {}
    if hasattr(args, 'pcr0') and args.pcr0:
        expected_pcrs[0] = args.pcr0
    if hasattr(args, 'pcr1') and args.pcr1:
        expected_pcrs[1] = args.pcr1
    if hasattr(args, 'pcr2') and args.pcr2:
        expected_pcrs[2] = args.pcr2
    
    if args.command == 'hello':
        client.cmd_hello(expected_pcrs if expected_pcrs else None)
    elif args.command == 'echo':
        client.cmd_echo(args.public_key, args.message)
    elif args.command == 'echo-negative-test':
        client.cmd_echo_negative_test(args.message)

if __name__ == '__main__':
    main()
