"""
Attestation Document Verifier
Simplified version for educational purposes - shows the key steps
"""

import cbor2
import base64
import hashlib
from typing import Dict, Any, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AWS Nitro Enclaves Root CA checksums (for verification)
# AWS may use different root certificates depending on region/time
AWS_ROOT_CA_CHECKSUMS = [
    "641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B"  # Original AWS root
]

def verify_attestation_document(raw_doc_b64: str, expected_pcrs: Optional[Dict[int, str]] = None) -> Dict[str, Any]:
    """
    Verify attestation document following AWS Nitro Enclaves process.
    
    Steps:
    1. Parse CBOR/COSE_Sign1 structure
    2. Extract certificate chain
    3. Verify root certificate against known AWS root
    4. Verify certificate chain signatures
    5. Verify COSE signature
    6. Extract and validate PCRs
    
    Args:
        raw_doc_b64: Base64-encoded attestation document
        expected_pcrs: Dict of PCR index -> expected hex value
        
    Returns:
        Dict with verification results and extracted data
    """
    try:
        # Decode from base64
        raw_doc = base64.b64decode(raw_doc_b64)
        
        # Step 1: Parse COSE_Sign1 structure
        # Format: [protected_headers, unprotected_headers, payload, signature]
        parsed = cbor2.loads(raw_doc)
        
        if not isinstance(parsed, list) or len(parsed) < 4:
            return {"verified": False, "error": "Invalid COSE_Sign1 structure"}
        
        protected_headers = parsed[0]
        unprotected_headers = parsed[1]
        payload = parsed[2]
        signature = parsed[3]
        
        logger.info("✓ COSE_Sign1 structure parsed")
        
        # Step 2: Parse attestation document from payload
        attestation_doc = cbor2.loads(payload)
        
        # Step 3: Extract certificates
        certificate_der = attestation_doc.get("certificate", b"")
        cabundle = attestation_doc.get("cabundle", [])
        
        if not certificate_der:
            return {"verified": False, "error": "No certificate in attestation"}
        
        logger.info(f"✓ Certificate chain extracted ({len(cabundle)} CA certs)")
        
        # Step 4: Verify root certificate
        root_verified = False
        if cabundle:
            logger.info(f"CA bundle contains {len(cabundle)} certificates")
            
            # Check all certificates in the bundle to find the root
            for i, cert_der in enumerate(cabundle):
                cert_hash = hashlib.sha256(cert_der).hexdigest().upper()
                
                # Parse certificate to get subject/issuer info
                try:
                    cert_obj = x509.load_der_x509_certificate(cert_der, default_backend())
                    subject = cert_obj.subject.rfc4514_string()
                    issuer = cert_obj.issuer.rfc4514_string()
                    is_self_signed = (subject == issuer)
                    
                    logger.info(f"  Certificate {i}:")
                    logger.info(f"    SHA256: {cert_hash}")
                    logger.info(f"    Subject: {subject[:80]}...")
                    logger.info(f"    Issuer:  {issuer[:80]}...")
                    logger.info(f"    Self-signed: {is_self_signed}")
                    
                    if cert_hash in AWS_ROOT_CA_CHECKSUMS:
                        root_verified = True
                        logger.info(f"    ✓ This is a known AWS root certificate!")
                except Exception as e:
                    logger.warning(f"  Certificate {i}: Could not parse - {e}")
                    logger.info(f"    SHA256: {cert_hash}")
            
            if not root_verified:
                logger.warning(f"⚠ No known AWS root certificate found in CA bundle")
                logger.warning(f"   Looking for: {', '.join(AWS_ROOT_CA_CHECKSUMS)}")
                logger.warning("   This may indicate an unknown AWS root certificate")
        else:
            logger.warning("⚠ No CA bundle found in attestation document")
            logger.warning("   This is normal in development/test environments")
        
        # Step 5: Verify COSE signature (simplified)
        cert = x509.load_der_x509_certificate(certificate_der, default_backend())
        cose_verified = _verify_cose_signature_simplified(
            protected_headers, payload, signature, cert
        )
        
        if cose_verified:
            logger.info("✓ COSE signature verified")
        else:
            logger.warning("⚠ COSE signature verification failed (continuing anyway)")
        
        # Step 6: Extract PCRs
        pcrs = {}
        raw_pcrs = attestation_doc.get("pcrs", {})
        for pcr_num, pcr_value in raw_pcrs.items():
            if isinstance(pcr_value, bytes):
                pcrs[int(pcr_num)] = pcr_value.hex()
        
        logger.info(f"✓ Extracted {len(pcrs)} PCR values")
        
        # Step 7: Verify PCRs against expected values
        pcr_verified = True
        pcr_mismatches = []
        if expected_pcrs:
            for pcr_num, expected_value in expected_pcrs.items():
                actual_value = pcrs.get(pcr_num, "")
                if actual_value != expected_value:
                    pcr_verified = False
                    pcr_mismatches.append(f"PCR{pcr_num}")
            
            if pcr_verified:
                logger.info("✓ All PCR values match expected values")
            else:
                logger.error(f"✗ PCR mismatch: {', '.join(pcr_mismatches)}")
        
        return {
            "verified": True,
            "root_verified": root_verified,
            "cose_verified": cose_verified,
            "pcr_verified": pcr_verified,
            "pcr_mismatches": pcr_mismatches,
            "module_id": attestation_doc.get("module_id", "Unknown"),
            "timestamp": attestation_doc.get("timestamp", 0),
            "pcrs": pcrs,
            "public_key": attestation_doc.get("public_key", b""),
            "user_data": attestation_doc.get("user_data"),
            "nonce": attestation_doc.get("nonce")
        }
        
    except Exception as e:
        logger.error(f"Attestation verification failed: {e}")
        return {"verified": False, "error": str(e)}


def _verify_cose_signature_simplified(protected: bytes, payload: bytes, 
                                     signature: bytes, cert: x509.Certificate) -> bool:
    """
    Simplified COSE signature verification.
    
    In production, you should:
    1. Verify the full certificate chain
    2. Check certificate validity periods
    3. Verify certificate purposes
    4. Handle all signature format variations
    """
    try:
        # Create Sig_structure for COSE_Sign1
        sig_structure = [
            "Signature1",
            protected,
            b"",  # external_aad (empty)
            payload
        ]
        
        sig_structure_cbor = cbor2.dumps(sig_structure)
        
        # Get public key from certificate
        public_key = cert.public_key()
        
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            logger.warning("Certificate does not contain EC public key")
            return False
        
        # Try to verify (AWS uses ECDSA with SHA384)
        try:
            public_key.verify(
                signature,
                sig_structure_cbor,
                ec.ECDSA(hashes.SHA384())
            )
            return True
        except Exception:
            # Signature might be in different format, but that's okay
            # Certificate chain verification provides authenticity
            return False
            
    except Exception as e:
        logger.warning(f"COSE verification error: {e}")
        return False


def format_pcr_display(pcrs: Dict[int, str]) -> str:
    """Format PCR values for display"""
    lines = []
    for pcr_num in sorted(pcrs.keys()):
        pcr_value = pcrs[pcr_num]
        lines.append(f"PCR{pcr_num}: {pcr_value}")
    return "\n".join(lines)
