"""
NSM (Nitro Security Module) Client
Python bindings for AWS Nitro Enclaves NSM device
"""

import os
import cbor2
import logging
import fcntl
import ctypes

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# NSM ioctl definitions
NSM_IOCTL_MAGIC = 0x0A
NSM_REQUEST_MAX_SIZE = 0x1000
NSM_RESPONSE_MAX_SIZE = 0x3000


class NSMClient:
    """Client for interacting with AWS Nitro Secure Module (NSM) device"""
    
    def __init__(self, device_path: str = "/dev/nsm"):
        self.device_path = device_path
        self._fd = None
        logger.debug(f"NSM client initialized with device: {device_path}")
    
    def _ensure_device_open(self):
        """Ensure NSM device is open, open if needed"""
        if self._fd is None:
            self._fd = os.open(self.device_path, os.O_RDWR)
            logger.debug(f"NSM device opened, fd: {self._fd}")
    
    def close(self):
        """Close NSM device if open"""
        if self._fd is not None:
            os.close(self._fd)
            logger.debug("NSM device closed")
            self._fd = None
    
    def is_available(self) -> bool:
        """Check if NSM device is available"""
        return os.path.exists(self.device_path)
    
    def _nsm_ioctl(self, request_data: bytes) -> bytes:
        """
        Send ioctl request to NSM device and receive response
        Uses persistent file descriptor for better performance
        """
        try:
            # Ensure device is open
            self._ensure_device_open()
            logger.debug(f"Using NSM device fd: {self._fd}")
            
            # NSM message structure matching Rust IoSlice/IoSliceMut (iovec)
            class NsmMessage(ctypes.Structure):
                _fields_ = [
                    ("request_base", ctypes.c_void_p),
                    ("request_len", ctypes.c_size_t),
                    ("response_base", ctypes.c_void_p),
                    ("response_len", ctypes.c_size_t),
                ]
            
            # Create buffers
            request_buf = ctypes.create_string_buffer(request_data)
            response_buf = ctypes.create_string_buffer(NSM_RESPONSE_MAX_SIZE)
            
            # Setup message structure
            msg = NsmMessage()
            msg.request_base = ctypes.cast(request_buf, ctypes.c_void_p)
            msg.request_len = len(request_data)
            msg.response_base = ctypes.cast(response_buf, ctypes.c_void_p)
            msg.response_len = NSM_RESPONSE_MAX_SIZE
            
            # NSM ioctl command: _IOWR(NSM_IOCTL_MAGIC, 0, struct nsm_message)
            struct_size = ctypes.sizeof(NsmMessage)
            NSM_IOCTL_REQUEST = (3 << 30) | (NSM_IOCTL_MAGIC << 8) | 0x00 | (struct_size << 16)
            
            logger.debug(f"Sending ioctl to NSM device (request size: {len(request_data)} bytes)")
            
            # Send ioctl
            fcntl.ioctl(self._fd, NSM_IOCTL_REQUEST, msg)
            
            # Get actual response size and data
            actual_response_size = msg.response_len
            logger.debug(f"NSM response size: {actual_response_size} bytes")
            
            if actual_response_size == 0:
                raise Exception("No response data received from NSM")
            
            response_data = response_buf.raw[:actual_response_size]
            return response_data
            
        except Exception as e:
            # Log as warning since we're propagating the exception, not handling it
            logger.warning(f"NSM ioctl failed, propagating exception: {e}")
            # Close and reset fd on error
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError as close_error:
                    # Log but don't raise - we're already handling an error
                    # File descriptor may already be closed or invalid
                    logger.debug(f"Failed to close NSM device fd during error cleanup: {close_error}")
                self._fd = None
            raise
    
    def get_attestation_document(
        self, 
        user_data: bytes = None, 
        nonce: bytes = None, 
        public_key: bytes = None
    ) -> bytes:
        """
        Get attestation document from NSM
        
        Args:
            user_data: Optional user data to include (max 512 bytes)
            nonce: Optional nonce for replay protection (max 512 bytes)
            public_key: Optional public key to include (max 1024 bytes)
            
        Returns:
            CBOR-encoded COSE_Sign1 attestation document
        """
        logger.info("Requesting attestation document from NSM")
        
        # Build NSM attestation request in CBOR format
        attestation_params = {}
        
        if user_data:
            if len(user_data) > 512:
                raise ValueError("user_data must be <= 512 bytes")
            attestation_params["user_data"] = user_data
            logger.debug(f"Including user_data: {len(user_data)} bytes")
        
        if nonce:
            if len(nonce) > 512:
                raise ValueError("nonce must be <= 512 bytes")
            attestation_params["nonce"] = nonce
            logger.debug(f"Including nonce: {len(nonce)} bytes")
        
        if public_key:
            if len(public_key) > 1024:
                raise ValueError("public_key must be <= 1024 bytes")
            attestation_params["public_key"] = public_key
            logger.debug(f"Including public_key: {len(public_key)} bytes")
        
        # Create request
        request = {"Attestation": attestation_params}
        request_cbor = cbor2.dumps(request)
        
        logger.debug(f"NSM request size: {len(request_cbor)} bytes")
        
        # Send to NSM device
        response_cbor = self._nsm_ioctl(request_cbor)
        
        # Parse response
        response = cbor2.loads(response_cbor)
        
        # Response format: {"Attestation": {"document": <cbor_bytes>}} or {"Error": ...}
        if "Error" in response:
            raise Exception(f"NSM error: {response['Error']}")
        
        if "Attestation" not in response or "document" not in response["Attestation"]:
            raise Exception("Invalid NSM response format")
        
        attestation_doc = response["Attestation"]["document"]
        logger.info(f"Attestation document generated: {len(attestation_doc)} bytes")
        
        return attestation_doc
