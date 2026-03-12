import hmac
import hashlib
import os
import logging
from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

# Use a dummy secret key for the prototype if one is not provided in .env
DUMMY_SECRET = os.environ.get("CRYPTO_SIGNING_SECRET", "CSPM-v2-Enterprise-Zero-Trust-Key-842910")

def generate_signature(script_text: str) -> str:
    """
    Generates an HMAC-SHA256 signature for the given script text using the environment secret.
    """
    if not script_text:
        return ""
        
    secret_bytes = DUMMY_SECRET.encode('utf-8')
    script_bytes = script_text.encode('utf-8')
    
    signature = hmac.new(secret_bytes, script_bytes, hashlib.sha256).hexdigest()
    logger.info(f"Generated cryptographic signature for remediation script.")
    return signature

def verify_signature(script_text: str, signature: str) -> bool:
    """
    Recalculates the HMAC-SHA256 hash of the script text and compares it to the provided signature
    to mathematically prove the script has not been tampered with since the LLM Critic approved it.
    """
    if not script_text or not signature:
        return False
        
    expected_signature = generate_signature(script_text)
    
    # Use hmac.compare_digest to prevent timing attacks
    is_valid = hmac.compare_digest(expected_signature, signature)
    
    if is_valid:
        logger.info("Cryptographic signature verified successfully. Execution authorized.")
    else:
        logger.warning("CRITICAL: Cryptographic signature verification FAILED. Possible tampering detected.")
        
    return is_valid

if __name__ == "__main__":
    # Test script for standalone execution
    sample_script = "aws s3api put-public-access-block --bucket test"
    sig = generate_signature(sample_script)
    print(f"Generated Sig: {sig}")
    print(f"Verified: {verify_signature(sample_script, sig)}")
    print(f"Tampered Verified: {verify_signature(sample_script + ' --delete', sig)}")
