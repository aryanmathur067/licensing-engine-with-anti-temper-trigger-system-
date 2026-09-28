"""
Public Key Verification and Hashing Utilities for CORTA LicenseGuard
"""

import base64
import hashlib
import json
from typing import Any, Dict, Union, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def canonical_json_bytes(data: Any) -> bytes:
    """
    Serializes a Python object into canonical, deterministic JSON bytes.
    Keys are sorted, whitespace is minimized, and UTF-8 is used.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_sha256(data: Union[bytes, str]) -> str:
    """Computes lowercase hex SHA-256 hash."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


class LicenseVerifier:
    """
    Verifies digital signatures using an Ed25519 Public Key.
    """

    def __init__(self, public_key_pem_or_bytes: Union[str, bytes]):
        if isinstance(public_key_pem_or_bytes, str):
            data = public_key_pem_or_bytes.encode("utf-8")
        else:
            data = public_key_pem_or_bytes
        self.public_key = serialization.load_pem_public_key(data)
        if not isinstance(self.public_key, ed25519.Ed25519PublicKey):
            raise ValueError("Provided public key is not an Ed25519 key")

    @classmethod
    def from_file(cls, filepath: str) -> "LicenseVerifier":
        with open(filepath, "rb") as f:
            return cls(f.read())

    def verify_bytes(self, data: bytes, signature_b64: str) -> bool:
        """Verifies raw bytes against a base64 encoded signature."""
        try:
            sig = base64.b64decode(signature_b64)
            self.public_key.verify(sig, data)
            return True
        except (InvalidSignature, Exception):
            return False

    def verify_payload(self, payload: Dict[str, Any], signature_b64: str) -> bool:
        """Verifies canonical JSON dictionary against signature."""
        data_bytes = canonical_json_bytes(payload)
        return self.verify_bytes(data_bytes, signature_b64)

    def verify_signed_bundle(self, bundle: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Verifies a signed bundle of format:
        {
            "payload": { ... },
            "signature": "<base64_sig>",
            "algorithm": "Ed25519"
        }
        """
        if not isinstance(bundle, dict):
            return False, {}
        payload = bundle.get("payload")
        signature = bundle.get("signature")
        if payload is None or not signature:
            return False, {}
        is_valid = self.verify_payload(payload, signature)
        return is_valid, payload if is_valid else {}
