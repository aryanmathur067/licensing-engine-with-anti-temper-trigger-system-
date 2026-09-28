from pathlib import Path

base = Path(r"C:\Users\aryan mathur\.gemini\antigravity\scratch\cruxx-license-engine")
crypto_dir = base / "cruxx_license" / "crypto"

(crypto_dir / "__init__.py").write_text('''from .signer import KeyPairGenerator, LicenseSigner
from .verifier import LicenseVerifier, canonical_json_bytes, compute_sha256

__all__ = [
    "KeyPairGenerator",
    "LicenseSigner",
    "LicenseVerifier",
    "canonical_json_bytes",
    "compute_sha256",
]
''', encoding="utf-8")

(crypto_dir / "verifier.py").write_text('''"""
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
''', encoding="utf-8")

(crypto_dir / "signer.py").write_text('''"""
Master Key Generation and Signing Tools (Cruxx HQ Authority Only)
"""

import base64
import os
from typing import Any, Dict, Tuple, Union
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from .verifier import canonical_json_bytes


class KeyPairGenerator:
    """Generates Ed25519 cryptographic keypairs for Cruxx Licensing."""

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """Returns (private_key_pem, public_key_pem)."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return private_pem, public_pem

    @staticmethod
    def save_keypair(out_dir: str, private_filename: str = "cruxx_private_key.pem", public_filename: str = "cruxx_public_key.pem") -> Tuple[str, str]:
        os.makedirs(out_dir, exist_ok=True)
        priv_pem, pub_pem = KeyPairGenerator.generate_keypair()
        priv_path = os.path.join(out_dir, private_filename)
        pub_path = os.path.join(out_dir, public_filename)
        with open(priv_path, "wb") as f:
            f.write(priv_pem)
        with open(pub_path, "wb") as f:
            f.write(pub_pem)
        return priv_path, pub_path


class LicenseSigner:
    """
    Signs payloads and files using Cruxx Master Private Key.
    """

    def __init__(self, private_key_pem_or_bytes: Union[str, bytes]):
        if isinstance(private_key_pem_or_bytes, str):
            data = private_key_pem_or_bytes.encode("utf-8")
        else:
            data = private_key_pem_or_bytes
        self.private_key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(self.private_key, ed25519.Ed25519PrivateKey):
            raise ValueError("Provided key is not an Ed25519 Private Key")

    @classmethod
    def from_file(cls, filepath: str) -> "LicenseSigner":
        with open(filepath, "rb") as f:
            return cls(f.read())

    def sign_bytes(self, data: bytes) -> str:
        """Returns base64 signature of raw bytes."""
        sig = self.private_key.sign(data)
        return base64.b64encode(sig).decode("utf-8")

    def sign_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Creates a signed bundle."""
        data_bytes = canonical_json_bytes(payload)
        sig_b64 = self.sign_bytes(data_bytes)
        return {
            "payload": payload,
            "signature": sig_b64,
            "algorithm": "Ed25519",
        }

    def sign_unlock_challenge(self, challenge_payload: Dict[str, Any]) -> Dict[str, Any]:
        """Signs an unlock challenge request to produce an authorized unlock token."""
        unlock_payload = {
            "action": "CRUXX_SYSTEM_UNLOCK",
            "challenge_nonce": challenge_payload.get("challenge_nonce"),
            "target_hwid": challenge_payload.get("target_hwid"),
            "issued_timestamp": challenge_payload.get("timestamp"),
            "status": "APPROVED",
        }
        return self.sign_payload(unlock_payload)
''', encoding="utf-8")

print("Part 2 written successfully.")
