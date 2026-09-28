"""
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
