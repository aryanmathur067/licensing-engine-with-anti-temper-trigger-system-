"""
SHA-256 Codebase Integrity Verifier & Manifest Signer for CORTA OS Modules
"""

import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Tuple
from ..constants import (
    TAMPER_CODE_FILE_MODIFIED,
    TAMPER_CODE_FILE_MISSING,
    TAMPER_CODE_FILE_UNTRACKED,
    TAMPER_CODE_MANIFEST_INVALID,
)
from ..crypto.verifier import LicenseVerifier, canonical_json_bytes
from ..crypto.signer import LicenseSigner


def calculate_file_sha256(filepath: str) -> str:
    """Calculates SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


class CodeIntegrityVerifier:
    """
    Manages codebase integrity manifests and verifies real-time SHA-256 hashes
    of all source code, binaries, and configurations.
    """

    DEFAULT_IGNORES = [
        "__pycache__",
        ".git",
        ".pytest_cache",
        ".corta_lockout.bin",
        "corta_manifest.json",
        ".DS_Store",
        ".venv",
        "*.pyc",
        "*.pyo",
        "*.pyd",
    ]

    @classmethod
    def should_ignore(cls, filename: str, extra_ignores: Optional[List[str]] = None) -> bool:
        ignores = cls.DEFAULT_IGNORES + (extra_ignores or [])
        for pat in ignores:
            if pat.startswith("*.") and filename.endswith(pat[1:]):
                return True
            if filename == pat or filename.startswith(pat):
                return True
        return False

    @classmethod
    def scan_directory(cls, root_dir: str, extra_ignores: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """
        Scans a directory and maps relative path -> {sha256, size_bytes}.
        """
        file_map = {}
        root_dir = os.path.abspath(root_dir)

        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Prune ignored directories
            dirnames[:] = [d for d in dirnames if not cls.should_ignore(d, extra_ignores)]
            for fname in filenames:
                if cls.should_ignore(fname, extra_ignores):
                    continue
                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, root_dir).replace("\\", "/")
                file_hash = calculate_file_sha256(full_path)
                file_size = os.path.getsize(full_path)
                file_map[rel_path] = {
                    "sha256": file_hash,
                    "size": file_size,
                }
        return file_map

    @classmethod
    def create_signed_manifest(
        cls,
        root_dir: str,
        signer: LicenseSigner,
        version: str = "1.0.0",
        metadata: Optional[Dict[str, Any]] = None,
        extra_ignores: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Generates a digitally signed manifest bundle for a directory.
        """
        files_map = cls.scan_directory(root_dir, extra_ignores)
        # Compute root hash of all files
        combined_str = "".join(f"{k}:{v['sha256']}" for k, v in sorted(files_map.items()))
        root_sha256 = hashlib.sha256(combined_str.encode("utf-8")).hexdigest()

        payload = {
            "version": version,
            "root_sha256": root_sha256,
            "file_count": len(files_map),
            "files": files_map,
            "metadata": metadata or {},
        }
        return signer.sign_payload(payload)

    @classmethod
    def verify_directory_integrity(
        cls,
        root_dir: str,
        manifest_bundle: Dict[str, Any],
        verifier: LicenseVerifier,
        strict_untracked: bool = False,
        extra_ignores: Optional[List[str]] = None,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verifies directory against signed manifest:
        1. Validates manifest signature using Cruxx public key.
        2. Validates SHA-256 for each tracked file.
        3. Checks for missing files or modified content.
        4. Optionally checks for untracked injected code.
        """
        is_valid_sig, payload = verifier.verify_signed_bundle(manifest_bundle)
        if not is_valid_sig:
            return False, TAMPER_CODE_MANIFEST_INVALID, {"reason": "Manifest digital signature verification failed"}

        tracked_files: Dict[str, Dict[str, Any]] = payload.get("files", {})
        root_dir = os.path.abspath(root_dir)

        # 1. Check all tracked files exist and match hashes
        for rel_path, meta in tracked_files.items():
            full_path = os.path.join(root_dir, rel_path.replace("/", os.sep))
            if not os.path.exists(full_path):
                return False, TAMPER_CODE_FILE_MISSING, {
                    "file": rel_path,
                    "expected_hash": meta.get("sha256"),
                }
            current_hash = calculate_file_sha256(full_path)
            if current_hash != meta.get("sha256"):
                return False, TAMPER_CODE_FILE_MODIFIED, {
                    "file": rel_path,
                    "expected_hash": meta.get("sha256"),
                    "actual_hash": current_hash,
                }

        # 2. Check for unauthorized/injected files
        if strict_untracked:
            current_scan = cls.scan_directory(root_dir, extra_ignores)
            for current_rel in current_scan:
                if current_rel not in tracked_files:
                    return False, TAMPER_CODE_FILE_UNTRACKED, {
                        "file": current_rel,
                        "hash": current_scan[current_rel]["sha256"],
                    }

        return True, "OK", {"file_count": len(tracked_files), "root_sha256": payload.get("root_sha256")}
