'''
Instant Tamper Detection, Hardware-Bound Tripwire & Lockdown Engine
'''

import datetime
import hashlib
import json
import os
import secrets
from typing import Any, Dict, Optional, Tuple
from ..constants import DEFAULT_LOCKOUT_FILE
from ..crypto.verifier import LicenseVerifier, canonical_json_bytes
from ..hardware.fingerprint import HardwareFingerprint


class CruxxSecurityException(Exception):
    '''Base exception for Cruxx License & Security Engine'''
    pass


class CruxxTamperLockoutError(CruxxSecurityException):
    '''Raised when the system has been tripped into a tamper lockdown state'''
    pass


class CruxxLicenseInvalidError(CruxxSecurityException):
    '''Raised when a license is invalid or unauthorized'''
    pass


class CruxxIntegrityViolationError(CruxxSecurityException):
    '''Raised when code or binary integrity check fails'''
    pass


class LockoutCircuitBreaker:
    '''
    Fail-Secure Circuit Breaker:
    Upon any detected modification, signature forgery, or tampering:
    1. Hashes tamper incident forensics.
    2. Writes a hardware-locked tamper tripwire file (.corta_lockout.bin).
    3. Traps the system into permanent lockout.
    4. Only permits unlock via authorized Cruxx Master Key Challenge-Response.
    '''

    def __init__(self, lockout_file_path: Optional[str] = None):
        self.lockout_file_path = os.path.abspath(lockout_file_path or DEFAULT_LOCKOUT_FILE)
        self._in_memory_tripped = False
        self._trip_reason: Optional[str] = None
        self._incident_nonce: Optional[str] = None

    def is_locked_out(self) -> Tuple[bool, Optional[Dict[str, Any]]]:
        '''
        Returns (is_locked, lockout_data).
        Checks both in-memory state and persistent on-disk lockout file.
        '''
        if self._in_memory_tripped:
            return True, {
                "reason_code": self._trip_reason or "IN_MEMORY_TRIPPED",
                "reason": self._trip_reason or "IN_MEMORY_TRIPPED",
                "incident_nonce": self._incident_nonce,
            }

        if not os.path.exists(self.lockout_file_path):
            return False, None

        try:
            with open(self.lockout_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            seal = data.get("seal")
            payload = data.get("payload", {})
            computed_seal = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
            if seal != computed_seal:
                return True, {
                    "reason_code": "CORRUPTED_TAMPER_SEAL",
                    "reason": "CORRUPTED_TAMPER_SEAL",
                    "details": "Lockout record modified externally",
                }
            return True, payload
        except Exception:
            return True, {
                "reason_code": "LOCKOUT_FILE_UNREADABLE",
                "reason": "LOCKOUT_FILE_UNREADABLE",
            }

    def trip_lockout(
        self,
        reason_code: str,
        details: Optional[Dict[str, Any]] = None,
        hwid: Optional[str] = None,
    ) -> None:
        '''
        INSTANT LOCKOUT TRIPWIRE:
        Persists tamper state, writes machine-bound forensic lockfile,
        and halts execution.
        '''
        self._in_memory_tripped = True
        self._trip_reason = reason_code
        self._incident_nonce = secrets.token_hex(16)
        hwid = hwid or HardwareFingerprint.get_fingerprint()
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        payload = {
            "status": "SYSTEM_LOCKED_OUT",
            "reason_code": reason_code,
            "timestamp": timestamp,
            "incident_nonce": self._incident_nonce,
            "target_hwid": hwid,
            "details": details or {},
        }
        seal = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
        lockout_record = {
            "payload": payload,
            "seal": seal,
        }

        try:
            lockout_dir = os.path.dirname(self.lockout_file_path)
            if lockout_dir:
                os.makedirs(lockout_dir, exist_ok=True)
            with open(self.lockout_file_path, "w", encoding="utf-8") as f:
                json.dump(lockout_record, f, indent=2)
        except Exception:
            pass

        raise CruxxTamperLockoutError(
            f"CRUXX DEFENSE SECURITY ALERT: SYSTEM LOCKED OUT! Reason: {reason_code}. "
            f"Tamper detected. Hardware ID: {hwid}. Incident nonce: {self._incident_nonce}"
        )

    def generate_unlock_challenge(self) -> Dict[str, Any]:
        '''
        Generates a challenge for Cruxx HQ to authorize an unlock.
        '''
        is_locked, payload = self.is_locked_out()
        if not is_locked or not payload:
            raise CruxxSecurityException("System is not currently locked out.")

        hwid = HardwareFingerprint.get_fingerprint()
        challenge = {
            "type": "CRUXX_UNLOCK_CHALLENGE",
            "challenge_nonce": payload.get("incident_nonce") or secrets.token_hex(16),
            "target_hwid": hwid,
            "lockout_reason": payload.get("reason_code") or payload.get("reason"),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        return challenge

    def apply_unlock_token(
        self,
        unlock_bundle: Dict[str, Any],
        verifier: LicenseVerifier,
    ) -> bool:
        '''
        Validates and applies a Cruxx Master Key signed unlock token to clear lockout.
        '''
        is_valid, payload = verifier.verify_signed_bundle(unlock_bundle)
        if not is_valid:
            raise CruxxSecurityException("Invalid unlock token signature. Recovery rejected.")

        if payload.get("action") != "CRUXX_SYSTEM_UNLOCK" or payload.get("status") != "APPROVED":
            raise CruxxSecurityException("Unauthorized unlock token payload.")

        current_hwid = HardwareFingerprint.get_fingerprint()
        token_hwid = payload.get("target_hwid")
        if not HardwareFingerprint.matches(token_hwid, current_hwid):
            raise CruxxSecurityException(f"Unlock token is bound to {token_hwid}, but system is {current_hwid}")

        if os.path.exists(self.lockout_file_path):
            try:
                os.remove(self.lockout_file_path)
            except Exception:
                with open(self.lockout_file_path, "w") as f:
                    f.write("{}")
                os.remove(self.lockout_file_path)

        self._in_memory_tripped = False
        self._trip_reason = None
        self._incident_nonce = None
        return True