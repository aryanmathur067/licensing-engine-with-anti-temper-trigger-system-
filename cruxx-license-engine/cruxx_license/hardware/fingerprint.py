"""
Cross-Platform Hardware Fingerprinting & Machine Binding for Cruxx Systems
"""

import hashlib
import platform
import subprocess
import uuid
from typing import Dict, Optional


class HardwareFingerprint:
    """
    Extracts hardware identities (UUID, CPU ID, Baseboard, MAC) to generate
    a deterministic, hardware-locked device identifier.
    """

    @staticmethod
    def get_raw_attributes() -> Dict[str, str]:
        system = platform.system().lower()
        attrs = {
            "os": system,
            "machine": platform.machine(),
            "node": platform.node(),
            "mac": hex(uuid.getnode()),
        }

        if system == "windows":
            try:
                # Get Computer System Product UUID
                cmd = 'powershell -NoProfile -Command "(Get-CimInstance Win32_ComputerSystemProduct).UUID"'
                res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)
                if res.returncode == 0 and res.stdout.strip():
                    attrs["system_uuid"] = res.stdout.strip()
            except Exception:
                pass

            try:
                # Get Processor ID
                cmd = 'powershell -NoProfile -Command "(Get-CimInstance Win32_Processor).ProcessorId"'
                res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)
                if res.returncode == 0 and res.stdout.strip():
                    attrs["processor_id"] = res.stdout.strip()
            except Exception:
                pass

            try:
                # Get BaseBoard Serial
                cmd = 'powershell -NoProfile -Command "(Get-CimInstance Win32_BaseBoard).SerialNumber"'
                res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=5)
                if res.returncode == 0 and res.stdout.strip():
                    attrs["baseboard_serial"] = res.stdout.strip()
            except Exception:
                pass

        elif system == "linux":
            # Check /etc/machine-id
            for path, key in [
                ("/etc/machine-id", "machine_id"),
                ("/var/lib/dbus/machine-id", "dbus_id"),
                ("/sys/class/dmi/id/product_uuid", "product_uuid"),
            ]:
                try:
                    with open(path, "r") as f:
                        attrs[key] = f.read().strip()
                except Exception:
                    pass

        return attrs

    @classmethod
    def get_fingerprint(cls, salt: str = "CRUXX_DEFENSE_SALT_2026") -> str:
        """
        Generates a formatted hardware fingerprint: CRUXX-HW-XXXX-XXXX-XXXX-XXXX
        """
        attrs = cls.get_raw_attributes()
        # Sort items deterministically
        raw_str = "|".join(f"{k}:{v}" for k, v in sorted(attrs.items())) + f"|salt:{salt}"
        digest = hashlib.sha256(raw_str.encode("utf-8")).hexdigest().upper()
        # Format into 4 segments of 4 chars
        parts = [digest[i:i+4] for i in range(0, 16, 4)]
        return f"CRUXX-HW-{'-'.join(parts)}"

    @classmethod
    def matches(cls, target_hwid: str, current_hwid: Optional[str] = None) -> bool:
        """
        Validates if target_hwid matches current hardware.
        Supports wildcard 'CRUXX-HW-UNBOUND-ANY' or '*' for lab/demo deployments.
        """
        if not target_hwid or target_hwid == "CRUXX-HW-UNBOUND-ANY" or target_hwid == "*":
            return True
        if current_hwid is None:
            current_hwid = cls.get_fingerprint()
        return target_hwid.strip().upper() == current_hwid.strip().upper()
