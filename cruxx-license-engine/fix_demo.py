from pathlib import Path

base = Path(r"C:\Users\aryan mathur\.gemini\antigravity\scratch\cruxx-license-engine")
ex_file = base / "examples" / "corta_drone_demo.py"

content = r"""'''
Interactive End-to-End Demonstration of Cruxx CORTA OS Licensing & Anti-Tamper Engine
'''

import json
import os
import shutil
import tempfile
from cruxx_license.crypto.signer import KeyPairGenerator, LicenseSigner
from cruxx_license.hardware.fingerprint import HardwareFingerprint
from cruxx_license.licensing.schema import LicenseSchema
from cruxx_license.guard.integrity_verifier import CodeIntegrityVerifier
from cruxx_license.engine import CORTALicenseGuard, require_feature
from cruxx_license.guard.lockout_circuit_breaker import (
    CruxxTamperLockoutError,
    CruxxLicenseInvalidError,
)
from cruxx_license.constants import TIER_DEFENSE


def run_demo():
    print("=================================================================")
    print("     CRUXX SOLUTIONS - CORTA OS LICENSING & ANTI-TAMPER DEMO     ")
    print("=================================================================")

    temp_workspace = tempfile.mkdtemp(prefix="cruxx_demo_")
    try:
        keys_dir = os.path.join(temp_workspace, "keys")
        corta_modules_dir = os.path.join(temp_workspace, "corta_modules")
        os.makedirs(keys_dir, exist_ok=True)
        os.makedirs(corta_modules_dir, exist_ok=True)

        print("\n[Step 1] Cruxx HQ: Generating Master Ed25519 Signing Keys...")
        priv_path, pub_path = KeyPairGenerator.save_keypair(keys_dir)
        signer = LicenseSigner.from_file(priv_path)
        print(f"  -> Private Key (Confidential): {priv_path}")
        print(f"  -> Public Key (Embedded):      {pub_path}")

        print("\n[Step 2] Edge Drone: Gathering Hardware Fingerprint...")
        hwid = HardwareFingerprint.get_fingerprint()
        print(f"  -> Detected Drone/Edge HWID: {hwid}")

        print("\n[Step 3] Cruxx HQ: Issuing Cryptographically Signed License...")
        lic_payload = LicenseSchema.create_payload(
            customer_id="Strategic_Border_Command_Unit_7",
            tier=TIER_DEFENSE,
            hardware_id=hwid,
            allowed_features=["corta_core", "edge_ai_vision", "bvlos_comms", "anti_jam_protocol"],
            days_valid=365,
            max_fleet_size=12,
        )
        lic_bundle = signer.sign_payload(lic_payload)
        lic_path = os.path.join(temp_workspace, "corta.lic")
        with open(lic_path, "w", encoding="utf-8") as f:
            json.dump(lic_bundle, f, indent=2)
        print(f"  -> Signed License saved to: {lic_path}")
        print(f"  -> Allowed Modules: {', '.join(lic_payload['allowed_features'])}")

        print("\n[Step 4] Deployment: Creating CORTA OS Flight Code & Integrity Manifest...")
        flight_file = os.path.join(corta_modules_dir, "autonomous_flight.py")
        ai_file = os.path.join(corta_modules_dir, "edge_vision.py")
        with open(flight_file, "w") as f:
            f.write("# Cruxx CORTA OS Flight Control Matrix\ndef get_flight_plan(): return {'mode': 'AUTONOMOUS_TACTICAL', 'status': 'STABLE'}\n")
        with open(ai_file, "w") as f:
            f.write("# Cruxx Edge AI Perception Engine\ndef scan_perimeter(): return {'target_detected': False, 'confidence': 0.99}\n")

        manifest_bundle = CodeIntegrityVerifier.create_signed_manifest(
            root_dir=corta_modules_dir,
            signer=signer,
            version="1.0.0-PROD",
        )
        mani_path = os.path.join(temp_workspace, "corta_manifest.json")
        with open(mani_path, "w", encoding="utf-8") as f:
            json.dump(manifest_bundle, f, indent=2)
        print(f"  -> Signed Code Integrity Manifest created at: {mani_path}")
        print(f"  -> Tracked files root SHA-256: {manifest_bundle['payload']['root_sha256']}")

        print("\n[Step 5] Initializing CORTA-LicenseGuard on Drone Hardware...")
        lockout_path = os.path.join(temp_workspace, ".corta_lockout.bin")
        guard = CORTALicenseGuard(
            public_key_pem_or_path=pub_path,
            codebase_root_dir=corta_modules_dir,
            manifest_path=mani_path,
            license_path=lic_path,
            lockout_file_path=lockout_path,
            auto_lockout_on_tamper=True,
        )
        health = guard.verify_all()
        print(f"  -> System Status: {health['status']} | Hardware Verified: {health['hardware_id']}")

        # Guarded Service Functions
        @require_feature("corta_core")
        def execute_autonomous_flight():
            return ">> [CORTA OS] Autonomous flight vector active. BVLOS link connected."

        @require_feature("edge_ai_vision")
        def execute_ai_recon():
            return ">> [EDGE AI] AI Perception running locally on edge neural processor."

        @require_feature("unlicensed_hypersonic_boost")
        def execute_unlicensed_feature():
            return ">> [ERROR] Should not run."

        print("\n[Step 6] Testing Authorized Service Invocations:")
        print(" ", execute_autonomous_flight())
        print(" ", execute_ai_recon())

        print("\n[Step 7] Testing Unlicensed Feature Access:")
        try:
            execute_unlicensed_feature()
        except CruxxLicenseInvalidError as e:
            print(f"  -> Successfully BLOCKED unauthorized feature: {e}")

        print("\n[Step 8] SIMULATING ADVERSARY TAMPERING ATTACK...")
        print("  -> An attacker attempts to inject reverse-engineered bytecode into autonomous_flight.py...")
        with open(flight_file, "a") as f:
            f.write("\n# MALICIOUS INJECTION: bypass_safety_limits = True\n")
        print("  -> Malicious modification made to source file.")

        print("\n[Step 9] Executing Next Operational Call (Integrity Tripwire Trigger)...")
        try:
            execute_autonomous_flight()
        except CruxxTamperLockoutError as e:
            print("  -> !!! TAMPER TRIPWIRE FIRED IMMEDIATELY !!!")
            print(f"  -> {e}")

        print("\n[Step 10] Testing System State Post-Tamper:")
        is_locked, lock_data = guard.circuit_breaker.is_locked_out()
        print(f"  -> Is Drone Locked Out? {is_locked}")
        print(f"  -> Reason: {lock_data.get('reason_code')}")
        print(f"  -> Persistent Lockout Tripwire File exists? {os.path.exists(lockout_path)}")

        print("\n[Step 11] Testing Subsequent Invocations (Fail-Secure Lockdown)...")
        try:
            execute_autonomous_flight()
        except CruxxTamperLockoutError:
            print("  -> All services permanently refusing execution. Hardware is locked.")

        print("\n[Step 12] Authorized Recovery Process (Challenge-Response Protocol)...")
        challenge = guard.circuit_breaker.generate_unlock_challenge()
        print(f"  -> Generated Recovery Challenge Nonce: {challenge['challenge_nonce']}")

        # Cruxx HQ verifies incident, clears the tampered file, and signs unlock token
        with open(flight_file, "w") as f:
            f.write("# Cruxx CORTA OS Flight Control Matrix\ndef get_flight_plan(): return {'mode': 'AUTONOMOUS_TACTICAL', 'status': 'STABLE'}\n")

        unlock_token = signer.sign_unlock_challenge(challenge)
        print("  -> Cruxx Master HQ validated incident and signed cryptographic Unlock Token.")

        guard.circuit_breaker.apply_unlock_token(unlock_token, guard.verifier)
        print("  -> Unlock Token applied. System restored to operational mode.")

        print("\n[Step 13] Verifying Restored Execution:")
        print(" ", execute_autonomous_flight())

        print("\n=================================================================")
        print("       DEMO COMPLETED: ALL SECURITY OBJECTIVES VERIFIED          ")
        print("=================================================================")

    finally:
        shutil.rmtree(temp_workspace, ignore_errors=True)


if __name__ == "__main__":
    run_demo()
"""

ex_file.write_text(content.strip(), encoding="utf-8")
print("Rewritten corta_drone_demo.py successfully.")
