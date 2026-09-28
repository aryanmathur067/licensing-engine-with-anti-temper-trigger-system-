"""
Command Line Interface for Cruxx LicenseGuard Administration & Edge Operations
"""

import argparse
import json
import os
import sys
from .constants import (
    DEFAULT_LOCKOUT_FILE,
    DEFAULT_MANIFEST_FILE,
    DEFAULT_LICENSE_FILE,
    DEFAULT_PUBLIC_KEY_FILE,
    DEFAULT_PRIVATE_KEY_FILE,
    TIER_DEFENSE,
    KNOWN_MODULES,
)
from .crypto.signer import KeyPairGenerator, LicenseSigner
from .crypto.verifier import LicenseVerifier
from .guard.integrity_verifier import CodeIntegrityVerifier
from .guard.lockout_circuit_breaker import LockoutCircuitBreaker
from .hardware.fingerprint import HardwareFingerprint
from .licensing.schema import LicenseSchema
from .engine import CORTALicenseGuard


def cmd_keygen(args):
    priv_path, pub_path = KeyPairGenerator.save_keypair(
        out_dir=args.out_dir,
        private_filename=args.priv_name or DEFAULT_PRIVATE_KEY_FILE,
        public_filename=args.pub_name or DEFAULT_PUBLIC_KEY_FILE,
    )
    print(f"[+] Successfully generated Cruxx Ed25519 Master Keypair:")
    print(f"    Private Key (KEEP CONFIDENTIAL AT HQ): {priv_path}")
    print(f"    Public Key (Embed on Drones & GCS):     {pub_path}")


def cmd_hwid(args):
    hwid = HardwareFingerprint.get_fingerprint()
    print(f"[+] Device Hardware ID: {hwid}")
    if args.verbose:
        attrs = HardwareFingerprint.get_raw_attributes()
        print("[-] Hardware Attributes:")
        for k, v in attrs.items():
            print(f"    {k}: {v}")


def cmd_issue(args):
    if not os.path.exists(args.private_key):
        print(f"[!] Error: Private key file not found: {args.private_key}")
        sys.exit(1)

    features = [f.strip() for f in args.features.split(",") if f.strip()] if args.features else KNOWN_MODULES
    payload = LicenseSchema.create_payload(
        customer_id=args.customer,
        tier=args.tier,
        hardware_id=args.hwid,
        allowed_features=features,
        days_valid=args.days,
        max_fleet_size=args.fleet_size,
    )

    signer = LicenseSigner.from_file(args.private_key)
    bundle = signer.sign_payload(payload)

    out_path = args.output or DEFAULT_LICENSE_FILE
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    print(f"[+] Successfully generated signed license for '{args.customer}':")
    print(f"    File:       {out_path}")
    print(f"    Tier:       {args.tier}")
    print(f"    Hardware:   {args.hwid}")
    print(f"    Features:   {', '.join(payload['allowed_features'])}")
    print(f"    Expires:    {payload['valid_until']}")


def cmd_manifest_create(args):
    if not os.path.exists(args.private_key):
        print(f"[!] Error: Private key file not found: {args.private_key}")
        sys.exit(1)

    signer = LicenseSigner.from_file(args.private_key)
    target_dir = args.dir or "."
    out_path = args.output or DEFAULT_MANIFEST_FILE

    print(f"[*] Scanning codebase directory: {os.path.abspath(target_dir)} ...")
    bundle = CodeIntegrityVerifier.create_signed_manifest(
        root_dir=target_dir,
        signer=signer,
        version=args.manifest_version or "1.0.0",
    )

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    payload = bundle["payload"]
    print(f"[+] Successfully generated signed Codebase Integrity Manifest:")
    print(f"    File:          {out_path}")
    print(f"    Files Tracked: {payload['file_count']}")
    print(f"    Root SHA-256:  {payload['root_sha256']}")


def cmd_verify(args):
    print("[*] Initializing CORTA LicenseGuard security check...")
    try:
        guard = CORTALicenseGuard(
            public_key_pem_or_path=args.public_key,
            codebase_root_dir=args.dir or ".",
            manifest_path=args.manifest,
            license_path=args.license,
            auto_lockout_on_tamper=not args.no_lockout,
            strict_untracked_files=args.strict,
        )
        res = guard.verify_all()
        print("[+] SUCCESS: System is healthy, licensed, and unmodified!")
        print(f"    Hardware ID: {res['hardware_id']}")
        if res.get("license"):
            print(f"    Customer:    {res['license'].get('customer_id')}")
            print(f"    Tier:        {res['license'].get('tier')}")
            print(f"    Features:    {', '.join(res['license'].get('allowed_features', []))}")
    except Exception as e:
        print(f"[!] SECURITY ALERT / VERIFICATION FAILED: {e}")
        sys.exit(1)


def cmd_status(args):
    cb = LockoutCircuitBreaker(args.lockout_file or DEFAULT_LOCKOUT_FILE)
    is_locked, lock_data = cb.is_locked_out()
    hwid = HardwareFingerprint.get_fingerprint()

    print(f"[-] Device HWID: {hwid}")
    if is_locked:
        print("[!] STATUS: *** SYSTEM LOCKED OUT (TAMPER DETECTED) ***")
        print(f"    Reason Code: {lock_data.get('reason_code') or lock_data.get('reason')}")
        print(f"    Timestamp:   {lock_data.get('timestamp')}")
        print(f"    Nonce:       {lock_data.get('incident_nonce')}")
        print(f"    Details:     {json.dumps(lock_data.get('details', {}))}")
    else:
        print("[+] STATUS: Normal Operation (No Lockout Tripped)")


def cmd_unlock_challenge(args):
    cb = LockoutCircuitBreaker(args.lockout_file or DEFAULT_LOCKOUT_FILE)
    try:
        challenge = cb.generate_unlock_challenge()
        out_file = args.output or "unlock_challenge.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(challenge, f, indent=2)
        print(f"[+] Unlock Challenge generated: {out_file}")
        print("[-] Send this file to Cruxx Support Authority to obtain an authorized unlock token.")
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


def cmd_unlock_resolve(args):
    if not os.path.exists(args.private_key):
        print(f"[!] Error: Private key file not found: {args.private_key}")
        sys.exit(1)

    with open(args.challenge_file, "r", encoding="utf-8") as f:
        challenge = json.load(f)

    signer = LicenseSigner.from_file(args.private_key)
    token = signer.sign_unlock_challenge(challenge)

    out_file = args.output or "unlock_token.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(token, f, indent=2)
    print(f"[+] Cruxx HQ Master Unlock Token generated: {out_file}")


def cmd_unlock_apply(args):
    verifier = LicenseVerifier.from_file(args.public_key)
    with open(args.token_file, "r", encoding="utf-8") as f:
        token_bundle = json.load(f)

    cb = LockoutCircuitBreaker(args.lockout_file or DEFAULT_LOCKOUT_FILE)
    try:
        cb.apply_unlock_token(token_bundle, verifier)
        print("[+] SUCCESS: Lockout cleared! System is restored to operational state.")
    except Exception as e:
        print(f"[!] Unlock rejected: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Cruxx CORTA-LicenseGuard Engine CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_keygen = subparsers.add_parser("keygen", help="Generate Cruxx Master Ed25519 Keypair")
    p_keygen.add_argument("--out-dir", default=".", help="Output directory")
    p_keygen.add_argument("--priv-name", help="Private key file name")
    p_keygen.add_argument("--pub-name", help="Public key file name")
    p_keygen.set_defaults(func=cmd_keygen)

    p_hwid = subparsers.add_parser("hwid", help="Get Current Hardware Identifier")
    p_hwid.add_argument("-v", "--verbose", action="store_true", help="Show raw hardware attributes")
    p_hwid.set_defaults(func=cmd_hwid)

    p_issue = subparsers.add_parser("issue", help="Issue a signed Cruxx License")
    p_issue.add_argument("--private-key", required=True, help="Path to Master Private Key PEM")
    p_issue.add_argument("--customer", required=True, help="Customer / Organization Name")
    p_issue.add_argument("--tier", default=TIER_DEFENSE, help="Product Tier (e.g. DEFENSE_TACTICAL, COMMERCIAL_ENTERPRISE)")
    p_issue.add_argument("--hwid", default="*", help="Target Hardware ID or '*' for unbound")
    p_issue.add_argument("--features", help="Comma-separated allowed features list")
    p_issue.add_argument("--days", type=int, default=365, help="Validity in days")
    p_issue.add_argument("--fleet-size", type=int, default=1, help="Max fleet size")
    p_issue.add_argument("--output", "-o", help="Output .lic path")
    p_issue.set_defaults(func=cmd_issue)

    p_mani = subparsers.add_parser("manifest-create", help="Create signed Codebase Integrity Manifest")
    p_mani.add_argument("--private-key", required=True, help="Path to Master Private Key PEM")
    p_mani.add_argument("--dir", default=".", help="Target codebase directory to scan")
    p_mani.add_argument("--manifest-version", help="Manifest version tag")
    p_mani.add_argument("--output", "-o", help="Output manifest path")
    p_mani.set_defaults(func=cmd_manifest_create)

    p_verify = subparsers.add_parser("verify", help="Verify License & Code Integrity")
    p_verify.add_argument("--public-key", required=True, help="Cruxx Public Key PEM")
    p_verify.add_argument("--license", help="Path to .lic file")
    p_verify.add_argument("--manifest", help="Path to manifest.json file")
    p_verify.add_argument("--dir", default=".", help="Codebase directory to verify")
    p_verify.add_argument("--strict", action="store_true", help="Strict untracked files check")
    p_verify.add_argument("--no-lockout", action="store_true", help="Do not trigger hard lockout file on failure")
    p_verify.set_defaults(func=cmd_verify)

    p_status = subparsers.add_parser("status", help="Check Lockout Status")
    p_status.add_argument("--lockout-file", help="Path to lockout file")
    p_status.set_defaults(func=cmd_status)

    p_uchal = subparsers.add_parser("unlock-challenge", help="Generate Challenge to request unlock from Cruxx")
    p_uchal.add_argument("--lockout-file", help="Path to lockout file")
    p_uchal.add_argument("--output", "-o", help="Output challenge JSON")
    p_uchal.set_defaults(func=cmd_unlock_challenge)

    p_ures = subparsers.add_parser("unlock-resolve", help="Cruxx HQ command to sign an unlock challenge")
    p_ures.add_argument("--private-key", required=True, help="Path to Master Private Key")
    p_ures.add_argument("--challenge-file", required=True, help="Input challenge JSON")
    p_ures.add_argument("--output", "-o", help="Output recovery token JSON")
    p_ures.set_defaults(func=cmd_unlock_resolve)

    p_uapp = subparsers.add_parser("unlock-apply", help="Apply Recovery Token to clear lockout")
    p_uapp.add_argument("--public-key", required=True, help="Path to Public Key")
    p_uapp.add_argument("--token-file", required=True, help="Path to Recovery Token JSON")
    p_uapp.add_argument("--lockout-file", help="Path to lockout file")
    p_uapp.set_defaults(func=cmd_unlock_apply)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
