#!/usr/bin/env python3
"""Generate LogPilot license keys.

Usage:
    python scripts/generate_license.py --name "Acme AB" --days 90
    python scripts/generate_license.py --name "BigCorp" --days 365 --tier pro
    python scripts/generate_license.py --name "Acme" --days 90 --providers claude,gemini --models haiku,sonnet
    python scripts/generate_license.py --generate-secret

Requires LOGPILOT_LICENSE_SECRET env var (or --generate-secret to create one).
"""

from __future__ import annotations

import argparse
import os
import sys

# Allow running from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from logpilot.license import generate_token, generate_secret, validate_token


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate LogPilot license keys",
    )
    parser.add_argument("--name", help="Customer/organization name")
    parser.add_argument("--days", type=int, default=90, help="Days until expiry (default: 90)")
    parser.add_argument("--tier", choices=["trial", "pro"], default="trial", help="License tier")
    parser.add_argument(
        "--providers",
        help="Comma-separated allowed providers (default: claude for trial, claude,gemini,openai for pro)",
    )
    parser.add_argument(
        "--models",
        help="Comma-separated allowed models (default: haiku for trial, all for pro)",
    )
    parser.add_argument("--generate-secret", action="store_true",
                        help="Generate a new signing secret and exit")
    args = parser.parse_args()

    if args.generate_secret:
        secret = generate_secret()
        print("\n=== LogPilot License Secret ===")
        print(f"\n  {secret}\n")
        print("Store this in Keeper Security under 'LogPilot License Secret'.")
        print("Then set it as an environment variable before generating licenses:\n")
        print(f"  export LOGPILOT_LICENSE_SECRET=\"{secret}\"\n")
        return

    if not args.name:
        parser.error("--name is required (or use --generate-secret)")

    secret = os.environ.get("LOGPILOT_LICENSE_SECRET")
    if not secret:
        print("ERROR: LOGPILOT_LICENSE_SECRET not set.", file=sys.stderr)
        print("Run with --generate-secret first, then set the env var.", file=sys.stderr)
        sys.exit(1)

    # Parse optional provider/model overrides
    providers = [p.strip() for p in args.providers.split(",")] if args.providers else None
    models = [m.strip() for m in args.models.split(",")] if args.models else None

    token = generate_token(
        args.name, args.days, tier=args.tier, secret=secret,
        providers=providers, models=models,
    )

    # Verify the token we just created
    info = validate_token(token, secret)
    assert info and info.valid, "Generated token failed validation"

    print(f"\n=== LogPilot License Key ===")
    print(f"  Customer:  {info.name}")
    print(f"  Tier:      {info.tier}")
    print(f"  Expires:   in {info.days_left} days")
    print(f"  Providers: {', '.join(info.providers)}")
    print(f"  Models:    {', '.join(info.models)}")
    print(f"\n{token}\n")
    print("Send this key to the customer.")


if __name__ == "__main__":
    main()
