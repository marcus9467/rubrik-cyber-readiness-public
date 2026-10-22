"""Run all collectors and write bundle.json. One collector failing never stops the run.

Usage: python3 collect.py --sa ~/.rubrik/<instance>.json --customer LAB
"""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

from rsc_client import RscClient
from collectors import access, clusters, detection, dhrc, identity, inventory, mfa, offsite, quorum, recovery, sla, threat

COLLECTORS = {
    "identity": identity, "mfa": mfa, "quorum": quorum,
    "inventory": inventory, "dhrc": dhrc, "sla": sla, "access": access,
    "clusters": clusters, "threat": threat, "detection": detection, "recovery": recovery,
    "offsite": offsite,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sa", required=True)
    ap.add_argument("--customer", required=True)
    ap.add_argument("--out", default="~/.local/share/cyber-readiness")
    ap.add_argument("--redact", action="store_true",
                    help="also write bundle.redacted.json (safe to send) and redaction-map.json (keep)")
    args = ap.parse_args()

    client = RscClient(args.sa)
    bundle = {
        "customer": args.customer,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "status": {},
        "data": {},
    }
    for name, mod in COLLECTORS.items():
        try:
            bundle["data"][name] = mod.collect(client)
            bundle["status"][name] = "ok"
        except Exception as e:  # record and continue
            bundle["status"][name] = f"error: {str(e)[:300]}"
        print(f"{name}: {bundle['status'][name]}")

    out = Path(args.out).expanduser() / args.customer
    out.mkdir(parents=True, exist_ok=True)
    path = out / "bundle.json"
    path.write_text(json.dumps(bundle, indent=2))
    print(f"wrote {path}")
    if args.redact:
        from redact import redact_bundle
        redacted, mapping = redact_bundle(bundle)
        (out / "bundle.redacted.json").write_text(json.dumps(redacted, indent=2))
        (out / "redaction-map.json").write_text(json.dumps(mapping, indent=2))
        print(f"wrote {out / 'bundle.redacted.json'} (send this one)")
        print(f"wrote {out / 'redaction-map.json'} (keep this one, do not send)")


if __name__ == "__main__":
    main()
