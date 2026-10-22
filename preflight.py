"""Check what a service account can actually read, before a full collection.

Usage: python3 preflight.py --sa ~/.rubrik/<instance>.json

Runs every collector and prints one line per collector and per sub-section that failed, so a role that
is missing a permission shows up as a named gap instead of a silently empty report.
Exit code 0 if everything collected, 1 if anything was denied or failed.
"""
import argparse
import sys

from collect import COLLECTORS
from rsc_client import RscClient


def failures(node, path=""):
    """Yield (path, message) for every error stub in a collected section."""
    if isinstance(node, dict):
        if "error" in node:
            yield path or "(root)", str(node["error"])
            return
        for k, v in node.items():
            yield from failures(v, f"{path}.{k}" if path else k)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sa", required=True)
    args = ap.parse_args()
    client = RscClient(args.sa)
    print(f"authenticated to {client.gql_url.split('/api')[0]}")
    bad = 0
    for name, mod in COLLECTORS.items():
        try:
            data = mod.collect(client)
        except Exception as e:
            bad += 1
            print(f"FAIL  {name}: {str(e)[:140]}")
            continue
        sub = list(failures(data))
        if sub:
            bad += len(sub)
            for path, msg in sub:
                print(f"FAIL  {name}.{path}: {msg[:140]}")
        else:
            print(f"ok    {name}")
    print("all collectors can read" if not bad else f"{bad} problem(s): grant the missing view permissions or "
          "expect those areas to be reported as not assessed")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
