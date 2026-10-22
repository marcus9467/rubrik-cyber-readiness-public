"""Compare two bundles from the same customer: what was fixed, what is new, what is still open.

Both bundles are scored with the CURRENT rules, so a rule change between runs cannot masquerade as progress.

A finding can vanish because it was fixed, or because its data was not collected the second time (a denied
query, a collector that did not exist yet). Only the first is progress. So findings are compared only inside
domains that were assessed in BOTH bundles; everything else is reported as not comparable.
"""
import json
import re
import sys

from posture import domain_rows, overall
from score import SEVERITY_ORDER, score


def _prep(bundle):
    result = score(bundle)
    rows = domain_rows(result, bundle["data"])
    return {
        "customer": bundle["customer"],
        "collected_at": bundle["collected_at"],
        "findings": {f["id"]: f for f in result["findings"]},
        "domains": dict(rows),
        "overall": overall(rows),
    }


def _avg(domains, names):
    vals = [domains[d] for d in names]
    return round(sum(vals) / len(vals)) if vals else None


def changed_numbers(x, y):
    """Numbers in two evidence strings that differ, as 'before -> after' pairs."""
    nx, ny = re.findall(r"\d[\d,]*", x), re.findall(r"\d[\d,]*", y)
    if len(nx) != len(ny):
        return [("text changed", "")]
    return [(p, q) for p, q in zip(nx, ny) if p != q]


def describe_change(x, y, limit=3):
    """'Title: 55 to 56, ...' for a still-open finding whose numbers moved. Caps the pairs shown."""
    pairs = changed_numbers(x["evidence"], y["evidence"])
    shown = [f"{a} to {b}" if b else a for a, b in pairs[:limit]]
    more = f" (+{len(pairs) - limit} more)" if len(pairs) > limit else ""
    return f"{x['title']}: " + ", ".join(shown) + more


def _sev(f):
    return SEVERITY_ORDER.index(f["severity"])


def compute(before, after):
    b, a = _prep(before), _prep(after)
    both = [d for d in b["domains"] if b["domains"][d] is not None and a["domains"].get(d) is not None]
    not_comparable = [d for d in b["domains"] if d not in both]

    in_scope = lambda f: f["domain"] in both
    bf = {k: f for k, f in b["findings"].items() if in_scope(f)}
    af = {k: f for k, f in a["findings"].items() if in_scope(f)}

    resolved = [bf[k] for k in bf if k not in af]
    new = [af[k] for k in af if k not in bf]
    persisting = [k for k in bf if k in af]
    improved = [(bf[k], af[k]) for k in persisting if _sev(af[k]) > _sev(bf[k])]
    worse = [(bf[k], af[k]) for k in persisting if _sev(af[k]) < _sev(bf[k])]
    same = [(bf[k], af[k]) for k in persisting if _sev(af[k]) == _sev(bf[k])]
    # Same severity but different evidence usually means the count moved; show it rather than hide it.
    moved = [(x, y) for x, y in same if x["evidence"] != y["evidence"]]

    by_sev = lambda fs: sorted(fs, key=lambda f: (_sev(f), f["id"]))
    return {
        "customer": a["customer"],
        "before_at": b["collected_at"], "after_at": a["collected_at"],
        # Like for like: averaged over the domains assessed in both runs only.
        "overall": {"before": _avg(b["domains"], both), "after": _avg(a["domains"], both)},
        "overall_each": {"before": b["overall"], "after": a["overall"]},
        "domains": {d: {"before": b["domains"][d], "after": a["domains"][d]} for d in both},
        "not_comparable": not_comparable,
        "resolved": by_sev(resolved), "new": by_sev(new),
        "improved": improved, "worse": worse, "moved": moved,
        "unchanged": len(same) - len(moved),
    }


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: python3 delta.py BEFORE_bundle.json AFTER_bundle.json")
    d = compute(json.load(open(sys.argv[1])), json.load(open(sys.argv[2])))
    o = d["overall"]
    print(f"{d['customer']}: {d['before_at'][:10]} -> {d['after_at'][:10]}  overall {o['before']} -> {o['after']} (like for like)")
    for key in ("resolved", "new"):
        for f in d[key]:
            print(f"  {key:9} {f['severity']:8} {f['id']:5} {f['title']}")
    for key in ("improved", "worse"):
        for x, y in d[key]:
            print(f"  {key:9} {x['id']:5} {x['severity']} -> {y['severity']}")
    for x, y in d["moved"]:
        print(f"  moved     {x['id']:5} {describe_change(x, y)}")
    if d["not_comparable"]:
        print("  not comparable (not assessed in both runs):", ", ".join(d["not_comparable"]))


if __name__ == "__main__":
    main()
