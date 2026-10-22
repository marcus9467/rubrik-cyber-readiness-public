"""Compare two bundles from the Python and PowerShell collectors.

Usage: python3 tests/compare_bundles.py A.json B.json [--mask] [--unordered]
--mask replaces `<kind>-<8 hex>` pseudonyms with `<kind>-*` first, because each run uses a random salt.
--unordered sorts lists and ignores lastLogin / lastConnectionTime, for comparing two live-tenant runs.
Ignores `customer` and `collected_at`. Prints each difference as a path, exits 1 if any.
"""
import json
import re
import sys

PSEUDO = re.compile(
    r"\b(user|email|svc|client|role|group|idp|ip|org|policy|sla|cluster|obj|loc|acct|archive|plan)-[0-9a-f]{8}\b")


def mask(node):
    if isinstance(node, str):
        return PSEUDO.sub(r"\1-*", node)
    if isinstance(node, list):
        return [mask(x) for x in node]
    if isinstance(node, dict):
        return {mask(k): mask(v) for k, v in node.items()}
    return node


VOLATILE = {"lastLogin", "lastConnectionTime"}


def unordered(node):
    """Sort every list canonically and drop volatile timestamps. A live RSC returns role, objectType and
    platform lists in a different order on each call (Python vs Python differs the same way), so order is
    not evidence of a port bug. Use only for live data; the mock comparison stays order-sensitive."""
    if isinstance(node, list):
        return sorted((unordered(x) for x in node), key=lambda x: json.dumps(x, sort_keys=True))
    if isinstance(node, dict):
        return {k: unordered(v) for k, v in node.items() if k not in VOLATILE}
    return node


def diff(a, b, path=""):
    if isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool) \
            and not isinstance(b, bool) and a == b:
        return  # 50 vs 50.0: the same number
    if type(a) is not type(b):
        yield f"{path}: type {type(a).__name__} vs {type(b).__name__}  ({str(a)[:50]!r} vs {str(b)[:50]!r})"
    elif isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                yield f"{path}.{k}: only in B"
            elif k not in b:
                yield f"{path}.{k}: only in A"
            else:
                yield from diff(a[k], b[k], f"{path}.{k}")
    elif isinstance(a, list):
        if len(a) != len(b):
            yield f"{path}: length {len(a)} vs {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            yield from diff(x, y, f"{path}[{i}]")
    elif path.endswith(".error") and isinstance(a, str) and "".join(a.split()) == "".join(b.split()):
        return  # same message, different JSON spacing (Python json.dumps vs PowerShell ConvertTo-Json)
    elif a != b:
        yield f"{path}: {a!r} vs {b!r}"


def main():
    a, b = (json.load(open(p)) for p in sys.argv[1:3])
    for x in (a, b):
        x.pop("customer", None)
        x.pop("collected_at", None)
    if "--mask" in sys.argv:
        a, b = mask(a), mask(b)
    if "--unordered" in sys.argv:
        a, b = unordered(a), unordered(b)
    out = list(diff(a, b))
    print("\n".join(out) if out else "identical")
    sys.exit(1 if out else 0)


if __name__ == "__main__":
    main()
