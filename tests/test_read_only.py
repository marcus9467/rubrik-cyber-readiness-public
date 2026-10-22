"""The toolkit must be strictly read-only. Fail if any GraphQL operation in the shipped code is not a query."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = [*ROOT.glob("*.py"), *ROOT.glob("collectors/*.py"), ROOT / "Invoke-CyberReadiness.ps1"]
# A real GraphQL operation: the keyword followed by an optional name and an opening ( or {. A response field
# such as subscriptionType { ... } has no space before the brace and no preceding quote or line start.
OP = re.compile(r'(?:^|[\"\'\s])(?:mutation|subscription)(?:\s+\w+)?\s*[({]')


def test_no_mutation_or_subscription_in_shipped_code():
    bad = []
    for f in FILES:
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            if line.lstrip().startswith(("#", "//")):
                continue
            if OP.search(line):
                bad.append(f"{f.name}:{n}: {line.strip()[:80]}")
    assert not bad, bad


def test_every_collector_query_starts_with_query():
    for f in [*ROOT.glob("collectors/*.py")]:
        text = f.read_text()
        for m in re.finditer(r'"""\s*(\w+)', text):
            if m.group(1) in ("query", "mutation", "subscription"):
                assert m.group(1) == "query", (f.name, m.group(1))
