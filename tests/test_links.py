"""Remediation doc links must resolve. Needs network and certifi, so it skips (passes) when either is
missing; run it deliberately before delivering a report: python3 tests/test_links.py
"""
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from remediation import REMEDIATION  # noqa: E402


def all_urls():
    return sorted({u for v in REMEDIATION.values() for _, u in v["docs"]})


def check(url, ctx):
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}),
                                   timeout=20, context=ctx)
        return r.status if r.geturl() == url else f"redirected to {r.geturl()}"
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:  # network down, DNS, TLS
        return f"unreachable: {type(e).__name__}"


def test_every_doc_link_resolves():
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        print("skip: certifi not installed")
        return
    results = {u: check(u, ctx) for u in all_urls()}
    if all(isinstance(r, str) and r.startswith("unreachable") for r in results.values()):
        print("skip: network unreachable")
        return
    bad = {u: r for u, r in results.items() if r != 200}
    assert not bad, bad


def test_every_link_is_https_docs_rubrik_com():
    assert all(u.startswith("https://docs.rubrik.com/") for u in all_urls())


def test_every_finding_rule_has_steps():
    # Rule ids that score.py can emit; a missing entry would render a finding with no remediation.
    emitted = {"ID-1", "ID-2", "ID-3", "ID-4", "MFA-1", "MFA-2", "Q-1", "Q-2", "R-1", "R-2", "R-3", "A-1",
               "A-2", "A-3", "A-4", "S-1", "S-2", "C-1", "C-2", "C-3", "CL-1", "CL-2", "CL-3", "T-1", "T-2"}
    assert emitted <= set(REMEDIATION), emitted - set(REMEDIATION)
    assert all(REMEDIATION[i]["steps"] for i in emitted)


if __name__ == "__main__":
    test_every_link_is_https_docs_rubrik_com()
    test_every_finding_rule_has_steps()
    test_every_doc_link_resolves()
    print("links ok")
