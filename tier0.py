"""Find likely Tier-0 assets among unprotected objects, with an honest confidence label.

Tier-0 here means assets whose loss stops recovery of everything else: identity (AD domain controllers,
AD/Entra Connect, ADFS), the virtualization management plane (vCenter), and core network services (DNS,
DHCP, PKI). RSC does not label criticality, so this is inferred two ways:

  structural  the RSC object type itself says so (for example ACTIVE_DIRECTORY_DOMAIN_CONTROLLER).
              High confidence.
  name        a VM or host name looks like a domain controller, vCenter, PKI or similar. Heuristic:
              it will miss assets with opaque names and can match unrelated ones. Confirm with the customer.

Neither replaces asking the customer what their Tier-0 list is. The report says so.
"""
import re

from collectors.inventory import NONPROD_RE

STRUCTURAL_TYPES = {
    "ACTIVE_DIRECTORY_DOMAIN_CONTROLLER": "Active Directory domain controller",
    "ACTIVE_DIRECTORY_DOMAIN": "Active Directory domain",
    "ACTIVE_DIRECTORY_FOREST": "Active Directory forest",
    "AZURE_AD_DIRECTORY": "Entra ID directory",
    "OKTA_TENANT": "Okta tenant",
    "VSPHERE_VCENTER": "vCenter",
}

# Only VM-like and host-like objects are name-matched; disks, buckets and volume groups are not.
NAME_TYPES = {"VmwareVirtualMachine", "HypervVirtualMachine", "AzureNativeVm", "Ec2Instance",
              "NutanixVirtualMachine", "OPENSTACK_VIRTUAL_MACHINE", "PhysicalHost", "WindowsFileset"}

# Token must stand alone (separators or digits around it), so 'dc01' and 'prod-dc-2' match, 'dcim' does not.
_SEP = r"(?<![a-z])"
_END = r"(?![a-z])"
NAME_PATTERNS = [
    ("Domain controller", re.compile(rf"{_SEP}(dc|pdc|rwdc|rodc)[0-9]*{_END}|domain[-_ ]?controller", re.I)),
    # 'ad' then optional hyphenated words then a number: adds01, ad-restore01, ad-m-child-01. Not 'adobe-01'.
    ("Active Directory", re.compile(
        rf"{_SEP}ad[a-z]*[0-9]+{_END}|{_SEP}ad(?:[-_](?!hoc)[a-z]+)+[-_]?[0-9]+{_END}|{_SEP}adfs{_END}|{_SEP}entra", re.I)),
    ("vCenter", re.compile(rf"{_SEP}(vcenter|vcsa)[0-9]*{_END}", re.I)),
    ("PKI / CA", re.compile(rf"{_SEP}(pki|issuingca|rootca|subca)[0-9]*{_END}", re.I)),
    ("DNS / DHCP", re.compile(rf"{_SEP}(dns|dhcp)[0-9]*{_END}", re.I)),
]


def classify(row):
    """Return (kind, confidence) for an inventory row, or None if it does not look Tier-0."""
    t = STRUCTURAL_TYPES.get(row.get("objectType"))
    if t:
        return t, "structural"
    # A test or restore-drill copy of a domain controller is not Tier-0; finding C-2 already covers non-prod.
    name = row.get("name") or ""
    if row.get("objectType") in NAME_TYPES and not NONPROD_RE.search(name) and "restore" not in name.lower():
        for kind, rx in NAME_PATTERNS:
            if rx.search(name):
                return kind, "name"
    return None


def find(rows):
    """Tier-0 candidates among rows, one per (objectType, name).

    RSC lists a VM once per cluster that sees it, so rows repeat. The input rows are already filtered to
    unprotected objects, so a candidate here is unprotected on at least one cluster. It may still be protected
    from another cluster (see finding C-3), which this does not check.
    """
    seen = {}
    for r in rows:
        c = classify(r)
        if not c:
            continue
        key = (r["objectType"], r["name"])
        e = seen.setdefault(key, {"name": r["name"], "objectType": r["objectType"], "kind": c[0],
                                  "confidence": c[1], "statuses": set(), "clusters": set()})
        e["statuses"].add(r.get("protectionStatus"))
        e["clusters"].add(r.get("clusterName") or "unknown")
    out = []
    for e in seen.values():
        e["statuses"], e["clusters"] = sorted(e["statuses"], key=str), sorted(e["clusters"])
        out.append(e)
    out.sort(key=lambda e: (e["confidence"] != "structural", e["kind"], e["name"]))
    return out
