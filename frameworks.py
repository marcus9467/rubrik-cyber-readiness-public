"""Map each finding id to a NIST CSF 2.0 function and to HIPAA Security Rule sections.

HIPAA citations were checked against the 45 CFR 164.308 and 164.312 text on 2026-10-22. The function and section
assignment per finding has not had a compliance review.

CSF 2.0 functions: GV Govern, ID Identify, PR Protect, DE Detect, RS Respond, RC Recover.
"""

CSF_NAMES = {"GV": "Govern", "ID": "Identify", "PR": "Protect", "DE": "Detect", "RS": "Respond", "RC": "Recover"}

# HIPAA Security Rule sections used below.
H_AUTH = "164.312(d)"            # person or entity authentication
H_ACCESS = "164.312(a)(1)"       # access control
H_AUDIT = "164.312(b)"           # audit controls
H_REVIEW = "164.308(a)(1)(ii)(D)"  # information system activity review
H_BACKUP = "164.308(a)(7)(ii)(A)"  # data backup plan
H_DR = "164.308(a)(7)(ii)(B)"      # disaster recovery plan
H_TEST = "164.308(a)(7)(ii)(D)"    # testing and revision of contingency plans
H_ENC = "164.312(a)(2)(iv)"        # encryption and decryption (addressable)
H_INTEGRITY = "164.312(c)(1)"      # integrity
H_PASSWORD = "164.308(a)(5)(ii)(D)"  # password management
H_ACCESSMGMT = "164.308(a)(4)"     # information access management
H_WORKFORCE = "164.308(a)(3)"      # workforce security
H_RISK = "164.308(a)(1)(ii)(A)"    # risk analysis
H_INCIDENT = "164.308(a)(6)(ii)"   # response and reporting

MAP = {
    "ID-1": ("PR", [H_AUTH]),
    "ID-2": ("PR", [H_WORKFORCE, H_ACCESSMGMT]),
    "ID-3": ("PR", [H_ACCESSMGMT]),
    "ID-4": ("PR", [H_ACCESSMGMT]),
    "MFA-1": ("PR", [H_AUTH]),
    "MFA-2": ("PR", [H_AUTH]),
    "Q-1": ("PR", [H_ACCESS, H_INTEGRITY]),
    "Q-2": ("PR", [H_ACCESS, H_INTEGRITY]),
    "A-1": ("PR", [H_ACCESS]),
    "A-2": ("PR", [H_ACCESS, H_AUTH]),
    "A-3": ("PR", [H_AUTH]),
    "A-4": ("PR", [H_PASSWORD]),
    "R-1": ("PR", [H_ACCESSMGMT]),
    "R-2": ("PR", [H_ACCESSMGMT]),
    "R-3": ("PR", [H_AUTH, H_ACCESSMGMT]),
    "R-4": ("PR", [H_ACCESSMGMT]),
    "R-5": ("PR", [H_ACCESSMGMT]),
    "S-1": ("PR", [H_INTEGRITY, H_BACKUP]),
    "S-2": ("PR", [H_INTEGRITY, H_BACKUP]),
    "S-3": ("PR", [H_INTEGRITY, H_BACKUP]),
    "RP-1": ("PR", [H_BACKUP, H_DR]),
    "RP-2": ("PR", [H_BACKUP, H_DR]),
    "RP-3": ("PR", [H_BACKUP, H_DR]),
    "C-1": ("ID", [H_RISK, H_BACKUP]),
    "C-2": ("ID", [H_RISK, H_BACKUP]),
    "C-3": ("RC", [H_BACKUP]),
    "C-4": ("ID", [H_RISK, H_BACKUP, H_DR]),
    "C-5": ("RC", [H_BACKUP]),
    "CL-1": ("PR", [H_ENC]),
    "CL-2": ("PR", [H_ACCESS]),
    "CL-3": ("PR", [H_ACCESS]),
    "T-1": ("DE", [H_REVIEW]),
    "T-2": ("ID", [H_ACCESS, H_RISK]),
    "T-3": ("DE", [H_REVIEW]),
    "T-4": ("DE", [H_AUDIT, H_REVIEW]),
    "T-5": ("DE", [H_AUDIT, H_REVIEW]),
    "T-6": ("DE", [H_REVIEW, H_INCIDENT]),
    "T-7": ("DE", [H_AUDIT, H_REVIEW]),
    "T-8": ("DE", [H_REVIEW]),
    "T-9": ("DE", [H_AUDIT, H_REVIEW]),
    "T-10": ("DE", [H_REVIEW]),
    "T-11": ("DE", [H_REVIEW]),
    "V-1": ("DE", [H_REVIEW, H_INCIDENT]),
    "V-2": ("DE", [H_REVIEW, H_INCIDENT]),
    "V-4": ("ID", [H_RISK, H_ACCESS]),
    "RC-1": ("RC", [H_DR]),
    "RC-2": ("RC", [H_TEST]),
    "RC-3": ("RC", [H_TEST]),
}


def framework_of(rule_id):
    """CSF function code and HIPAA sections for a rule id. Unmapped ids return (None, [])."""
    csf, hipaa = MAP.get(rule_id, (None, []))
    return {"csf": csf, "hipaa": list(hipaa)}
