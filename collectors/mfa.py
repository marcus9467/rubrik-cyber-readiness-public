"""Global MFA / TOTP enforcement settings."""

MFA_Q = """
query Mfa {
  mfaSetting {
    isTotpEnforcedGlobal isTotpGlobalEnforceLocked isTotpMandatory
    mandatoryTotpEnforcementDate mfaRememberHours totpReminderHours
  }
}
"""


def collect(client):
    return client.query(MFA_Q)["mfaSetting"]
