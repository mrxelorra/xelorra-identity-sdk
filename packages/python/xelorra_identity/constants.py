"""Constants for the Xelorra Identity API on https://one.xelorra.app."""

DEFAULT_ISSUER = "https://one.xelorra.app"
DEFAULT_WEBHOOK_TOLERANCE_SECONDS = 300

HEADER_SIGNATURE = "X-Xelorra-Signature"
HEADER_EVENT = "X-Xelorra-Event"
HEADER_EVENT_ID = "X-Xelorra-Event-Id"

DEFAULT_SCOPES: tuple[str, ...] = (
    "profile.read",
    "passport.read",
    "email.read",
)

# Complete 14-scope catalog across Levels 1 to 5
XELORRA_SCOPES: dict[str, str] = {
    # Level 1: Basic Identity
    "PROFILE_READ": "profile.read",
    "PASSPORT_READ": "passport.read",
    "REWARDS_READ": "rewards.read",
    # Level 2: Contact Identity
    "EMAIL_READ": "email.read",
    "PHONE_READ": "phone.read",
    "WALLET_READ": "wallet.read",
    # Level 3: Extended Identity
    "ADDRESS_READ": "address.read",
    "PERSONAL_READ": "personal.read",
    "LOCATION_READ": "location.read",
    "ACCOUNT_READ": "account.read",
    # Level 4: Verified Identity (admin review required)
    "VERIFICATION_READ": "verification.read",
    "KYC_ASSERTION_READ": "kyc.assertion.read",
    # Level 5: Restricted Government Identity (admin compliance approval required)
    "GOV_NIN_VERIFY": "gov.nin.verify",
    "GOV_BVN_VERIFY": "gov.bvn.verify",
}

# All 11 signed webhook events emitted by Xelorra One
XELORRA_WEBHOOK_EVENTS: dict[str, str] = {
    # Lifecycle
    "USER_REGISTERED": "user.registered",
    "USER_UPDATED": "user.updated",
    "USER_DELETED": "user.deleted",
    "USER_ACCOUNT_SUSPENDED": "user.account_suspended",
    # Authentication
    "USER_LOGIN": "user.login",
    "USER_LOGOUT": "user.logout",
    # Verification
    "USER_EMAIL_VERIFIED": "user.email_verified",
    "USER_PHONE_VERIFIED": "user.phone_verified",
    "USER_IDENTITY_VERIFIED": "user.identity_verified",
    # Consent
    "USER_PERMISSIONS_UPDATED": "user.permissions_updated",
    "USER_ACCESS_REVOKED": "user.access_revoked",
}
