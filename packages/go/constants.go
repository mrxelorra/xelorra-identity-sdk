package xelorra

const (
	DefaultIssuer                  = "https://one.xelorra.app"
	DefaultWebhookToleranceSeconds = 300

	HeaderSignature = "X-Xelorra-Signature"
	HeaderEvent     = "X-Xelorra-Event"
	HeaderEventID   = "X-Xelorra-Event-Id"

	// Level 1: Basic Identity
	ScopeProfileRead  = "profile.read"
	ScopePassportRead = "passport.read"
	ScopeRewardsRead  = "rewards.read"

	// Level 2: Contact Identity
	ScopeEmailRead  = "email.read"
	ScopePhoneRead  = "phone.read"
	ScopeWalletRead = "wallet.read"

	// Level 3: Extended Identity
	ScopeAddressRead  = "address.read"
	ScopePersonalRead = "personal.read"
	ScopeLocationRead = "location.read"
	ScopeAccountRead  = "account.read"

	// Level 4: Verified Identity (admin review required)
	ScopeVerificationRead = "verification.read"
	ScopeKYCAssertionRead = "kyc.assertion.read"

	// Level 5: Restricted Government Identity (admin compliance approval required)
	ScopeGovNINVerify = "gov.nin.verify"
	ScopeGovBVNVerify = "gov.bvn.verify"

	// Signed Webhook Events (All 11)
	EventUserRegistered       = "user.registered"
	EventUserUpdated          = "user.updated"
	EventUserDeleted          = "user.deleted"
	EventUserAccountSuspended = "user.account_suspended"
	EventUserLogin            = "user.login"
	EventUserLogout           = "user.logout"
	EventUserEmailVerified    = "user.email_verified"
	EventUserPhoneVerified    = "user.phone_verified"
	EventUserIdentityVerified = "user.identity_verified"
	EventUserPermissionsUpdated = "user.permissions_updated"
	EventUserAccessRevoked    = "user.access_revoked"
)

// DefaultScopes returns the default Level 1 + 2 scope list.
func DefaultScopes() []string {
	return []string{ScopeProfileRead, ScopePassportRead, ScopeEmailRead}
}
