/** Default production issuer origin for Xelorra One. */
export const DEFAULT_XELORRA_ISSUER = "https://one.xelorra.app";

/** Default scopes requested when no explicit scope list is provided. */
export const DEFAULT_XELORRA_SCOPES = [
  "profile.read",
  "passport.read",
  "email.read",
] as const;

/** Default replay-attack tolerance window in seconds for signed webhooks. */
export const DEFAULT_WEBHOOK_TOLERANCE_SECONDS = 300;

/** Canonical outbound webhook HTTP headers sent by Xelorra One. */
export const XELORRA_SIGNATURE_HEADER = "x-xelorra-signature";
export const XELORRA_EVENT_HEADER = "x-xelorra-event";
export const XELORRA_EVENT_ID_HEADER = "x-xelorra-event-id";

/**
 * Complete 14-scope catalog across all 5 permission levels on Xelorra One.
 */
export const XELORRA_SCOPES = {
  // Level 1: Basic Identity
  PROFILE_READ: "profile.read",
  PASSPORT_READ: "passport.read",
  REWARDS_READ: "rewards.read",

  // Level 2: Contact Identity
  EMAIL_READ: "email.read",
  PHONE_READ: "phone.read",
  WALLET_READ: "wallet.read",

  // Level 3: Extended Identity
  ADDRESS_READ: "address.read",
  PERSONAL_READ: "personal.read",
  LOCATION_READ: "location.read",
  ACCOUNT_READ: "account.read",

  // Level 4: Verified Identity (admin review required)
  VERIFICATION_READ: "verification.read",
  KYC_ASSERTION_READ: "kyc.assertion.read",

  // Level 5: Restricted Government Identity (admin compliance approval required)
  GOV_NIN_VERIFY: "gov.nin.verify",
  GOV_BVN_VERIFY: "gov.bvn.verify",
} as const;

export type XelorraScope = (typeof XELORRA_SCOPES)[keyof typeof XELORRA_SCOPES];

export interface XelorraScopeMetadata {
  scope: XelorraScope;
  level: 1 | 2 | 3 | 4 | 5;
  category:
    | "Basic Identity"
    | "Contact Identity"
    | "Extended Identity"
    | "Verified Identity"
    | "Restricted Government Identity";
  requiresApproval: boolean;
  description: string;
}

/** Structured metadata for all 14 scopes supported on https://one.xelorra.app. */
export const XELORRA_SCOPE_CATALOG: readonly XelorraScopeMetadata[] = [
  {
    scope: XELORRA_SCOPES.PROFILE_READ,
    level: 1,
    category: "Basic Identity",
    requiresApproval: false,
    description: "Display name, avatar, and basic member profile.",
  },
  {
    scope: XELORRA_SCOPES.PASSPORT_READ,
    level: 1,
    category: "Basic Identity",
    requiresApproval: false,
    description: "Xelorra Digital Passport status, tier, and membership standing.",
  },
  {
    scope: XELORRA_SCOPES.REWARDS_READ,
    level: 1,
    category: "Basic Identity",
    requiresApproval: false,
    description: "Ecosystem rewards balance and loyalty standing.",
  },
  {
    scope: XELORRA_SCOPES.EMAIL_READ,
    level: 2,
    category: "Contact Identity",
    requiresApproval: false,
    description: "Primary email address and verification flag.",
  },
  {
    scope: XELORRA_SCOPES.PHONE_READ,
    level: 2,
    category: "Contact Identity",
    requiresApproval: false,
    description: "Verified phone number and verification flag.",
  },
  {
    scope: XELORRA_SCOPES.WALLET_READ,
    level: 2,
    category: "Contact Identity",
    requiresApproval: false,
    description: "Linked Xelorra wallet metadata.",
  },
  {
    scope: XELORRA_SCOPES.ADDRESS_READ,
    level: 3,
    category: "Extended Identity",
    requiresApproval: false,
    description: "Residential or mailing address claims.",
  },
  {
    scope: XELORRA_SCOPES.PERSONAL_READ,
    level: 3,
    category: "Extended Identity",
    requiresApproval: false,
    description: "Extended personal demographic attributes.",
  },
  {
    scope: XELORRA_SCOPES.LOCATION_READ,
    level: 3,
    category: "Extended Identity",
    requiresApproval: false,
    description: "Country, region, and timezone attributes.",
  },
  {
    scope: XELORRA_SCOPES.ACCOUNT_READ,
    level: 3,
    category: "Extended Identity",
    requiresApproval: false,
    description: "Account status, creation timestamp, and membership metadata.",
  },
  {
    scope: XELORRA_SCOPES.VERIFICATION_READ,
    level: 4,
    category: "Verified Identity",
    requiresApproval: true,
    description: "Identity verification level and status claims.",
  },
  {
    scope: XELORRA_SCOPES.KYC_ASSERTION_READ,
    level: 4,
    category: "Verified Identity",
    requiresApproval: true,
    description: "Minimum-disclosure Reusable KYC verification assertion without raw PII.",
  },
  {
    scope: XELORRA_SCOPES.GOV_NIN_VERIFY,
    level: 5,
    category: "Restricted Government Identity",
    requiresApproval: true,
    description: "NIN verification assertion status (admin compliance approval required).",
  },
  {
    scope: XELORRA_SCOPES.GOV_BVN_VERIFY,
    level: 5,
    category: "Restricted Government Identity",
    requiresApproval: true,
    description: "BVN verification assertion status (admin compliance approval required).",
  },
] as const;

/** Scopes that authorize access to POST /api/v1/verify/assertion. */
export const KYC_ASSERTION_SCOPES: readonly XelorraScope[] = [
  XELORRA_SCOPES.KYC_ASSERTION_READ,
  XELORRA_SCOPES.VERIFICATION_READ,
  XELORRA_SCOPES.GOV_NIN_VERIFY,
  XELORRA_SCOPES.GOV_BVN_VERIFY,
] as const;

/** All 11 signed webhook event types emitted by Xelorra One. */
export const XELORRA_WEBHOOK_EVENTS = {
  // Lifecycle
  USER_REGISTERED: "user.registered",
  USER_UPDATED: "user.updated",
  USER_DELETED: "user.deleted",
  USER_ACCOUNT_SUSPENDED: "user.account_suspended",

  // Authentication
  USER_LOGIN: "user.login",
  USER_LOGOUT: "user.logout",

  // Verification
  USER_EMAIL_VERIFIED: "user.email_verified",
  USER_PHONE_VERIFIED: "user.phone_verified",
  USER_IDENTITY_VERIFIED: "user.identity_verified",

  // Consent
  USER_PERMISSIONS_UPDATED: "user.permissions_updated",
  USER_ACCESS_REVOKED: "user.access_revoked",
} as const;

export type XelorraWebhookEventType =
  (typeof XELORRA_WEBHOOK_EVENTS)[keyof typeof XELORRA_WEBHOOK_EVENTS];

export const ALL_XELORRA_WEBHOOK_EVENTS: readonly XelorraWebhookEventType[] =
  Object.values(XELORRA_WEBHOOK_EVENTS);
