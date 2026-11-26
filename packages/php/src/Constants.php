<?php

declare(strict_types=1);

namespace Xelorra\Identity;

final class Constants
{
    public const DEFAULT_ISSUER = 'https://one.xelorra.app';
    public const DEFAULT_WEBHOOK_TOLERANCE_SECONDS = 300;

    public const HEADER_SIGNATURE = 'X-Xelorra-Signature';
    public const HEADER_EVENT = 'X-Xelorra-Event';
    public const HEADER_EVENT_ID = 'X-Xelorra-Event-Id';

    /** @var list<string> */
    public const DEFAULT_SCOPES = [
        'profile.read',
        'passport.read',
        'email.read',
    ];

    /** Complete 14-scope catalog across Levels 1 to 5. */
    public const SCOPE_PROFILE_READ = 'profile.read';
    public const SCOPE_PASSPORT_READ = 'passport.read';
    public const SCOPE_REWARDS_READ = 'rewards.read';
    public const SCOPE_EMAIL_READ = 'email.read';
    public const SCOPE_PHONE_READ = 'phone.read';
    public const SCOPE_WALLET_READ = 'wallet.read';
    public const SCOPE_ADDRESS_READ = 'address.read';
    public const SCOPE_PERSONAL_READ = 'personal.read';
    public const SCOPE_LOCATION_READ = 'location.read';
    public const SCOPE_ACCOUNT_READ = 'account.read';
    public const SCOPE_VERIFICATION_READ = 'verification.read';
    public const SCOPE_KYC_ASSERTION_READ = 'kyc.assertion.read';
    public const SCOPE_GOV_NIN_VERIFY = 'gov.nin.verify';
    public const SCOPE_GOV_BVN_VERIFY = 'gov.bvn.verify';

    /** @var list<string> */
    public const ALL_SCOPES = [
        self::SCOPE_PROFILE_READ,
        self::SCOPE_PASSPORT_READ,
        self::SCOPE_REWARDS_READ,
        self::SCOPE_EMAIL_READ,
        self::SCOPE_PHONE_READ,
        self::SCOPE_WALLET_READ,
        self::SCOPE_ADDRESS_READ,
        self::SCOPE_PERSONAL_READ,
        self::SCOPE_LOCATION_READ,
        self::SCOPE_ACCOUNT_READ,
        self::SCOPE_VERIFICATION_READ,
        self::SCOPE_KYC_ASSERTION_READ,
        self::SCOPE_GOV_NIN_VERIFY,
        self::SCOPE_GOV_BVN_VERIFY,
    ];

    /** All 11 signed webhook event types emitted by Xelorra One. */
    public const EVENT_USER_REGISTERED = 'user.registered';
    public const EVENT_USER_UPDATED = 'user.updated';
    public const EVENT_USER_DELETED = 'user.deleted';
    public const EVENT_USER_ACCOUNT_SUSPENDED = 'user.account_suspended';
    public const EVENT_USER_LOGIN = 'user.login';
    public const EVENT_USER_LOGOUT = 'user.logout';
    public const EVENT_USER_EMAIL_VERIFIED = 'user.email_verified';
    public const EVENT_USER_PHONE_VERIFIED = 'user.phone_verified';
    public const EVENT_USER_IDENTITY_VERIFIED = 'user.identity_verified';
    public const EVENT_USER_PERMISSIONS_UPDATED = 'user.permissions_updated';
    public const EVENT_USER_ACCESS_REVOKED = 'user.access_revoked';

    /** @var list<string> */
    public const ALL_WEBHOOK_EVENTS = [
        self::EVENT_USER_REGISTERED,
        self::EVENT_USER_UPDATED,
        self::EVENT_USER_DELETED,
        self::EVENT_USER_ACCOUNT_SUSPENDED,
        self::EVENT_USER_LOGIN,
        self::EVENT_USER_LOGOUT,
        self::EVENT_USER_EMAIL_VERIFIED,
        self::EVENT_USER_PHONE_VERIFIED,
        self::EVENT_USER_IDENTITY_VERIFIED,
        self::EVENT_USER_PERMISSIONS_UPDATED,
        self::EVENT_USER_ACCESS_REVOKED,
    ];
}
