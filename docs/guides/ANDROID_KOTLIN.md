# Android (Kotlin) Integration Guide

Integrate Xelorra ID (`https://one.xelorra.app`) on Android using **AppAuth-Android** (Chrome Custom Tabs + automatic PKCE `S256`) and hardware-backed token storage.

## 1. Gradle Setup

```kotlin
dependencies {
    implementation("net.openid:appauth:0.11.1")
}
```

In `app/build.gradle.kts`, register your custom redirect scheme:

```kotlin
android {
    defaultConfig {
        manifestPlaceholders["appAuthRedirectScheme"] = "com.yourapp"
    }
}
```

## 2. Build Sign In & Sign Up (`prompt=create`) Requests

```kotlin
import android.net.Uri
import net.openid.appauth.AuthorizationRequest
import net.openid.appauth.AuthorizationServiceConfiguration
import net.openid.appauth.ResponseTypeValues

object XelorraConfig {
    const val ISSUER = "https://one.xelorra.app"
    const val CLIENT_ID = "your-android-client-id"
    val REDIRECT_URI: Uri = Uri.parse("com.yourapp://auth/callback")

    val serviceConfig = AuthorizationServiceConfiguration(
        Uri.parse("$ISSUER/oauth/authorize"),
        Uri.parse("$ISSUER/oauth/token"),
    )

    fun buildAuthRequest(signUp: Boolean = false): AuthorizationRequest {
        val builder = AuthorizationRequest.Builder(
            serviceConfig,
            CLIENT_ID,
            ResponseTypeValues.CODE,
            REDIRECT_URI,
        )
            .setScopes("profile.read", "passport.read", "email.read")

        if (signUp) {
            builder.setAdditionalParameters(mapOf("prompt" to "create"))
        }

        // AppAuth automatically generates an RFC 7636 S256 PKCE code_verifier & code_challenge
        return builder.build()
    }
}
```

## 3. Exchange Code & Handle `401 access_revoked`

```kotlin
// Inside your ActivityResult callback:
val resp = AuthorizationResponse.fromIntent(data)
val ex = AuthorizationException.fromIntent(data)

if (resp != null) {
    authService.performTokenRequest(resp.createTokenExchangeRequest()) { tokenResp, tokenErr ->
        val accessToken = tokenResp?.accessToken
        val refreshToken = tokenResp?.refreshToken
        // Persist accessToken and refreshToken in Android Keystore / EncryptedSharedPreferences.
        // Never embed client_secret in the APK.
    }
}
```

When calling `GET https://one.xelorra.app/oauth/userinfo`, check for HTTP `401` with JSON `{"error": "access_revoked"}` to immediately clear local tokens and navigate back to your login screen. On local sign-out, send `POST https://one.xelorra.app/oauth/revoke` with `{"token": refreshToken, "client_id": CLIENT_ID}`.
