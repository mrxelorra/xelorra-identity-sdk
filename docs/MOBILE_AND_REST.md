# Mobile & Universal REST Integration Guides

Because Xelorra One implements standard OAuth 2.0 + OpenID Connect + PKCE (`S256`) with clean JSON/form endpoints, any mobile platform or backend language (Ruby, Java, C#/.NET, Rust, Elixir) can integrate directly.

## Security Rules for Native Mobile Apps

1. **Always use the system browser** (`ASWebAuthenticationSession` on iOS, Chrome Custom Tabs on Android, `expo-auth-session` on Expo, `flutter_appauth` on Flutter). Never use embedded WebViews.
2. **Never embed `client_secret` in mobile binaries**. Native mobile apps are public PKCE clients and authenticate token exchanges using `code_verifier` (`S256`).
3. **Store tokens only in hardware-backed secure storage** (iOS Keychain, Android Keystore / EncryptedSharedPreferences, `expo-secure-store`, `flutter_secure_storage`).
4. **Support both Sign In and Sign Up**: Offer a "Sign in with Xelorra ID" button (no `prompt`) and a "Sign up with Xelorra ID" button (`prompt=create`).

## Platform-Specific Guides

- **[React Native / Expo Guide](./guides/REACT_NATIVE_EXPO.md)**: `expo-auth-session` + `expo-secure-store` + `prompt=create`.
- **[Flutter Guide](./guides/FLUTTER.md)**: `flutter_appauth` + `flutter_secure_storage` + KYC assertion check.
- **[Android (Kotlin) Guide](./guides/ANDROID_KOTLIN.md)**: AppAuth-Android + Chrome Custom Tabs + EncryptedSharedPreferences.
- **[iOS (Swift) Guide](./guides/IOS_SWIFT.md)**: `ASWebAuthenticationSession` + `CryptoKit` PKCE `S256` + Keychain.
- **[Universal cURL / REST Reference](./guides/CURL_REST.md)**: Complete raw HTTP examples for every live endpoint on `https://one.xelorra.app` (ideal for Ruby, Java, C#/.NET, Rust, and manual debugging).
