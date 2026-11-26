# iOS (Swift) Integration Guide

Integrate Xelorra ID (`https://one.xelorra.app`) on iOS using `ASWebAuthenticationSession`, `CryptoKit` (unpadded PKCE `S256`), and iOS Keychain storage.

## 1. PKCE `S256` Helper (`CryptoKit`)

```swift
import AuthenticationServices
import CryptoKit
import Foundation

struct XelorraPKCE {
    let codeVerifier: String
    let codeChallenge: String
    let state: String

    static func generate() -> XelorraPKCE {
        var verifierBytes = [UInt8](repeating: 0, count: 48)
        _ = SecRandomCopyBytes(kSecRandomDefault, verifierBytes.count, &verifierBytes)
        let verifier = base64URLEncode(Data(verifierBytes))

        let digest = SHA256.hash(data: Data(verifier.utf8))
        let challenge = base64URLEncode(Data(digest))

        var stateBytes = [UInt8](repeating: 0, count: 18)
        _ = SecRandomCopyBytes(kSecRandomDefault, stateBytes.count, &stateBytes)
        let state = base64URLEncode(Data(stateBytes))

        return XelorraPKCE(codeVerifier: verifier, codeChallenge: challenge, state: state)
    }

    private static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
```

## 2. Launch `ASWebAuthenticationSession` (Sign In or Sign Up with `prompt=create`)

```swift
final class XelorraAuthManager: NSObject {
    let issuer = "https://one.xelorra.app"
    let clientId = "your-ios-client-id"
    let redirectUri = "myapp://auth/callback"
    let callbackScheme = "myapp"

    func buildAuthorizeURL(pkce: XelorraPKCE, signUp: Bool = false) -> URL {
        var components = URLComponents(string: "\(issuer)/oauth/authorize")!
        var items: [URLQueryItem] = [
            .init(name: "response_type", value: "code"),
            .init(name: "client_id", value: clientId),
            .init(name: "redirect_uri", value: redirectUri),
            .init(name: "scope", value: "profile.read passport.read email.read"),
            .init(name: "state", value: pkce.state),
            .init(name: "code_challenge", value: pkce.codeChallenge),
            .init(name: "code_challenge_method", value: "S256"),
        ]
        if signUp {
            items.append(.init(name: "prompt", value: "create"))
        }
        components.queryItems = items
        return components.url!
    }

    func exchangeCode(code: String, codeVerifier: String) async throws -> [String: Any] {
        var req = URLRequest(url: URL(string: "\(issuer)/oauth/token")!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: [
            "grant_type": "authorization_code",
            "code": code,
            "client_id": clientId,
            "redirect_uri": redirectUri,
            "code_verifier": codeVerifier,
        ])

        let (data, _) = try await URLSession.shared.data(for: req)
        return (try JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    }
}
```

Store returned tokens exclusively in the iOS Keychain, check `401 access_revoked` on `GET /oauth/userinfo`, and call `POST /oauth/revoke` when the user disconnects Xelorra ID in your app.
