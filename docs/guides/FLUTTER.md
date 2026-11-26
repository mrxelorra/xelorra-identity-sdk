# Flutter Integration Guide

Integrate Xelorra ID (`https://one.xelorra.app`) in Flutter using `flutter_appauth` (system browser + automatic PKCE `S256`) and `flutter_secure_storage`.

## 1. Add Dependencies (`pubspec.yaml`)

```yaml
dependencies:
  flutter_appauth: ^8.0.0
  flutter_secure_storage: ^9.2.2
  http: ^1.2.2
```

Register your redirect URI (for example `com.yourapp://auth/callback`) in **console.one.xelorra.app**.

## 2. Sign In, Sign Up (`prompt=create`), KYC Assertion & Revocation

```dart
import 'dart:convert';
import 'package:flutter_appauth/flutter_appauth.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;

class XelorraAuthService {
  static const _issuer = 'https://one.xelorra.app';
  static const _clientId = 'your-flutter-client-id';
  static const _redirectUri = 'com.yourapp://auth/callback';

  final _appAuth = const FlutterAppAuth();
  final _storage = const FlutterSecureStorage();

  Future<AuthorizationTokenResponse?> authenticate({bool signUp = false}) async {
    final result = await _appAuth.authorizeAndExchangeCode(
      AuthorizationTokenRequest(
        _clientId,
        _redirectUri,
        discoveryUrl: '$_issuer/.well-known/openid-configuration',
        scopes: const ['profile.read', 'passport.read', 'email.read'],
        additionalParameters: signUp ? const {'prompt': 'create'} : null,
      ),
    );

    if (result?.accessToken != null) {
      await _storage.write(key: 'xelorra_access_token', value: result!.accessToken);
      if (result.refreshToken != null) {
        await _storage.write(key: 'xelorra_refresh_token', value: result.refreshToken);
      }
    }
    return result;
  }

  Future<Map<String, dynamic>> getUserInfo() async {
    final token = await _storage.read(key: 'xelorra_access_token');
    final res = await http.get(
      Uri.parse('$_issuer/oauth/userinfo'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (res.statusCode == 401) {
      final body = jsonDecode(res.body) as Map<String, dynamic>;
      if (body['error'] == 'access_revoked') {
        await _clearLocalTokens();
        throw Exception('Xelorra access was revoked.');
      }
    }
    return jsonDecode(res.body) as Map<String, dynamic>;
  }

  Future<void> disconnect() async {
    final token = await _storage.read(key: 'xelorra_refresh_token') ??
        await _storage.read(key: 'xelorra_access_token');
    if (token != null) {
      await http.post(
        Uri.parse('$_issuer/oauth/revoke'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({'token': token, 'client_id': _clientId}),
      );
    }
    await _clearLocalTokens();
  }

  Future<void> _clearLocalTokens() async {
    await _storage.delete(key: 'xelorra_access_token');
    await _storage.delete(key: 'xelorra_refresh_token');
  }
}
```
