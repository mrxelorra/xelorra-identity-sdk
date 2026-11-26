# React Native / Expo Integration Guide

Integrate Xelorra ID (`https://one.xelorra.app`) in React Native / Expo using `expo-auth-session`, `expo-web-browser`, and `expo-secure-store` (PKCE `S256`, no client secret in the app bundle).

## 1. Install Dependencies

```bash
npx expo install expo-auth-session expo-crypto expo-web-browser expo-secure-store
```

Register your custom redirect URI (for example `myapp://auth/callback`) in **console.one.xelorra.app**.

## 2. Sign In & Sign Up (`prompt=create`) Hook

```tsx
import { useEffect } from "react";
import { Button, View } from "react-native";
import * as AuthSession from "expo-auth-session";
import * as SecureStore from "expo-secure-store";
import * as WebBrowser from "expo-web-browser";

WebBrowser.maybeCompleteAuthSession();

const ISSUER = "https://one.xelorra.app";
const CLIENT_ID = "your-mobile-client-id";

const discovery: AuthSession.DiscoveryDocument = {
  authorizationEndpoint: `${ISSUER}/oauth/authorize`,
  tokenEndpoint: `${ISSUER}/oauth/token`,
  revocationEndpoint: `${ISSUER}/oauth/revoke`,
};

export function XelorraAuthButtons({ onAuthenticated }: { onAuthenticated: (user: any) => void }) {
  const redirectUri = AuthSession.makeRedirectUri({ scheme: "myapp", path: "auth/callback" });

  const [request, response, promptAsync] = AuthSession.useAuthRequest(
    {
      clientId: CLIENT_ID,
      redirectUri,
      scopes: ["profile.read", "passport.read", "email.read"],
      usePKCE: true,
      codeChallengeMethod: AuthSession.CodeChallengeMethod.S256,
    },
    discovery,
  );

  useEffect(() => {
    if (response?.type === "success" && response.params.code && request?.codeVerifier) {
      void (async () => {
        const tokenRes = await fetch(`${ISSUER}/oauth/token`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            grant_type: "authorization_code",
            code: response.params.code,
            client_id: CLIENT_ID,
            redirect_uri: redirectUri,
            code_verifier: request.codeVerifier,
          }),
        });
        const tokens = await tokenRes.json();

        await SecureStore.setItemAsync("xelorra_access_token", tokens.access_token);
        if (tokens.refresh_token) {
          await SecureStore.setItemAsync("xelorra_refresh_token", tokens.refresh_token);
        }

        const userRes = await fetch(`${ISSUER}/oauth/userinfo`, {
          headers: { authorization: `Bearer ${tokens.access_token}` },
        });
        onAuthenticated(await userRes.json());
      })();
    }
  }, [response, request, redirectUri, onAuthenticated]);

  const startSignUp = async () => {
    // Use a separate request with extraParams: { prompt: "create" } for new members
    await promptAsync();
  };

  return (
    <View style={{ gap: 12 }}>
      <Button title="Sign in with Xelorra ID" disabled={!request} onPress={() => void promptAsync()} />
      <Button title="Sign up with Xelorra ID" disabled={!request} onPress={() => void startSignUp()} />
    </View>
  );
}
```

> Tip: To send new users directly to registration, pass `extraParams: { prompt: "create" }` inside `useAuthRequest`.

## 3. Disconnect & Revoke on Sign Out

```ts
export async function disconnectXelorra() {
  const token =
    (await SecureStore.getItemAsync("xelorra_refresh_token")) ??
    (await SecureStore.getItemAsync("xelorra_access_token"));

  if (token) {
    await fetch("https://one.xelorra.app/oauth/revoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, client_id: CLIENT_ID }),
    });
  }

  await SecureStore.deleteItemAsync("xelorra_access_token");
  await SecureStore.deleteItemAsync("xelorra_refresh_token");
}
```
