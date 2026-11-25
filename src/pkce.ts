import { XelorraAuthError } from "./errors.js";
import type { PkcePair } from "./types.js";

const BASE64URL_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Encodes raw bytes to RFC 4648 URL-safe Base64 without padding (`=`).
 * Works identically in browsers, Node.js, Edge workers, and React Native.
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let output = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const hasB1 = i + 1 < bytes.length;
    const hasB2 = i + 2 < bytes.length;
    const b1 = hasB1 ? bytes[i + 1]! : 0;
    const b2 = hasB2 ? bytes[i + 2]! : 0;

    output += BASE64URL_ALPHABET[b0 >> 2]!;
    output += BASE64URL_ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)]!;
    if (hasB1) {
      output += BASE64URL_ALPHABET[((b1 & 0x0f) << 2) | (b2 >> 6)]!;
    }
    if (hasB2) {
      output += BASE64URL_ALPHABET[b2 & 0x3f]!;
    }
  }
  return output;
}

async function getRandomBytes(length: number): Promise<Uint8Array> {
  if (typeof globalThis.crypto !== "undefined" && typeof globalThis.crypto.getRandomValues === "function") {
    const buffer = new Uint8Array(length);
    globalThis.crypto.getRandomValues(buffer);
    return buffer;
  }

  try {
    const nodeCrypto = await import("node:crypto");
    return new Uint8Array(nodeCrypto.randomBytes(length));
  } catch {
    throw new XelorraAuthError(
      "crypto_unavailable",
      "A cryptographic random generator (Web Crypto or Node crypto) is required for PKCE S256.",
    );
  }
}

async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle) {
    const copy = new Uint8Array(input.byteLength);
    copy.set(input);
    const digest = await globalThis.crypto.subtle.digest("SHA-256", copy.buffer);
    return new Uint8Array(digest);
  }

  try {
    const nodeCrypto = await import("node:crypto");
    const hash = nodeCrypto.createHash("sha256").update(input).digest();
    return new Uint8Array(hash);
  } catch {
    throw new XelorraAuthError(
      "crypto_unavailable",
      "SHA-256 hashing (Web Crypto or Node crypto) is required for PKCE S256.",
    );
  }
}

/**
 * Generates an RFC 7636 PKCE `S256` code verifier, code challenge, and CSRF state.
 * Compatible with both browser Web Crypto (`crypto.subtle`) and Node.js `node:crypto`.
 */
export async function createPkcePair(): Promise<PkcePair> {
  const verifierBytes = await getRandomBytes(48);
  const codeVerifier = bytesToBase64Url(verifierBytes);

  const challengeDigest = await sha256Bytes(new TextEncoder().encode(codeVerifier));
  const codeChallenge = bytesToBase64Url(challengeDigest);

  const stateBytes = await getRandomBytes(18);
  const state = bytesToBase64Url(stateBytes);

  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: "S256",
    state,
  };
}
