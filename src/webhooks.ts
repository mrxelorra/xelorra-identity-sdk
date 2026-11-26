import {
  DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
  XELORRA_EVENT_HEADER,
  XELORRA_EVENT_ID_HEADER,
  XELORRA_SIGNATURE_HEADER,
} from "./constants.js";
import { XelorraWebhookSignatureError } from "./errors.js";
import type { VerifyWebhookOptions, XelorraWebhookEvent } from "./types.js";

export { XELORRA_EVENT_HEADER, XELORRA_EVENT_ID_HEADER, XELORRA_SIGNATURE_HEADER };

interface ParsedSignatureHeader {
  timestamp: number;
  rawTimestamp: string;
  v1Signatures: string[];
}

function rawBodyToString(rawBody: string | Uint8Array): string {
  return typeof rawBody === "string" ? rawBody : new TextDecoder().decode(rawBody);
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    return null;
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Constant-time comparison over two equal-length byte arrays.
 * Uses bitwise XOR accumulation so execution time does not depend on matching prefixes.
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

async function computeHmacSha256Bytes(
  message: string,
  secret: string,
): Promise<Uint8Array> {
  const messageBytes = new TextEncoder().encode(message);

  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle) {
    const keyBytes = new TextEncoder().encode(secret);
    const keyCopy = new Uint8Array(keyBytes.byteLength);
    keyCopy.set(keyBytes);
    const msgCopy = new Uint8Array(messageBytes.byteLength);
    msgCopy.set(messageBytes);

    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      keyCopy.buffer,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, msgCopy.buffer);
    return new Uint8Array(signature);
  }

  const nodeCrypto = await import("node:crypto");
  const digest = nodeCrypto.createHmac("sha256", secret).update(messageBytes).digest();
  return new Uint8Array(digest);
}

/**
 * Parses a `X-Xelorra-Signature` header of the exact format `t=<unix_seconds>,v1=<hmac_sha256_hex>`.
 */
export function parseSignatureHeader(signatureHeader: string): ParsedSignatureHeader | null {
  const trimmed = signatureHeader.trim();
  if (!trimmed) return null;

  let rawTimestamp: string | null = null;
  const v1Signatures: string[] = [];

  for (const segment of trimmed.split(",")) {
    const part = segment.trim();
    if (!part) continue;
    const eqIndex = part.indexOf("=");
    if (eqIndex <= 0) return null;
    const key = part.slice(0, eqIndex).trim();
    const value = part.slice(eqIndex + 1).trim();
    if (!value) return null;

    if (key === "t") {
      if (rawTimestamp !== null || !/^\d+$/.test(value)) {
        return null;
      }
      rawTimestamp = value;
    } else if (key === "v1") {
      if (!/^[0-9a-fA-F]{64}$/.test(value)) {
        return null;
      }
      v1Signatures.push(value.toLowerCase());
    }
  }

  if (rawTimestamp === null || v1Signatures.length === 0) {
    return null;
  }

  const timestamp = Number(rawTimestamp);
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0) {
    return null;
  }

  return { timestamp, rawTimestamp, v1Signatures };
}

function normalizeWebhookArgs(
  first: VerifyWebhookOptions | string | Uint8Array,
  signatureHeader?: string | null,
  signingSecret?: string,
  toleranceSeconds?: number,
): VerifyWebhookOptions {
  if (
    typeof first === "object" &&
    first !== null &&
    !(first instanceof Uint8Array) &&
    "rawBody" in first
  ) {
    return first;
  }
  return {
    rawBody: first,
    signatureHeader,
    signingSecret: signingSecret ?? "",
    toleranceSeconds,
  };
}

/**
 * Generates an outbound `X-Xelorra-Signature` header value in the exact Xelorra One format:
 * `t=<unix_timestamp_seconds>,v1=<hmac_sha256_hex>` where the signed payload is
 * `"${t}.${rawBody}"`. Useful for local testing and webhook integration tests.
 */
export async function computeWebhookSignature(
  rawBody: string | Uint8Array,
  signingSecret: string,
  timestampSeconds?: number,
): Promise<string> {
  if (!signingSecret) {
    throw new XelorraWebhookSignatureError(
      "missing_webhook_secret",
      "signingSecret is required to compute a webhook signature.",
    );
  }
  const ts =
    typeof timestampSeconds === "number"
      ? Math.floor(timestampSeconds)
      : Math.floor(Date.now() / 1000);
  const bodyText = rawBodyToString(rawBody);
  const digest = await computeHmacSha256Bytes(`${ts}.${bodyText}`, signingSecret);
  return `t=${ts},v1=${bytesToHex(digest)}`;
}

async function verifySignatureInternal(options: VerifyWebhookOptions): Promise<{
  ok: boolean;
  errorCode?:
    | "missing_webhook_secret"
    | "missing_signature"
    | "malformed_signature"
    | "expired_timestamp"
    | "invalid_signature";
  errorMessage?: string;
}> {
  const {
    rawBody,
    signatureHeader,
    signingSecret,
    toleranceSeconds = DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
    nowSeconds = Math.floor(Date.now() / 1000),
  } = options;

  if (!signingSecret) {
    return {
      ok: false,
      errorCode: "missing_webhook_secret",
      errorMessage: "signingSecret is required to verify Xelorra webhooks.",
    };
  }

  if (!signatureHeader || !signatureHeader.trim()) {
    return {
      ok: false,
      errorCode: "missing_signature",
      errorMessage: "Missing X-Xelorra-Signature header.",
    };
  }

  const parsed = parseSignatureHeader(signatureHeader);
  if (!parsed) {
    return {
      ok: false,
      errorCode: "malformed_signature",
      errorMessage:
        "X-Xelorra-Signature header must follow the format 't=<unix_timestamp>,v1=<hmac_sha256_hex>'.",
    };
  }

  if (toleranceSeconds > 0 && Math.abs(nowSeconds - parsed.timestamp) > toleranceSeconds) {
    return {
      ok: false,
      errorCode: "expired_timestamp",
      errorMessage: `Webhook timestamp is outside the allowed ${toleranceSeconds}s tolerance window.`,
    };
  }

  const signedPayload = `${parsed.rawTimestamp}.${rawBodyToString(rawBody)}`;
  const expectedBytes = await computeHmacSha256Bytes(signedPayload, signingSecret);

  let matched = false;
  for (const hexSig of parsed.v1Signatures) {
    const providedBytes = hexToBytes(hexSig);
    if (providedBytes && constantTimeEqual(providedBytes, expectedBytes)) {
      matched = true;
    }
  }

  if (!matched) {
    return {
      ok: false,
      errorCode: "invalid_signature",
      errorMessage: "X-Xelorra-Signature verification failed.",
    };
  }

  return { ok: true };
}

/**
 * Verifies the `X-Xelorra-Signature` header (`t=<unix_seconds>,v1=<hmac_sha256_hex>`)
 * against the exact raw request body using constant-time comparison and replay-window
 * timestamp validation (default 300 seconds).
 *
 * Returns `false` for missing, malformed, expired, or tampered signatures without throwing.
 */
export async function verifyWebhookSignature(options: VerifyWebhookOptions): Promise<boolean>;
export async function verifyWebhookSignature(
  rawBody: string | Uint8Array,
  signatureHeader: string | null | undefined,
  signingSecret: string,
  toleranceSeconds?: number,
): Promise<boolean>;
export async function verifyWebhookSignature(
  first: VerifyWebhookOptions | string | Uint8Array,
  signatureHeader?: string | null,
  signingSecret?: string,
  toleranceSeconds?: number,
): Promise<boolean> {
  const options = normalizeWebhookArgs(first, signatureHeader, signingSecret, toleranceSeconds);
  const result = await verifySignatureInternal(options);
  return result.ok;
}

/**
 * Verifies the `X-Xelorra-Signature` header (`t=<unix_seconds>,v1=<hmac_sha256_hex>`)
 * with replay-window enforcement and parses the raw webhook body into a strongly typed
 * `XelorraWebhookEvent`.
 *
 * Throws `XelorraWebhookSignatureError` if the secret is missing, the signature is missing,
 * malformed, expired, or invalid, or the JSON envelope is malformed.
 */
export async function parseWebhookEvent(options: VerifyWebhookOptions): Promise<XelorraWebhookEvent>;
export async function parseWebhookEvent(
  rawBody: string | Uint8Array,
  signatureHeader: string | null | undefined,
  signingSecret: string,
  toleranceSeconds?: number,
): Promise<XelorraWebhookEvent>;
export async function parseWebhookEvent(
  first: VerifyWebhookOptions | string | Uint8Array,
  signatureHeader?: string | null,
  signingSecret?: string,
  toleranceSeconds?: number,
): Promise<XelorraWebhookEvent> {
  const options = normalizeWebhookArgs(first, signatureHeader, signingSecret, toleranceSeconds);
  const check = await verifySignatureInternal(options);
  if (!check.ok) {
    throw new XelorraWebhookSignatureError(
      check.errorCode ?? "invalid_signature",
      check.errorMessage ?? "X-Xelorra-Signature verification failed.",
    );
  }

  const bodyText = rawBodyToString(options.rawBody);

  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    throw new XelorraWebhookSignatureError(
      "invalid_payload",
      "Webhook payload is not valid JSON.",
    );
  }

  if (
    !parsed ||
    typeof parsed !== "object" ||
    typeof (parsed as Record<string, unknown>).type !== "string" ||
    !(parsed as Record<string, unknown>).data ||
    typeof (parsed as Record<string, unknown>).data !== "object"
  ) {
    throw new XelorraWebhookSignatureError(
      "invalid_payload",
      "Webhook payload must be a JSON object with string 'type' and object 'data'.",
    );
  }

  return parsed as XelorraWebhookEvent;
}
