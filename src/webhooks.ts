import { XelorraWebhookSignatureError } from "./errors.js";
import type { XelorraWebhookEvent } from "./types.js";

/** Canonical HTTP header carrying the HMAC-SHA256 webhook signature from Xelorra One. */
export const XELORRA_SIGNATURE_HEADER = "x-xelorra-signature";

function toBytes(input: string | Uint8Array): Uint8Array {
  return typeof input === "string" ? new TextEncoder().encode(input) : input;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i]!.toString(16).padStart(2, "0");
  }
  return hex;
}

function hexToBytes(hex: string): Uint8Array | null {
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    return null;
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function extractHexDigest(signatureHeader: string): string | null {
  const trimmed = signatureHeader.trim();
  if (!trimmed) return null;

  // Support raw hex, "sha256=<hex>", or comma-separated key=value formats like "v1=<hex>"
  const parts = trimmed.split(",").map((part) => part.trim());
  for (const part of parts) {
    const candidate = part.includes("=") ? part.slice(part.indexOf("=") + 1).trim() : part;
    if (/^[0-9a-fA-F]{64}$/.test(candidate)) {
      return candidate.toLowerCase();
    }
  }
  return null;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

async function computeHmacSha256Bytes(
  rawBody: Uint8Array,
  secret: string,
): Promise<Uint8Array> {
  if (typeof globalThis.crypto !== "undefined" && globalThis.crypto.subtle) {
    const keyBytes = new TextEncoder().encode(secret);
    const keyCopy = new Uint8Array(keyBytes.byteLength);
    keyCopy.set(keyBytes);
    const bodyCopy = new Uint8Array(rawBody.byteLength);
    bodyCopy.set(rawBody);

    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      keyCopy.buffer,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, bodyCopy.buffer);
    return new Uint8Array(signature);
  }

  const nodeCrypto = await import("node:crypto");
  const digest = nodeCrypto.createHmac("sha256", secret).update(rawBody).digest();
  return new Uint8Array(digest);
}

/**
 * Computes the hex-encoded HMAC-SHA256 webhook signature for a raw request body.
 * Useful when writing integration tests for your webhook endpoint.
 */
export async function computeWebhookSignature(
  rawBody: string | Uint8Array,
  webhookSecret: string,
): Promise<string> {
  if (!webhookSecret) {
    throw new XelorraWebhookSignatureError(
      "missing_webhook_secret",
      "webhookSecret is required to compute a webhook signature.",
    );
  }
  const digest = await computeHmacSha256Bytes(toBytes(rawBody), webhookSecret);
  return bytesToHex(digest);
}

/**
 * Verifies the `X-Xelorra-Signature` HMAC-SHA256 header against the raw request body
 * using constant-time comparison.
 *
 * Accepts raw 64-character hex digests as well as prefixed formats such as `sha256=<hex>`.
 * Returns `false` for missing, malformed, or tampered signatures without throwing.
 */
export async function verifyWebhookSignature(
  rawBody: string | Uint8Array,
  signatureHeader: string | null | undefined,
  webhookSecret: string,
): Promise<boolean> {
  if (!webhookSecret || !signatureHeader) {
    return false;
  }

  const providedHex = extractHexDigest(signatureHeader);
  if (!providedHex) {
    return false;
  }

  const providedBytes = hexToBytes(providedHex);
  if (!providedBytes || providedBytes.length !== 32) {
    return false;
  }

  const expectedBytes = await computeHmacSha256Bytes(toBytes(rawBody), webhookSecret);
  return constantTimeEqual(providedBytes, expectedBytes);
}

/**
 * Verifies the `X-Xelorra-Signature` header and parses the raw webhook body into a
 * strongly typed `XelorraWebhookEvent` (including `user.access_revoked`).
 *
 * Throws `XelorraWebhookSignatureError` if the secret is missing, the signature header
 * is missing or invalid, or the JSON body does not match the Xelorra webhook envelope.
 */
export async function parseWebhookEvent(
  rawBody: string | Uint8Array,
  signatureHeader: string | null | undefined,
  webhookSecret: string,
): Promise<XelorraWebhookEvent> {
  if (!webhookSecret) {
    throw new XelorraWebhookSignatureError(
      "missing_webhook_secret",
      "webhookSecret is required to verify Xelorra webhooks.",
    );
  }

  if (!signatureHeader || !signatureHeader.trim()) {
    throw new XelorraWebhookSignatureError(
      "missing_signature",
      "Missing X-Xelorra-Signature header.",
    );
  }

  const valid = await verifyWebhookSignature(rawBody, signatureHeader, webhookSecret);
  if (!valid) {
    throw new XelorraWebhookSignatureError(
      "invalid_signature",
      "X-Xelorra-Signature verification failed.",
    );
  }

  const bodyText =
    typeof rawBody === "string" ? rawBody : new TextDecoder().decode(rawBody);

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
