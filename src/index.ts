import { XelorraAuth as BaseXelorraAuth } from "./client.js";
import { XelorraAuthButton, XelorraProvider, useXelorraAuth } from "./react.js";

export type {
  PkcePair,
  XelorraAuthConfig,
  XelorraEnvironment,
  XelorraKycAssertion,
  XelorraTokenSet,
  XelorraUserClaims,
} from "./client.js";
export { createPkcePair, XelorraAuthError } from "./client.js";
export type { XelorraAuthButtonProps, XelorraContextValue } from "./react.js";
export { XelorraAuthButton, XelorraProvider, useXelorraAuth };

/**
 * XelorraAuth namespace combining the core PKCE client with `<XelorraAuth.Button />`
 * so developers can drop in branded sign-in buttons directly.
 */
export class XelorraAuth extends BaseXelorraAuth {
  static Button = XelorraAuthButton;
}
