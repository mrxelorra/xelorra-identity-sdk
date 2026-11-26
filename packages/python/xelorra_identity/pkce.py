"""RFC 7636 PKCE S256 verifier, unpadded challenge, and CSRF state generator."""

from dataclasses import dataclass
import base64
import hashlib
import secrets


@dataclass(frozen=True)
class PkcePair:
    code_verifier: str
    code_challenge: str
    code_challenge_method: str
    state: str


def base64url_encode(data: bytes) -> str:
    """Encode raw bytes to RFC 4648 base64url with no '=' padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_pkce_pair() -> PkcePair:
    """Generate a cryptographically secure PKCE S256 pair and CSRF state."""
    code_verifier = base64url_encode(secrets.token_bytes(48))
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64url_encode(digest)
    state = base64url_encode(secrets.token_bytes(18))

    return PkcePair(
        code_verifier=code_verifier,
        code_challenge=code_challenge,
        code_challenge_method="S256",
        state=state,
    )
