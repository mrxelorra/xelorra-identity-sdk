"""FastAPI integration example for xelorra-identity."""

import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from xelorra_identity import (
    HEADER_SIGNATURE,
    XELORRA_SCOPES,
    XELORRA_WEBHOOK_EVENTS,
    XelorraClient,
    XelorraWebhookSignatureError,
    parse_webhook_event,
)

app = FastAPI()

client = XelorraClient(
    client_id=os.environ["XELORRA_CLIENT_ID"],
    client_secret=os.getenv("XELORRA_CLIENT_SECRET"),
    redirect_uri=os.environ["XELORRA_REDIRECT_URI"],
    scopes=[
        XELORRA_SCOPES["PROFILE_READ"],
        XELORRA_SCOPES["PASSPORT_READ"],
        XELORRA_SCOPES["EMAIL_READ"],
    ],
)

# Replace with Redis or an encrypted session store in production
pkce_store: dict[str, str] = {}


@app.get("/auth/xelorra/login")
def login() -> RedirectResponse:
    url, pkce = client.build_sign_in_url()
    pkce_store[pkce.state] = pkce.code_verifier
    return RedirectResponse(url)


@app.get("/auth/xelorra/signup")
def signup() -> RedirectResponse:
    url, pkce = client.build_sign_up_url()
    pkce_store[pkce.state] = pkce.code_verifier
    return RedirectResponse(url)


@app.get("/auth/xelorra/callback")
def callback(code: str, state: str) -> dict:
    verifier = pkce_store.pop(state, None)
    if not verifier:
        raise HTTPException(status_code=400, detail="Missing or expired PKCE state.")

    tokens = client.exchange_code(code, verifier)
    user = client.get_userinfo(tokens["access_token"])
    return {"user": user, "connected": True}


@app.post("/webhooks/xelorra")
async def webhook(request: Request) -> dict:
    raw_body = await request.body()
    signature = request.headers.get(HEADER_SIGNATURE)

    try:
        event = parse_webhook_event(
            raw_body=raw_body,
            signature_header=signature,
            signing_secret=os.environ["XELORRA_WEBHOOK_SECRET"],
        )
    except XelorraWebhookSignatureError as exc:
        raise HTTPException(status_code=401, detail=exc.code) from exc

    if event["type"] == XELORRA_WEBHOOK_EVENTS["USER_ACCESS_REVOKED"]:
        sub = event["data"].get("sub")
        # Invalidate local sessions and stored tokens for sub here
        print(f"Access revoked for subject: {sub}")

    return {"received": True, "event_type": event["type"]}
