"""Flask integration example for xelorra-identity."""

import os
from flask import Flask, jsonify, redirect, request, session
from xelorra_identity import (
    HEADER_SIGNATURE,
    XELORRA_WEBHOOK_EVENTS,
    XelorraClient,
    XelorraWebhookSignatureError,
    parse_webhook_event,
)

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]

client = XelorraClient(
    client_id=os.environ["XELORRA_CLIENT_ID"],
    client_secret=os.getenv("XELORRA_CLIENT_SECRET"),
    redirect_uri=os.environ["XELORRA_REDIRECT_URI"],
)


@app.get("/auth/xelorra/login")
def login():
    url, pkce = client.build_sign_in_url()
    session["xelorra_state"] = pkce.state
    session["xelorra_verifier"] = pkce.code_verifier
    return redirect(url)


@app.get("/auth/xelorra/signup")
def signup():
    url, pkce = client.build_sign_up_url()
    session["xelorra_state"] = pkce.state
    session["xelorra_verifier"] = pkce.code_verifier
    return redirect(url)


@app.get("/auth/xelorra/callback")
def callback():
    code = request.args.get("code", "")
    state = request.args.get("state", "")
    expected = session.pop("xelorra_state", "")
    verifier = session.pop("xelorra_verifier", "")

    if not code or not expected or state != expected or not verifier:
        return jsonify({"error": "invalid_state"}), 400

    tokens = client.exchange_code(code, verifier)
    user = client.get_userinfo(tokens["access_token"])
    session["xelorra_access_token"] = tokens["access_token"]
    return jsonify({"user": user})


@app.post("/webhooks/xelorra")
def webhook():
    try:
        event = parse_webhook_event(
            raw_body=request.get_data(cache=False),
            signature_header=request.headers.get(HEADER_SIGNATURE),
            signing_secret=os.environ["XELORRA_WEBHOOK_SECRET"],
        )
    except XelorraWebhookSignatureError as exc:
        return jsonify({"error": exc.code, "message": str(exc)}), 401

    if event["type"] == XELORRA_WEBHOOK_EVENTS["USER_ACCESS_REVOKED"]:
        # Destroy local session and revoke stored tokens for event["data"]["sub"]
        pass

    return jsonify({"received": True, "event_type": event["type"]})
