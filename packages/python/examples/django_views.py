"""Django views example for xelorra-identity."""

import os
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST
from xelorra_identity import (
    HEADER_SIGNATURE,
    XELORRA_WEBHOOK_EVENTS,
    XelorraClient,
    XelorraWebhookSignatureError,
    parse_webhook_event,
)


def _client() -> XelorraClient:
    return XelorraClient(
        client_id=os.environ["XELORRA_CLIENT_ID"],
        client_secret=os.getenv("XELORRA_CLIENT_SECRET"),
        redirect_uri=os.environ["XELORRA_REDIRECT_URI"],
    )


@require_GET
def xelorra_login(request: HttpRequest) -> HttpResponse:
    url, pkce = _client().build_sign_in_url()
    request.session["xelorra_pkce_state"] = pkce.state
    request.session["xelorra_pkce_verifier"] = pkce.code_verifier
    return redirect(url)


@require_GET
def xelorra_signup(request: HttpRequest) -> HttpResponse:
    url, pkce = _client().build_sign_up_url()
    request.session["xelorra_pkce_state"] = pkce.state
    request.session["xelorra_pkce_verifier"] = pkce.code_verifier
    return redirect(url)


@require_GET
def xelorra_callback(request: HttpRequest) -> HttpResponse:
    code = request.GET.get("code", "")
    state = request.GET.get("state", "")
    expected_state = request.session.pop("xelorra_pkce_state", "")
    verifier = request.session.pop("xelorra_pkce_verifier", "")

    if not code or not state or state != expected_state or not verifier:
        return HttpResponseBadRequest("Invalid OAuth state or missing code.")

    client = _client()
    tokens = client.exchange_code(code, verifier)
    user = client.get_userinfo(tokens["access_token"])

    request.session["xelorra_access_token"] = tokens["access_token"]
    request.session["xelorra_sub"] = user["sub"]
    return JsonResponse({"user": user})


@csrf_exempt
@require_POST
def xelorra_webhook(request: HttpRequest) -> JsonResponse:
    try:
        event = parse_webhook_event(
            raw_body=request.body,
            signature_header=request.headers.get(HEADER_SIGNATURE),
            signing_secret=os.environ["XELORRA_WEBHOOK_SECRET"],
        )
    except XelorraWebhookSignatureError as exc:
        return JsonResponse({"error": exc.code, "message": str(exc)}, status=401)

    if event["type"] == XELORRA_WEBHOOK_EVENTS["USER_ACCESS_REVOKED"]:
        # Revoke local Django sessions for event["data"]["sub"]
        pass

    return JsonResponse({"received": True, "event_type": event["type"]})
