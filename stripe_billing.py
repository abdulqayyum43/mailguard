"""
Stripe billing integration for SSLGuard.
Handles checkout session creation and webhook event processing.

Required env vars:
    STRIPE_SECRET_KEY          – your Stripe secret key (sk_live_... or sk_test_...)
    STRIPE_WEBHOOK_SECRET      – from `stripe listen` or Stripe dashboard
    STRIPE_PRO_PRICE_ID        – Price ID for $29/mo Pro plan
    STRIPE_ENTERPRISE_PRICE_ID – Price ID for $99/mo Enterprise plan
"""

import stripe
import hashlib
import hmac
import time
import logging
from fastapi import Request
from config import settings

logger = logging.getLogger("sslguard.billing")


def _get_client() -> stripe.StripeClient | None:
    if not settings.stripe_secret_key:
        return None
    return stripe.StripeClient(settings.stripe_secret_key)


def create_checkout_session(plan: str, customer_email: str | None = None) -> dict:
    """
    Create a Stripe Checkout session for the given plan.
    Returns {"url": "https://checkout.stripe.com/..."} or {"error": "..."}
    """
    client = _get_client()
    if not client:
        return {"error": "Stripe is not configured. Set STRIPE_SECRET_KEY in .env"}

    price_map = {
        "pro": settings.stripe_pro_price_id,
        "enterprise": settings.stripe_enterprise_price_id,
    }
    price_id = price_map.get(plan)
    if not price_id:
        return {"error": f"Unknown plan '{plan}'. Use 'pro' or 'enterprise'."}
    if not price_id:
        return {"error": f"Price ID for '{plan}' not configured. Set STRIPE_PRO_PRICE_ID or STRIPE_ENTERPRISE_PRICE_ID."}

    params: dict = {
        "mode": "subscription",
        "line_items": [{"price": price_id, "quantity": 1}],
        "success_url": f"{settings.stripe_success_url}?session_id={{CHECKOUT_SESSION_ID}}&plan={plan}",
        "cancel_url": settings.stripe_cancel_url,
        "allow_promotion_codes": True,
        "billing_address_collection": "auto",
        "metadata": {"plan": plan},
    }
    if customer_email:
        params["customer_email"] = customer_email

    try:
        session = client.checkout.sessions.create(params)
        return {"url": session.url, "session_id": session.id}
    except stripe.StripeError as exc:
        logger.error("Stripe checkout error: %s", exc)
        return {"error": str(exc)}


def verify_webhook(payload: bytes, sig_header: str) -> stripe.Event | None:
    """Verify Stripe webhook signature and return parsed event."""
    if not settings.stripe_webhook_secret:
        logger.warning("STRIPE_WEBHOOK_SECRET not set — skipping signature verification")
        return None
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.stripe_webhook_secret
        )
        return event
    except (stripe.SignatureVerificationError, ValueError) as exc:
        logger.error("Webhook verification failed: %s", exc)
        return None


def get_plan_from_event(event: stripe.Event) -> tuple[str, str]:
    """
    Extract (customer_email, plan) from a checkout.session.completed event.
    Returns ("", "") if not determinable.
    """
    if event["type"] != "checkout.session.completed":
        return "", ""

    session = event["data"]["object"]
    plan = session.get("metadata", {}).get("plan", "")
    email = session.get("customer_details", {}).get("email", "")
    return email, plan
