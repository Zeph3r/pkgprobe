"""
Stripe webhook handler and billing endpoints for pkgprobe API.

Handles:
- POST /v1/billing/checkout  -- create Checkout session
- GET  /v1/billing/status    -- current tier + usage
- GET  /v1/billing/portal    -- Stripe Customer Portal redirect
- POST /v1/stripe/webhook    -- Stripe event handler
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request

from .api_db import (
    ApiKey,
    Customer,
    Subscription,
    UsageRecord,
    create_customer_with_key,
    generate_api_key,
    hash_api_key,
    lookup_api_key,
)
from .stripe_config import StripeConfig, get_tier_pricing, load_stripe_config

logger = logging.getLogger(__name__)

router = APIRouter()


def _get_config() -> StripeConfig:
    return load_stripe_config()


# ── POST /v1/billing/checkout ─────────────────────────────────────────


@router.post("/v1/billing/checkout")
async def create_checkout(
    request: Request,
    config: StripeConfig = Depends(_get_config),
):
    """
    Create a Stripe Checkout Session for upgrading to pro or auto_wrap tier.

    Body: { "tier": "pro" | "auto_wrap", "email": "user@example.com" }
    Returns: { "checkout_url": "https://checkout.stripe.com/..." }
    """
    body = await request.json()
    tier = body.get("tier", "pro")
    email = body.get("email", "")

    if tier not in ("pro", "auto_wrap"):
        raise HTTPException(status_code=400, detail="tier must be 'pro' or 'auto_wrap'")

    pricing = get_tier_pricing(config, tier)
    if not pricing.subscription_price_id:
        raise HTTPException(
            status_code=503,
            detail=f"Subscription pricing not configured for tier: {tier}",
        )

    stripe.api_key = config.secret_key

    line_items = [{"price": pricing.subscription_price_id, "quantity": 1}]
    if pricing.metered_price_id:
        line_items.append({"price": pricing.metered_price_id})

    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            line_items=line_items,
            success_url=config.success_url,
            cancel_url=config.cancel_url,
            customer_email=email or None,
            metadata={"pkgprobe_tier": tier},
        )
    except stripe.StripeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {"checkout_url": session.url}


# ── GET /v1/billing/status ────────────────────────────────────────────


@router.get("/v1/billing/status")
async def billing_status(
    request: Request,
):
    """
    Return current tier, subscription status, and usage count for the
    authenticated customer. Requires X-API-Key header.
    """
    api_key_header = request.headers.get("X-API-Key", "")
    if not api_key_header:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    db_session = request.state.db_session
    api_key = lookup_api_key(db_session, api_key_header)
    if api_key is None:
        raise HTTPException(status_code=401, detail="Invalid API key")

    customer = api_key.customer
    sub = (
        db_session.query(Subscription)
        .filter(Subscription.customer_id == customer.id, Subscription.status == "active")
        .first()
    )

    usage_count = (
        db_session.query(UsageRecord)
        .filter(UsageRecord.api_key_id == api_key.id)
        .count()
    )

    return {
        "email": customer.email,
        "tier": customer.tier,
        "subscription_status": sub.status if sub else "none",
        "current_period_end": sub.current_period_end.isoformat() if sub and sub.current_period_end else None,
        "usage_this_period": usage_count,
    }


# ── GET /v1/billing/portal ────────────────────────────────────────────


@router.get("/v1/billing/portal")
async def billing_portal(
    request: Request,
    config: StripeConfig = Depends(_get_config),
):
    """
    Create a Stripe Customer Portal session for the authenticated customer.
    Returns { "portal_url": "..." }.
    """
    api_key_header = request.headers.get("X-API-Key", "")
    if not api_key_header:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    db_session = request.state.db_session
    api_key = lookup_api_key(db_session, api_key_header)
    if api_key is None:
        raise HTTPException(status_code=401, detail="Invalid API key")

    customer = api_key.customer
    if not customer.stripe_customer_id:
        raise HTTPException(
            status_code=400,
            detail="No Stripe customer linked to this account",
        )

    stripe.api_key = config.secret_key

    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=customer.stripe_customer_id,
            return_url=config.portal_return_url,
        )
    except stripe.StripeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {"portal_url": portal_session.url}


# ── POST /v1/stripe/webhook ──────────────────────────────────────────


@router.post("/v1/stripe/webhook")
async def stripe_webhook(
    request: Request,
    config: StripeConfig = Depends(_get_config),
):
    """
    Handle Stripe webhook events.

    Verifies signature, then dispatches to handler by event type.
    """
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, config.webhook_secret,
        )
    except stripe.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db_session = request.state.db_session

    handler = _EVENT_HANDLERS.get(event["type"])
    if handler:
        try:
            handler(event, db_session, config)
        except Exception:
            logger.exception("Webhook handler error for %s", event["type"])
            raise HTTPException(status_code=500, detail="Webhook processing failed")

    return {"received": True}


# ── Event handlers ────────────────────────────────────────────────────


def _handle_checkout_completed(event: dict, db_session, config: StripeConfig):
    """
    Customer completed Checkout. Create/upgrade customer + provision API key.
    """
    session = event["data"]["object"]
    stripe_customer_id = session.get("customer")
    email = session.get("customer_email") or session.get("customer_details", {}).get("email", "")
    tier = session.get("metadata", {}).get("pkgprobe_tier", "pro")
    subscription_id = session.get("subscription")

    existing = (
        db_session.query(Customer)
        .filter(Customer.stripe_customer_id == stripe_customer_id)
        .first()
    )

    if existing:
        existing.tier = tier
        for key in existing.api_keys:
            if key.revoked_at is None:
                key.tier = tier
        db_session.flush()
        customer = existing
    else:
        customer, _raw_key = create_customer_with_key(
            db_session,
            email=email,
            tier=tier,
            stripe_customer_id=stripe_customer_id,
        )
        logger.info("Provisioned new customer %s (tier=%s)", email, tier)

    if subscription_id:
        sub = Subscription(
            customer_id=customer.id,
            stripe_subscription_id=subscription_id,
            status="active",
        )
        db_session.add(sub)

    db_session.commit()


def _handle_subscription_updated(event: dict, db_session, config: StripeConfig):
    """Subscription changed (upgrade/downgrade/renewal)."""
    sub_data = event["data"]["object"]
    sub_id = sub_data["id"]
    status = sub_data.get("status", "active")
    period_end = sub_data.get("current_period_end")

    sub = (
        db_session.query(Subscription)
        .filter(Subscription.stripe_subscription_id == sub_id)
        .first()
    )
    if sub:
        sub.status = status
        if period_end:
            sub.current_period_end = datetime.fromtimestamp(period_end, tz=timezone.utc)
        db_session.commit()


def _handle_subscription_deleted(event: dict, db_session, config: StripeConfig):
    """Subscription cancelled. Downgrade customer to free tier."""
    sub_data = event["data"]["object"]
    sub_id = sub_data["id"]

    sub = (
        db_session.query(Subscription)
        .filter(Subscription.stripe_subscription_id == sub_id)
        .first()
    )
    if sub:
        sub.status = "cancelled"
        customer = sub.customer
        customer.tier = "free"
        for key in customer.api_keys:
            if key.revoked_at is None:
                key.tier = "free"
        db_session.commit()
        logger.info("Downgraded customer %s to free (subscription cancelled)", customer.email)


def _handle_invoice_payment_failed(event: dict, db_session, config: StripeConfig):
    """Payment failed. Flag the customer for follow-up."""
    invoice = event["data"]["object"]
    stripe_customer_id = invoice.get("customer")

    customer = (
        db_session.query(Customer)
        .filter(Customer.stripe_customer_id == stripe_customer_id)
        .first()
    )
    if customer:
        logger.warning("Payment failed for customer %s", customer.email)


def _handle_invoice_paid(event: dict, db_session, config: StripeConfig):
    """Payment succeeded. Clear any failure flags."""
    pass


_EVENT_HANDLERS = {
    "checkout.session.completed": _handle_checkout_completed,
    "customer.subscription.updated": _handle_subscription_updated,
    "customer.subscription.deleted": _handle_subscription_deleted,
    "invoice.payment_failed": _handle_invoice_payment_failed,
    "invoice.paid": _handle_invoice_paid,
}
