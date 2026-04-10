"""
Stripe product and price configuration for pkgprobe.

All IDs are loaded from environment variables so they can differ
between test-mode and live-mode without code changes.

Products and Prices are created in the Stripe Dashboard (or via
the setup script). This module just maps them to tiers.

Pricing model flexibility:
- Each paid tier has BOTH a subscription price and a metered price.
- Activate the model you want by setting the right price IDs.
- Subscription-only: set STRIPE_*_PRICE_ID, leave STRIPE_*_METERED_PRICE_ID empty.
- Usage-only: set STRIPE_*_METERED_PRICE_ID, leave STRIPE_*_PRICE_ID empty.
- Hybrid: set both (subscription base + metered overage).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class TierPricing:
    product_id: str = ""
    subscription_price_id: str = ""
    metered_price_id: str = ""


@dataclass(frozen=True)
class StripeConfig:
    secret_key: str = ""
    webhook_secret: str = ""
    success_url: str = "https://pkgprobe.io/billing/success?session_id={CHECKOUT_SESSION_ID}"
    cancel_url: str = "https://pkgprobe.io/billing/cancel"
    portal_return_url: str = "https://pkgprobe.io/billing"

    free: TierPricing = field(default_factory=TierPricing)
    pro: TierPricing = field(default_factory=TierPricing)
    auto_wrap: TierPricing = field(default_factory=TierPricing)


def load_stripe_config() -> StripeConfig:
    """Load Stripe configuration from environment variables."""
    return StripeConfig(
        secret_key=os.environ.get("STRIPE_SECRET_KEY", ""),
        webhook_secret=os.environ.get("STRIPE_WEBHOOK_SECRET", ""),
        success_url=os.environ.get(
            "STRIPE_SUCCESS_URL",
            "https://pkgprobe.io/billing/success?session_id={CHECKOUT_SESSION_ID}",
        ),
        cancel_url=os.environ.get(
            "STRIPE_CANCEL_URL",
            "https://pkgprobe.io/billing/cancel",
        ),
        portal_return_url=os.environ.get(
            "STRIPE_PORTAL_RETURN_URL",
            "https://pkgprobe.io/billing",
        ),
        free=TierPricing(
            product_id=os.environ.get("STRIPE_FREE_PRODUCT_ID", ""),
        ),
        pro=TierPricing(
            product_id=os.environ.get("STRIPE_PRO_PRODUCT_ID", ""),
            subscription_price_id=os.environ.get("STRIPE_PRO_PRICE_ID", ""),
            metered_price_id=os.environ.get("STRIPE_PRO_METERED_PRICE_ID", ""),
        ),
        auto_wrap=TierPricing(
            product_id=os.environ.get("STRIPE_AUTOWRAP_PRODUCT_ID", ""),
            subscription_price_id=os.environ.get("STRIPE_AUTOWRAP_PRICE_ID", ""),
            metered_price_id=os.environ.get("STRIPE_AUTOWRAP_METERED_PRICE_ID", ""),
        ),
    )


def get_tier_pricing(config: StripeConfig, tier: str) -> TierPricing:
    """Get pricing config for a given tier name."""
    return {
        "free": config.free,
        "pro": config.pro,
        "auto_wrap": config.auto_wrap,
    }.get(tier, config.free)


def tier_has_subscription(pricing: TierPricing) -> bool:
    return bool(pricing.subscription_price_id)


def tier_has_metered(pricing: TierPricing) -> bool:
    return bool(pricing.metered_price_id)
