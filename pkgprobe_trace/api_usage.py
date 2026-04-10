"""
Usage tracking middleware and Stripe metered billing reporter.

Records every paid endpoint call in the database.
Background task batch-reports unreported usage to Stripe.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

import stripe

from .api_db import ApiKey, Customer, Subscription, UsageRecord
from .stripe_config import StripeConfig, get_tier_pricing, tier_has_metered

logger = logging.getLogger(__name__)


def record_usage(db_session, *, api_key_id: int, endpoint: str) -> None:
    """Insert a usage record for a paid endpoint call."""
    record = UsageRecord(
        api_key_id=api_key_id,
        endpoint=endpoint,
        timestamp=datetime.now(timezone.utc),
        stripe_reported=False,
    )
    db_session.add(record)
    db_session.commit()


def report_unreported_usage(
    db_session,
    config: StripeConfig,
    *,
    batch_size: int = 100,
) -> int:
    """
    Batch-report unreported usage records to Stripe metered billing.

    For each unreported record, finds the customer's active subscription
    and reports usage via stripe.SubscriptionItem.create_usage_record().

    Returns the number of records successfully reported.
    """
    stripe.api_key = config.secret_key

    unreported = (
        db_session.query(UsageRecord)
        .filter(UsageRecord.stripe_reported == False)  # noqa: E712
        .limit(batch_size)
        .all()
    )

    if not unreported:
        return 0

    reported_count = 0

    for record in unreported:
        api_key = (
            db_session.query(ApiKey)
            .filter(ApiKey.id == record.api_key_id)
            .first()
        )
        if not api_key:
            record.stripe_reported = True
            continue

        customer = api_key.customer
        if not customer or not customer.stripe_customer_id:
            record.stripe_reported = True
            continue

        sub = (
            db_session.query(Subscription)
            .filter(
                Subscription.customer_id == customer.id,
                Subscription.status == "active",
            )
            .first()
        )
        if not sub:
            record.stripe_reported = True
            continue

        tier_pricing = get_tier_pricing(config, customer.tier)
        if not tier_has_metered(tier_pricing):
            record.stripe_reported = True
            continue

        try:
            stripe_sub = stripe.Subscription.retrieve(sub.stripe_subscription_id)

            metered_item = None
            for item in stripe_sub["items"]["data"]:
                if item["price"]["id"] == tier_pricing.metered_price_id:
                    metered_item = item
                    break

            if metered_item:
                stripe.SubscriptionItem.create_usage_record(
                    metered_item["id"],
                    quantity=1,
                    timestamp=int(record.timestamp.timestamp()),
                    action="increment",
                )
                reported_count += 1

            record.stripe_reported = True

        except stripe.StripeError as exc:
            logger.warning(
                "Failed to report usage for record %d: %s",
                record.id,
                exc,
            )

    db_session.commit()
    return reported_count


def get_usage_summary(
    db_session,
    *,
    customer_id: int,
    since: Optional[datetime] = None,
) -> dict[str, int]:
    """Get usage counts by endpoint for a customer."""
    query = (
        db_session.query(UsageRecord.endpoint, db_session.query(UsageRecord).count())
        .join(ApiKey, ApiKey.id == UsageRecord.api_key_id)
        .filter(ApiKey.customer_id == customer_id)
    )
    if since:
        query = query.filter(UsageRecord.timestamp >= since)

    from sqlalchemy import func
    results = (
        db_session.query(UsageRecord.endpoint, func.count(UsageRecord.id))
        .join(ApiKey, ApiKey.id == UsageRecord.api_key_id)
        .filter(ApiKey.customer_id == customer_id)
        .group_by(UsageRecord.endpoint)
    )
    if since:
        results = results.filter(UsageRecord.timestamp >= since)

    return {row[0]: row[1] for row in results.all()}
