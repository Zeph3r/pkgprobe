"""
Database models for the pkgprobe production API.

SQLite by default (single-server launch); clean separation for
PostgreSQL migration later via DATABASE_URL env var.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker


class Base(DeclarativeBase):
    pass


class Customer(Base):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True, autoincrement=True)
    stripe_customer_id = Column(String(255), unique=True, nullable=True, index=True)
    email = Column(String(255), nullable=False, index=True)
    tier = Column(String(20), nullable=False, default="free")
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    active = Column(Boolean, nullable=False, default=True)

    api_keys = relationship("ApiKey", back_populates="customer")
    subscriptions = relationship("Subscription", back_populates="customer")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    key_prefix = Column(String(12), nullable=False)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    tier = Column(String(20), nullable=False, default="free")
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    revoked_at = Column(DateTime, nullable=True)

    customer = relationship("Customer", back_populates="api_keys")
    usage_records = relationship("UsageRecord", back_populates="api_key")

    @property
    def is_active(self) -> bool:
        return self.revoked_at is None and self.customer.active


class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    stripe_subscription_id = Column(String(255), unique=True, nullable=False, index=True)
    stripe_price_id = Column(String(255), nullable=True)
    status = Column(String(30), nullable=False, default="active")
    current_period_end = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))

    customer = relationship("Customer", back_populates="subscriptions")


class UsageRecord(Base):
    __tablename__ = "usage_records"

    id = Column(Integer, primary_key=True, autoincrement=True)
    api_key_id = Column(Integer, ForeignKey("api_keys.id"), nullable=False)
    endpoint = Column(String(50), nullable=False)
    timestamp = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    stripe_reported = Column(Boolean, nullable=False, default=False)

    api_key = relationship("ApiKey", back_populates="usage_records")


# ── Engine / session factory ──────────────────────────────────────────


def get_database_url() -> str:
    return os.environ.get("DATABASE_URL", "sqlite:///pkgprobe_api.db")


def create_db_engine(url: Optional[str] = None):
    db_url = url or get_database_url()
    connect_args = {}
    if db_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    return create_engine(db_url, connect_args=connect_args)


def init_db(engine=None):
    """Create all tables. Safe to call multiple times."""
    if engine is None:
        engine = create_db_engine()
    Base.metadata.create_all(engine)
    return engine


def get_session_factory(engine=None) -> sessionmaker:
    if engine is None:
        engine = create_db_engine()
    return sessionmaker(bind=engine, expire_on_commit=False)


# ── API key helpers ───────────────────────────────────────────────────


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.
    Returns (raw_key, key_hash, key_prefix).
    The raw_key is shown to the user once; only key_hash is stored.
    """
    raw_key = f"pk_{secrets.token_urlsafe(32)}"
    key_h = hash_api_key(raw_key)
    prefix = raw_key[:12]
    return raw_key, key_h, prefix


def create_customer_with_key(
    session: Session,
    *,
    email: str,
    tier: str = "free",
    stripe_customer_id: Optional[str] = None,
) -> tuple["Customer", str]:
    """
    Create a customer and their first API key.
    Returns (customer, raw_api_key).
    """
    customer = Customer(
        email=email,
        tier=tier,
        stripe_customer_id=stripe_customer_id,
    )
    session.add(customer)
    session.flush()

    raw_key, key_h, prefix = generate_api_key()
    api_key = ApiKey(
        key_hash=key_h,
        key_prefix=prefix,
        customer_id=customer.id,
        tier=tier,
    )
    session.add(api_key)
    session.commit()

    return customer, raw_key


def lookup_api_key(session: Session, raw_key: str) -> Optional[ApiKey]:
    """Look up an API key by its raw value. Returns None if not found or revoked."""
    key_h = hash_api_key(raw_key)
    api_key = session.query(ApiKey).filter(ApiKey.key_hash == key_h).first()
    if api_key is None:
        return None
    if not api_key.is_active:
        return None
    return api_key
