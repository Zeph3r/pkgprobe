# pkgprobe API — Deployment Guide

## Overview

The pkgprobe API runs as a FastAPI service with three endpoint tiers:

- `/v1/analyze` (free) -- static analysis, no VM required
- `/v1/trace` (pro) -- VMware trace, requires VM host
- `/v1/auto-wrap` (paid) -- trace + PSADT wrapper + .intunewin packaging

## Quick start (analyze-only, no VM)

```bash
docker compose up -d
```

This starts the API with only `/v1/analyze` enabled. No VMware or trace infrastructure needed.

Test:

```bash
curl -F "installer=@setup.exe" http://localhost:8000/v1/analyze
curl http://localhost:8000/health
```

## Full deployment (with trace + auto-wrap)

### Host requirements

- VMware Workstation (or ESXi with vmrun CLI access)
- A prepared Windows VM snapshot with:
  - VMware Tools installed
  - ProcMon at `C:\trace\tools\procmon.exe`
  - IntuneWinAppUtil (for .intunewin packaging)
  - Clean snapshot named `TRACE_BASE` (or custom name)
- Docker for the API container

### Environment variables

Create a `.env` file:

```env
# Trace VM
TRACE_ENABLED=true
TRACE_VMX_PATH=C:\VMs\TraceVM\TraceVM.vmx
TRACE_SNAPSHOT_NAME=TRACE_BASE
TRACE_GUEST_USERNAME=Administrator
TRACE_GUEST_PASSWORD=your_password

# Stripe billing
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRO_PRODUCT_ID=prod_...
STRIPE_PRO_PRICE_ID=price_...
STRIPE_PRO_METERED_PRICE_ID=price_...
STRIPE_AUTOWRAP_PRODUCT_ID=prod_...
STRIPE_AUTOWRAP_PRICE_ID=price_...
STRIPE_AUTOWRAP_METERED_PRICE_ID=price_...
```

Run:

```bash
docker compose --env-file .env up -d
```

## Stripe setup

### 1. Create Products in Stripe Dashboard

- **pkgprobe Pro** -- for trace access
- **pkgprobe Auto-Wrap** -- for trace + wrapper + .intunewin

### 2. Create Prices for each product

For each product, create:
- A **recurring** price (monthly subscription)
- A **metered** price (per-use, reported via API)

Copy the price IDs into your environment variables.

### 3. Configure webhook endpoint

In Stripe Dashboard > Webhooks:

- URL: `https://api.pkgprobe.io/v1/stripe/webhook`
- Events:
  - `checkout.session.completed`
  - `customer.subscription.updated`
  - `customer.subscription.deleted`
  - `invoice.payment_failed`
  - `invoice.paid`

Copy the webhook signing secret to `STRIPE_WEBHOOK_SECRET`.

### 4. Configure Customer Portal

In Stripe Dashboard > Settings > Customer Portal:
- Enable subscription management
- Enable payment method updates
- Enable invoice history
- Set return URL to `https://pkgprobe.io/billing`

## Database

SQLite by default (stored in Docker volume at `/data/pkgprobe_api.db`).

For PostgreSQL, set:

```env
DATABASE_URL=postgresql://user:pass@host:5432/pkgprobe
```

Tables are auto-created on first startup.

## API endpoints

| Endpoint | Method | Tier | Description |
|----------|--------|------|-------------|
| `/health` | GET | public | Health check |
| `/v1/analyze` | POST | free | Static analysis |
| `/v1/trace` | POST | pro | VMware trace |
| `/v1/auto-wrap` | POST | auto_wrap | Trace + wrapper |
| `/v1/artifacts/{id}` | GET | auto_wrap | Download .intunewin |
| `/v1/billing/checkout` | POST | public | Create Stripe Checkout |
| `/v1/billing/status` | GET | any | Current tier + usage |
| `/v1/billing/portal` | GET | any | Stripe Customer Portal |
| `/v1/stripe/webhook` | POST | public | Stripe events |

All authenticated endpoints require `X-API-Key` header.

## Rate limits

| Tier | Requests per minute |
|------|-------------------|
| free | 60 |
| pro | 300 |
| auto_wrap | 600 |
