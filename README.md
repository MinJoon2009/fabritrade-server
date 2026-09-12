# FabriTrade server (v2)

The real backend for FabriTrade. Pure Node.js — nothing to install.

- Accounts (the **first account registered becomes the platform owner**), listings, orders with escrow + commission,
  bulk price tiers, samples, RFQs & offers, boosts, messaging with AI scam-flagging, platform settings,
  and a private **owner API** used by the Manager site.
- Serves the full FabriTrade app from `public/`.
- Data is stored in `data.json` (swap for a database later; the API stays the same).

## Run locally
```
node server.js
```
Open http://localhost:3000

## Deploy
See **GO-LIVE-STEPS.md** (Render, free). `render.yaml` configures it automatically.

## Payments (next step)
Search `server.js` for the comments mentioning **Stripe** — those are the exact spots to charge the buyer,
hold escrow, release to the seller minus your commission, and charge boost fees.
