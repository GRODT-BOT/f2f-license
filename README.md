# Flat to Funded — licence server

Zero dependencies. Node 18+. Licences are stored in `licences.json` on a
persistent volume, so there is no database to run.

## Environment variables

| Name | Value |
|---|---|
| `ADMIN_TOKEN` | password for the admin page |
| `RSA_PRIVATE_KEY` | PKCS#8 PEM, newlines written as `\n` |
| `DATA_DIR` | `/data` (must be a persistent volume) |
| `MAX_MACHINES` | `1` |
| `PRODUCT` | `FlatToFunded` |

All five are already set on the Railway service.

## Endpoints

- `POST /api/verify` — what the strategy calls. Answers are RSA-signed.
- `GET /admin.html` — the admin page.
- `GET /health` — returns `{ok:true}` plus the licence count.

## Important

`RSA_PRIVATE_KEY` is the only copy of the signing key. If it is lost, every
licence already issued stops verifying and you must ship a new build of the
strategy with a new public key. Keep a backup somewhere safe.
