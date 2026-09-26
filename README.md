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

| `RSA_PRIVATE_KEY_HOURLY` | signing key for the MNQ Hourly product (PKCS#8 PEM, `\n` newlines) |
| `MAX_MACHINES_HOURLY` | optional, computers per Hourly licence (defaults to `MAX_MACHINES`) |

All of these are already set on the Railway service.

## Products

The server runs two completely separate licence systems:

| Product | Keys | Verify endpoint | Licence file |
|---|---|---|---|
| Flat to Funded | `FTF-…` | `POST /api/verify` | `/data/licences.json` |
| MNQ Hourly (FlatToFundedHourly) | `FTH-…` | `POST /api/hourly/verify` | `/data/licences-hourly.json` |

Each product signs with its own RSA key, so a key from one bot never unlocks
the other. The admin page has a tab for each product.

## Endpoints

- `POST /api/verify` — what the Flat to Funded strategy calls. Answers are RSA-signed.
- `POST /api/hourly/verify` — what the MNQ Hourly strategy calls.
- `GET /admin.html` — the admin page.
- `GET /health` — returns `{ok:true}` plus the licence count.

## Important

`RSA_PRIVATE_KEY` and `RSA_PRIVATE_KEY_HOURLY` are the only copies of the signing keys. If it is lost, every
licence already issued stops verifying and you must ship a new build of the
strategy with a new public key. Keep a backup somewhere safe.
