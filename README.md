# MailGuard

**Instant email security intelligence — SPF, DKIM, DMARC, MTA-STS, BIMI, blacklists, and spoofability in one API call**

MailGuard is a self-hosted email security platform that analyzes a domain's complete authentication and deliverability setup. It gives you an actionable security grade (A–F), flags every misconfiguration, and produces compliance-ready PDF reports for PCI-DSS, SOC 2, and ISO 27001 audits. One POST request tells you whether a domain can be spoofed — and exactly how to fix it.

## Why MailGuard?

Checking SPF alone doesn't tell you if your domain is safe from spoofing. A valid SPF record with `p=none` DMARC means attackers can still impersonate you freely. A missing MTA-STS policy means your mail can be downgraded mid-transit. MailGuard runs all 10 checks together and gives you the one number that matters: is this domain spoofable, and why?

## What It Does

```
Request → FastAPI → API Key Auth → Rate Limiter
                          ↓
              analyze(domain)
                          ↓
     ┌──────────────────────────────────────────┐
     │          Parallel DNS + Security Checks   │
     │  SPF  │ DKIM  │ DMARC  │ MTA-STS         │
     │  BIMI │ MX Records │ STARTTLS             │
     │  DANE/TLSA │ Blacklists │ Spoofability     │
     └──────────────────────────────────────────┘
                          ↓
              Grade (A+ → F) + Spoofable: true/false
              Issues + Recommendations
```

## Quick Start

```bash
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload --port 8004
```

Analyze a domain immediately:

```bash
curl -X POST http://localhost:8004/analyze \
  -H "X-API-Key: mailg-free-your-key-here" \
  -H "Content-Type: application/json" \
  -d '{"domain": "yourdomain.com"}'
```

Interactive docs at **http://localhost:8004/docs**

## What You Get

| Feature | Description |
|---|---|
| 📋 **SPF** | Record presence, syntax, mechanism analysis, `+all` detection |
| 🔑 **DKIM** | Key presence, key length, algorithm strength |
| 🛡️ **DMARC** | Policy strictness (`none`/`quarantine`/`reject`), reporting config |
| 🔒 **MTA-STS** | Strict transport security policy presence and mode |
| 🏷️ **BIMI** | Brand indicator record and VMC certificate check |
| 📬 **MX Records** | Mail server presence and configuration |
| 🔐 **STARTTLS** | Opportunistic encryption support on mail servers |
| 🌐 **DANE / TLSA** | DNS-based authentication of named entities |
| 🚫 **Blacklists** | Multi-RBL check across major blocklists |
| 🎯 **Spoofability Score** | Overall impersonation risk based on all combined findings |

## Grading System

| Grade | Score | Meaning |
|---|---|---|
| A+ | 96–100 | All best practices in place — domain cannot be spoofed |
| A | 90–95 | Very strong configuration |
| B | 75–89 | Good, minor gaps |
| C | 60–74 | Moderate issues — spoofing risk present |
| D | 40–59 | Significant misconfigurations |
| F | 0–39 | Critical failures — domain is spoofable |

## What It Checks

| Check | Description |
|---|---|
| **SPF** | Record presence, syntax, mechanism analysis, `+all` detection |
| **DKIM** | Key presence, key length, algorithm strength |
| **DMARC** | Policy strictness (`none` / `quarantine` / `reject`), reporting config |
| **MTA-STS** | Strict transport security policy presence and validity |
| **BIMI** | Brand indicator record and VMC certificate |
| **MX Records** | Mail server presence and configuration |
| **STARTTLS** | Opportunistic encryption support on mail servers |
| **DANE / TLSA** | DNS-based authentication of named entities |
| **Blacklists** | Multi-RBL check across major blocklists |
| **Spoofability** | Overall spoofability risk based on combined findings |

## API Reference

### `POST /analyze` — Analyze a Domain

**Headers:** `X-API-Key: your-key` | `Content-Type: application/json`

**Request:**
```json
{"domain": "yourdomain.com"}
```

**Response:**
```json
{
  "domain": "yourdomain.com",
  "grade": "B",
  "score": 78,
  "issue_count": 2,
  "issues": [
    {
      "severity": "high",
      "check": "DMARC",
      "message": "DMARC policy is set to 'none' — emails are not rejected or quarantined",
      "recommendation": "Change p=none to p=quarantine or p=reject to enforce DMARC"
    },
    {
      "severity": "info",
      "check": "BIMI",
      "message": "No BIMI record found",
      "recommendation": "Add a BIMI record to display your logo in supported email clients"
    }
  ],
  "spf": {"record": "v=spf1 include:_spf.yourdomain.com -all", "valid": true, "all_mechanism": "-all"},
  "dmarc": {"record": "v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com", "policy": "none", "valid": true},
  "dkim": {"selectors_found": ["mail"], "valid": true},
  "mta_sts": {"policy_found": true, "mode": "enforce"},
  "blacklisted": false,
  "spoofable": true
}
```

### `POST /analyze/bulk` — Bulk Domain Scan (Pro)

```json
{"domains": ["yourdomain.com", "clientdomain.com", "example.org"]}
```

### `POST /monitor` — Continuous Monitoring (Pro)

```json
{
  "domain": "yourdomain.com",
  "check_interval_hours": 24,
  "alert_on_grade_drop": true,
  "slack_webhook": "https://hooks.slack.com/services/..."
}
```

### `POST /report/remediation` — PDF Remediation Guide (Free+)

### `POST /report/compliance` — PDF Compliance Report (Pro) — PCI-DSS, SOC 2, ISO 27001

```bash
curl -X POST http://localhost:8004/report/compliance \
  -H "X-API-Key: your-pro-key" \
  -H "Content-Type: application/json" \
  -d '{"domain": "yourdomain.com", "framework": "pci-dss"}' \
  --output compliance-report.pdf
```

### `GET /history` — Scan history per API key

### `GET /usage` — Scan count, grade distribution, usage stats

## API Tiers

| Endpoint | Free | Pro | Enterprise |
|---|---|---|---|
| `/analyze` | ✅ | ✅ | ✅ |
| `/analyze/bulk` | ❌ | ✅ | ✅ |
| `/report/remediation` | ✅ | ✅ | ✅ |
| `/report/compliance` | ❌ | ✅ | ✅ |
| `/monitor` | ❌ | ✅ | ✅ |
| `/schedule` | ❌ | ✅ | ✅ |
| Rate limit | 10/min | 60/min | Unlimited |

## Configuration

| Variable | Description |
|---|---|
| `ADMIN_SECRET` | Admin endpoint secret |
| `INITIAL_API_KEYS` | Comma-separated pre-loaded API keys |
| `DATA_DIR` | Persistent storage path (default: `./data`) |
| `SCAN_TIMEOUT` | Per-domain scan timeout in seconds (default: `15`) |
| `STRIPE_SECRET_KEY` | Enables Stripe billing (optional) |
| `TOYYIBPAY_SECRET_KEY` | Enables ToyyibPay billing — Malaysia (optional) |

## Project Structure

```
mailguard/
├── main.py                  # FastAPI app & all routes
├── config.py                # Settings (from .env)
├── auth.py                  # API key management
├── models.py                # Pydantic schemas
├── rate_limiter.py          # SlowAPI configuration
├── analytics.py             # Per-key usage tracking
├── scan_history.py          # Persistent scan history store
├── monitoring.py            # Background monitoring service
├── scheduler.py             # Scheduled scan service
├── portfolio.py             # Portfolio management
├── webhook_manager.py       # Webhook delivery and logging
├── alerts.py                # Alert delivery (Slack, PagerDuty, email)
├── pdf_report.py            # Security PDF report generator
├── remediation_report.py    # Remediation guide PDF generator
├── compliance_report.py     # PCI-DSS/SOC2/ISO27001 PDF generator
├── analyzer/
│   └── scorer.py            # Core email security analysis engine
├── stripe_billing.py        # Stripe integration
├── toyyibpay_billing.py     # ToyyibPay (Malaysia) integration
├── static/                  # Frontend dashboard
├── Dockerfile
└── docker-compose.yml
```

## Running with Docker

```bash
docker compose up -d
```

---

Built by **Abdul Quyyam** · MIT License
