from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Depends, Request, status, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
import asyncio

from config import settings
from auth import APIKeyStore, require_api_key, require_admin
from rate_limiter import limiter, get_tier_limit, set_key_store
from analytics import UsageTracker
from scan_history import ScanHistoryStore
from pdf_report import generate_report
from compliance_report import generate_compliance_report
from remediation_pdf import generate_remediation_report
from webhook_manager import WebhookManager
from monitoring import MonitoringService, MonitoredDomain
from scheduler import SchedulerService, ScheduledJob
from portfolio import PortfolioStore, PortfolioEntry
from waitlist import WaitlistStore
from toyyibpay_billing import create_bill, verify_callback as toyyibpay_verify
from stripe_billing import create_checkout_session, verify_webhook, get_plan_from_event
from models import (
    AnalyzeRequest, AnalyzeResponse,
    BulkAnalyzeRequest, BulkAnalyzeResponse,
    AddMonitorRequest, AddScheduleRequest, AddPortfolioRequest,
    ReportRequest, ComplianceReportRequest,
    WaitlistRequest, CheckoutRequest,
    KeyProvisionRequest, KeyProvisionResponse,
)
from analyzer.scorer import analyze_email


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http_client = httpx.AsyncClient(
        timeout=settings.scan_timeout, follow_redirects=True,
        headers={"User-Agent": "MailGuard-API/1.0"},
    )
    app.state.key_store = APIKeyStore(set(settings.initial_api_keys.split(",")))
    set_key_store(app.state.key_store)
    app.state.tracker = UsageTracker()
    app.state.history = ScanHistoryStore()
    app.state.monitor = MonitoringService()
    app.state.scheduler = SchedulerService()
    app.state.portfolio = PortfolioStore()
    app.state.webhook_mgr = WebhookManager()
    app.state.waitlist = WaitlistStore(data_dir=settings.data_dir)

    monitor_task = asyncio.create_task(app.state.monitor.run_loop(app))
    scheduler_task = asyncio.create_task(app.state.scheduler.run_loop(app))
    yield
    monitor_task.cancel()
    scheduler_task.cancel()
    await app.state.http_client.aclose()


app = FastAPI(
    title="MailGuard — Email Security Analyzer API",
    description=(
        "Complete email security platform: SPF, DKIM, DMARC, MTA-STS, BIMI, "
        "MX/STARTTLS analysis, blacklist checking, DANE/TLSA, spoofability assessment, "
        "compliance reports (PCI-DSS/SOC2/ISO27001), monitoring with alerts, and more."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"error": "Validation error", "detail": str(exc.errors()), "code": 422})


def _pro_only(store: APIKeyStore, api_key: str, feature: str):
    if store.get_tier(api_key) == "free":
        return JSONResponse(status_code=403, content={"error": f"{feature} requires Pro or Enterprise tier.", "code": 403})
    return None


# ── Pages ───────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def marketing_page():
    return FileResponse("static/index.html")

@app.get("/demo", include_in_schema=False)
async def demo_page():
    return FileResponse("static/demo.html")

@app.get("/admin", include_in_schema=False)
async def admin_page():
    return FileResponse("static/admin.html")

@app.get("/health", tags=["System"])
async def health():
    return {"status": "ok", "version": "1.0.0", "service": "MailGuard API"}


# ── Core Analysis ───────────────────────────────────────────────────────────

@app.post("/analyze", response_model=AnalyzeResponse, tags=["Email Analysis"])
@limiter.limit(get_tier_limit)
async def analyze_domain(request: Request, body: AnalyzeRequest, api_key: str = Depends(require_api_key)):
    try:
        result = await analyze_email(domain=body.domain, http_client=request.app.state.http_client, timeout=settings.scan_timeout)
    except ConnectionError as exc:
        return JSONResponse(status_code=502, content={"error": "Connection failed", "detail": str(exc), "code": 502})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": "Scan error", "detail": str(exc), "code": 500})

    request.app.state.tracker.record(api_key=api_key, hostname=body.domain, grade=result["grade"], score=result["score"], issue_count=result["issue_count"])
    request.app.state.history.record(api_key=api_key, hostname=body.domain, port=0, grade=result["grade"], score=result["score"], issue_count=result["issue_count"], top_issues=result["issues"][:3])

    if body.webhook_url and result["issue_count"] > 0:
        await request.app.state.webhook_mgr.send(
            http_client=request.app.state.http_client, api_key=api_key,
            webhook_url=body.webhook_url, event="email_issues_detected",
            payload={"domain": body.domain, "grade": result["grade"], "score": result["score"], "issues": result["issues"]},
        )
    return result


@app.post("/analyze/bulk", response_model=BulkAnalyzeResponse, tags=["Email Analysis"])
@limiter.limit(get_tier_limit)
async def analyze_bulk(request: Request, body: BulkAnalyzeRequest, api_key: str = Depends(require_api_key)):
    guard = _pro_only(request.app.state.key_store, api_key, "Bulk analysis")
    if guard: return guard
    results = []
    for domain in body.domains:
        try:
            result = await analyze_email(domain=domain, http_client=request.app.state.http_client, timeout=settings.scan_timeout)
            request.app.state.tracker.record(api_key=api_key, hostname=domain, grade=result["grade"], score=result["score"], issue_count=result["issue_count"])
            results.append(result)
        except Exception as exc:
            results.append({"domain": domain, "error": str(exc), "grade": "F", "score": 0})
    return {"total": len(results), "results": results}


# ── Reports ─────────────────────────────────────────────────────────────────

@app.post("/report", tags=["Reports"])
@limiter.limit(get_tier_limit)
async def pdf_report(request: Request, body: ReportRequest, api_key: str = Depends(require_api_key)):
    guard = _pro_only(request.app.state.key_store, api_key, "PDF reports")
    if guard: return guard
    try:
        result = await analyze_email(domain=body.domain, http_client=request.app.state.http_client, timeout=settings.scan_timeout)
    except ConnectionError as exc:
        return JSONResponse(status_code=502, content={"error": str(exc), "code": 502})
    pdf = generate_report(scan_result=result)
    safe = body.domain.replace(".", "-")
    return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="mailguard-{safe}.pdf"'})


@app.post("/report/remediation", tags=["Reports"])
@limiter.limit(get_tier_limit)
async def remediation_report(request: Request, body: ReportRequest, api_key: str = Depends(require_api_key)):
    """
    Generate an authenticated Remediation & Fix Guide PDF.

    Educates the user on each discovered issue (what it is, why it matters)
    and provides exact step-by-step DNS/config fix instructions tailored to
    the scanned domain. Includes a report ID, SHA-256 fingerprint, and
    certified footer on every page — suitable for developers and auditors.
    """
    try:
        result = await analyze_email(domain=body.domain, http_client=request.app.state.http_client, timeout=settings.scan_timeout)
    except ConnectionError as exc:
        return JSONResponse(status_code=502, content={"error": str(exc), "code": 502})
    pdf = generate_remediation_report(scan_result=result)
    safe = body.domain.replace(".", "-")
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="mailguard-remediation-{safe}.pdf"'},
    )


@app.post("/report/compliance", tags=["Reports"])
@limiter.limit(get_tier_limit)
async def compliance_report(request: Request, body: ComplianceReportRequest, api_key: str = Depends(require_api_key)):
    guard = _pro_only(request.app.state.key_store, api_key, "Compliance reports")
    if guard: return guard
    try:
        result = await analyze_email(domain=body.domain, http_client=request.app.state.http_client, timeout=settings.scan_timeout)
    except ConnectionError as exc:
        return JSONResponse(status_code=502, content={"error": str(exc), "code": 502})
    pdf = generate_compliance_report(scan_result=result, framework=body.framework)
    safe = body.domain.replace(".", "-")
    return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="mailguard-{body.framework}-{safe}.pdf"'})


# ── Monitoring ──────────────────────────────────────────────────────────────

@app.post("/monitor", tags=["Monitoring"])
@limiter.limit(get_tier_limit)
async def add_monitor(request: Request, body: AddMonitorRequest, api_key: str = Depends(require_api_key)):
    guard = _pro_only(request.app.state.key_store, api_key, "Monitoring")
    if guard: return guard
    domain = MonitoredDomain(api_key=api_key, domain=body.domain, check_interval_hours=body.check_interval_hours,
        alert_on_grade_drop=body.alert_on_grade_drop, alert_on_blacklist=body.alert_on_blacklist,
        alert_on_spoofability_change=body.alert_on_spoofability_change,
        slack_webhook=body.slack_webhook, pagerduty_key=body.pagerduty_key,
        alert_email=body.alert_email, webhook_url=body.webhook_url)
    added = request.app.state.monitor.add(domain)
    return {"message": "Domain added to monitoring.", "monitor": added.to_dict()}

@app.get("/monitor", tags=["Monitoring"])
async def list_monitors(request: Request, api_key: str = Depends(require_api_key)):
    return {"monitors": request.app.state.monitor.list_domains(api_key)}

@app.delete("/monitor/{monitor_id}", tags=["Monitoring"])
async def remove_monitor(monitor_id: str, request: Request, api_key: str = Depends(require_api_key)):
    removed = request.app.state.monitor.remove(api_key, monitor_id)
    if not removed: return JSONResponse(status_code=404, content={"error": "Monitor not found", "code": 404})
    return {"message": f"Monitor {monitor_id} removed."}

@app.post("/monitor/{monitor_id}/check", tags=["Monitoring"])
@limiter.limit(get_tier_limit)
async def force_check(monitor_id: str, request: Request, api_key: str = Depends(require_api_key)):
    domain = request.app.state.monitor.get_domain(api_key, monitor_id)
    if not domain: return JSONResponse(status_code=404, content={"error": "Monitor not found", "code": 404})
    try:
        result = await analyze_email(domain=domain.domain, http_client=request.app.state.http_client, timeout=settings.scan_timeout)
        from datetime import datetime, UTC
        domain.last_checked = datetime.now(UTC)
        domain.last_grade = result["grade"]
        domain.last_score = result["score"]
        domain.last_result = result
        return {"monitor": domain.to_dict(), "result": result}
    except Exception as exc:
        return JSONResponse(status_code=502, content={"error": str(exc), "code": 502})


# ── Scheduler ───────────────────────────────────────────────────────────────

@app.post("/schedule", tags=["Scheduler"])
@limiter.limit(get_tier_limit)
async def add_schedule(request: Request, body: AddScheduleRequest, api_key: str = Depends(require_api_key)):
    guard = _pro_only(request.app.state.key_store, api_key, "Scheduled scans")
    if guard: return guard
    job = ScheduledJob(api_key=api_key, domain=body.domain, frequency=body.frequency, label=body.label)
    added = request.app.state.scheduler.add(job)
    return {"message": "Scheduled scan created.", "job": added.to_dict()}

@app.get("/schedule", tags=["Scheduler"])
async def list_schedules(request: Request, api_key: str = Depends(require_api_key)):
    return {"jobs": request.app.state.scheduler.list_jobs(api_key)}

@app.delete("/schedule/{job_id}", tags=["Scheduler"])
async def delete_schedule(job_id: str, request: Request, api_key: str = Depends(require_api_key)):
    removed = request.app.state.scheduler.remove(api_key, job_id)
    if not removed: return JSONResponse(status_code=404, content={"error": "Job not found", "code": 404})
    return {"message": f"Schedule {job_id} deleted."}

@app.get("/schedule/{job_id}", tags=["Scheduler"])
async def get_schedule(job_id: str, request: Request, api_key: str = Depends(require_api_key)):
    job = request.app.state.scheduler.get_job(api_key, job_id)
    if not job: return JSONResponse(status_code=404, content={"error": "Job not found", "code": 404})
    return job.to_dict()


# ── Portfolio ───────────────────────────────────────────────────────────────

@app.post("/portfolio", tags=["Portfolio"])
@limiter.limit(get_tier_limit)
async def add_portfolio(request: Request, body: AddPortfolioRequest, api_key: str = Depends(require_api_key)):
    guard = _pro_only(request.app.state.key_store, api_key, "Portfolio management")
    if guard: return guard
    entry = PortfolioEntry(api_key=api_key, domain=body.domain, label=body.label)
    added = request.app.state.portfolio.add(entry)
    return {"message": "Domain added to portfolio.", "entry": added.to_dict()}

@app.get("/portfolio", tags=["Portfolio"])
async def get_portfolio(request: Request, api_key: str = Depends(require_api_key)):
    guard = _pro_only(request.app.state.key_store, api_key, "Portfolio management")
    if guard: return guard
    return request.app.state.portfolio.summary(api_key)

@app.post("/portfolio/refresh", tags=["Portfolio"])
@limiter.limit(get_tier_limit)
async def refresh_portfolio(request: Request, api_key: str = Depends(require_api_key)):
    guard = _pro_only(request.app.state.key_store, api_key, "Portfolio management")
    if guard: return guard
    entries = request.app.state.portfolio.get(api_key)
    refreshed = []
    for entry in entries:
        try:
            result = await analyze_email(domain=entry.domain, http_client=request.app.state.http_client, timeout=settings.scan_timeout)
            entry.update(result)
            refreshed.append({"domain": entry.domain, "grade": entry.last_grade, "score": entry.last_score})
        except Exception as exc:
            refreshed.append({"domain": entry.domain, "error": str(exc)})
    return {"refreshed": len(refreshed), "results": refreshed}

@app.delete("/portfolio/{entry_id}", tags=["Portfolio"])
async def remove_portfolio(entry_id: str, request: Request, api_key: str = Depends(require_api_key)):
    removed = request.app.state.portfolio.remove(api_key, entry_id)
    if not removed: return JSONResponse(status_code=404, content={"error": "Entry not found", "code": 404})
    return {"message": f"Portfolio entry {entry_id} removed."}


# ── History / Usage ─────────────────────────────────────────────────────────

@app.get("/history", tags=["Analytics"])
async def scan_history(request: Request, api_key: str = Depends(require_api_key), limit: int = Query(20, ge=1, le=100)):
    return {"scans": request.app.state.history.get_history(api_key, limit), "stats": request.app.state.history.get_stats(api_key)}

@app.delete("/history", tags=["Analytics"])
async def clear_history(request: Request, api_key: str = Depends(require_api_key)):
    request.app.state.history.clear(api_key)
    return {"message": "Scan history cleared."}

@app.get("/usage", tags=["Analytics"])
async def my_usage(request: Request, api_key: str = Depends(require_api_key)):
    return request.app.state.tracker.get_stats(api_key)

@app.get("/webhooks/logs", tags=["Webhooks"])
async def webhook_logs(request: Request, api_key: str = Depends(require_api_key), limit: int = Query(50, ge=1, le=200)):
    mgr: WebhookManager = request.app.state.webhook_mgr
    return {"logs": mgr.get_logs(api_key, limit), "stats": mgr.get_stats(api_key)}


# ── Admin ───────────────────────────────────────────────────────────────────

@app.get("/admin/usage", tags=["Admin"])
async def all_usage(request: Request, _: str = Depends(require_admin)):
    return request.app.state.tracker.get_all_stats()

@app.get("/admin/monitor", tags=["Admin"])
async def admin_monitor_summary(request: Request, _: str = Depends(require_admin)):
    return request.app.state.monitor.admin_summary()

@app.get("/admin/keys", tags=["Admin"])
async def list_keys(_: str = Depends(require_admin), request: Request = None):
    return {"keys": request.app.state.key_store.all_keys()}

@app.post("/admin/keys", response_model=KeyProvisionResponse, tags=["Admin"])
async def provision_key(body: KeyProvisionRequest, _: str = Depends(require_admin), request: Request = None):
    request.app.state.key_store.add_key(body.new_key, body.tier, body.expires_at)
    return KeyProvisionResponse(key=body.new_key, tier=body.tier, message="API key provisioned.")

@app.delete("/admin/keys/{key}", tags=["Admin"])
async def revoke_key(key: str, _: str = Depends(require_admin), request: Request = None):
    revoked = request.app.state.key_store.revoke_key(key)
    if not revoked: return JSONResponse(status_code=404, content={"error": "Key not found", "code": 404})
    return {"message": f"Key '{key[:8]}...' revoked."}

@app.get("/admin/scheduler", tags=["Admin"])
async def admin_scheduler(request: Request, _: str = Depends(require_admin)):
    return {"jobs": request.app.state.scheduler.all_jobs()}

@app.get("/admin/waitlist", tags=["Admin"])
async def admin_waitlist(request: Request, _: str = Depends(require_admin)):
    wl: WaitlistStore = request.app.state.waitlist
    return {"total": wl.count(), "entries": wl.all()}

@app.delete("/admin/waitlist/{entry_id}", tags=["Admin"])
async def admin_delete_waitlist(entry_id: str, request: Request, _: str = Depends(require_admin)):
    removed = request.app.state.waitlist.remove(entry_id)
    if not removed: return JSONResponse(status_code=404, content={"error": "Entry not found", "code": 404})
    return {"message": f"Entry {entry_id} removed."}

@app.get("/admin/system", tags=["Admin"])
async def admin_system(request: Request, _: str = Depends(require_admin)):
    import platform, sys
    return {
        "version": "1.0.0", "python": sys.version, "platform": platform.platform(),
        "monitors": len(request.app.state.monitor.admin_summary().get("domains", [])),
        "scheduler_jobs": len(request.app.state.scheduler.all_jobs()),
        "waitlist_count": request.app.state.waitlist.count(),
        "api_key_count": len(request.app.state.key_store.all_keys()),
    }


# ── Waitlist ────────────────────────────────────────────────────────────────

@app.post("/waitlist", tags=["Waitlist"])
async def join_waitlist(body: WaitlistRequest, request: Request):
    entry = request.app.state.waitlist.add(email=body.email, name=body.name, plan=body.plan, company=body.company)
    return {"message": "You're on the list! We'll be in touch.", "id": entry.id}


# ── Billing ─────────────────────────────────────────────────────────────────

@app.post("/billing/checkout", tags=["Billing"])
async def billing_checkout(body: CheckoutRequest):
    result = create_bill(plan=body.plan, buyer_name=body.name or "Customer", buyer_email=body.email or "", buyer_phone=body.phone or "0123456789")
    if "error" in result: return JSONResponse(status_code=400, content={"error": result["error"], "code": 400})
    return result

@app.post("/billing/toyyibpay/callback", include_in_schema=False)
async def toyyibpay_callback(request: Request):
    form = await request.form()
    status_val = form.get("status", "")
    ref = form.get("order_id", "")
    bill_code = form.get("billcode", "")
    txn_id = form.get("transaction_id", "")
    if toyyibpay_verify(status_val):
        plan = "enterprise" if ref.startswith("mailg-ent") else "pro"
        import secrets as _s
        new_key = f"mailg-{plan[:3]}-{_s.token_hex(16)}"
        request.app.state.key_store.add_key(new_key, tier=plan, expires_at=None)
        request.app.state.waitlist.add(email=f"{txn_id}@toyyibpay", name="ToyyibPay payment", plan=plan, company=f"ref:{ref} bill:{bill_code}")
    return {"status": "ok"}

@app.get("/billing/success", include_in_schema=False)
async def billing_success(plan: str = "pro", ref: str = "", session_id: str = ""):
    ref_display = ref or session_id
    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"/><title>Payment Successful – MailGuard</title>
<style>*{{margin:0;padding:0;box-sizing:border-box}}body{{background:#020817;color:#f8fafc;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh}}.card{{background:#0f172a;border:1px solid #1e293b;border-radius:16px;padding:48px;max-width:480px;width:100%;text-align:center}}.badge{{display:inline-block;background:linear-gradient(135deg,#38bdf8,#818cf8);color:#fff;padding:6px 18px;border-radius:999px;font-weight:600;font-size:14px;margin-bottom:24px}}h1{{font-size:28px;font-weight:700;color:#38bdf8;margin-bottom:12px}}p{{color:#94a3b8;line-height:1.6;margin-bottom:16px}}a{{display:inline-block;background:#38bdf8;color:#020817;padding:12px 32px;border-radius:8px;text-decoration:none;font-weight:600;margin-top:16px}}</style></head>
<body><div class="card"><div style="font-size:64px;margin-bottom:24px">🎉</div><div class="badge">{plan.upper()} Plan</div><h1>Payment Successful!</h1><p>Your MailGuard <strong>{plan.capitalize()}</strong> subscription is active.</p><p>Your API key will be emailed shortly.</p>{f'<p style="font-size:12px;color:#475569">Ref: {ref_display}</p>' if ref_display else ''}<a href="/">Back to MailGuard</a></div></body></html>"""
    return Response(content=html, media_type="text/html")
