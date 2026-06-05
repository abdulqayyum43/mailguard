from pydantic import BaseModel, Field, field_validator
from typing import Optional
import re


def _clean_domain(v: str) -> str:
    v = v.strip().lower()
    v = re.sub(r"^https?://", "", v)
    v = v.split("/")[0].rstrip(".")
    if not re.match(r"^[a-z0-9.\-]+$", v):
        raise ValueError("Invalid domain — only letters, digits, hyphens, and dots allowed")
    if "." not in v:
        raise ValueError("Invalid domain — must contain at least one dot")
    return v


# ── Core ──────────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    webhook_url: Optional[str] = Field(None)

    @field_validator("domain")
    @classmethod
    def clean_domain(cls, v): return _clean_domain(v)


class SPFResult(BaseModel):
    found: bool
    record: Optional[str]
    all_mechanism: Optional[str]
    dns_lookup_count: int
    exceeds_lookup_limit: bool
    syntax_error: Optional[str]
    includes: list[str]
    mechanisms: list[str]
    pass_all: bool
    softfail_all: bool
    neutral_all: bool
    hardfail_all: bool


class DKIMSelectorResult(BaseModel):
    selector: str
    record: Optional[str]
    key_bits: Optional[int]
    key_type: Optional[str]
    valid: bool


class DKIMResult(BaseModel):
    found: bool
    selectors_probed: int
    selectors_found: list[DKIMSelectorResult]
    strongest_key_bits: Optional[int]
    weakest_key_bits: Optional[int]
    has_weak_key: bool
    has_short_key: bool


class DMARCResult(BaseModel):
    found: bool
    record: Optional[str]
    policy: Optional[str]
    subdomain_policy: Optional[str]
    pct: Optional[int]
    rua: list[str]
    ruf: list[str]
    adkim: Optional[str]
    aspf: Optional[str]
    has_reporting: bool
    enforced: bool


class MTASTSResult(BaseModel):
    dns_record_found: bool
    dns_record: Optional[str]
    policy_fetched: bool
    policy_mode: Optional[str]
    policy_mx_hosts: list[str]
    policy_max_age: Optional[int]
    fetch_error: Optional[str]
    fully_configured: bool


class BIMIResult(BaseModel):
    found: bool
    record: Optional[str]
    logo_url: Optional[str]
    vmc_url: Optional[str]
    vmc_present: bool


class MXServerResult(BaseModel):
    hostname: str
    priority: int
    ip_addresses: list[str]
    banner: Optional[str]
    starttls_supported: bool
    tls_version: Optional[str]
    tls_cipher: Optional[str]
    banner_exposes_version: bool
    connect_error: Optional[str]


class MXResult(BaseModel):
    found: bool
    records: list[MXServerResult]
    all_support_starttls: bool
    any_support_starttls: bool
    starttls_count: int
    total_mx_count: int


class BlacklistEntry(BaseModel):
    ip: str
    rbl: str
    listed: bool
    reason: Optional[str]


class BlacklistResult(BaseModel):
    ips_checked: list[str]
    listings: list[BlacklistEntry]
    listed_count: int
    clean: bool


class DANEResult(BaseModel):
    mx_hostname: str
    tlsa_found: bool
    records: list[str]
    record_count: int


class DANECheckResult(BaseModel):
    any_tlsa_found: bool
    mx_results: list[DANEResult]


class SpoofabilityResult(BaseModel):
    risk: str
    can_spoof_display_name: bool
    can_spoof_from_header: bool
    spf_contribution: str
    dmarc_contribution: str
    dkim_contribution: str
    rationale: str


class MailTLSServerResult(BaseModel):
    mx_hostname: str
    port: int
    tls_version: Optional[str]
    cipher: Optional[str]
    tls_version_deprecated: bool
    cipher_weak: bool
    connect_error: Optional[str]


class MailTLSResult(BaseModel):
    servers_checked: list[MailTLSServerResult]
    any_deprecated_tls: bool
    any_weak_cipher: bool


class AnalyzeResponse(BaseModel):
    domain: str
    score: int
    grade: str
    spf: SPFResult
    dkim: DKIMResult
    dmarc: DMARCResult
    mta_sts: MTASTSResult
    bimi: BIMIResult
    mx: MXResult
    blacklist: BlacklistResult
    dane: DANECheckResult
    spoofability: SpoofabilityResult
    mail_tls: MailTLSResult
    issues: list[str]
    issue_count: int
    recommendations: list[str]
    scan_duration_ms: Optional[int]


class BulkAnalyzeRequest(BaseModel):
    domains: list[str] = Field(..., min_length=1, max_length=20)

    @field_validator("domains")
    @classmethod
    def validate_domains(cls, v):
        return [_clean_domain(d) for d in v]


class BulkAnalyzeResponse(BaseModel):
    total: int
    results: list[dict]


# ── Monitoring ────────────────────────────────────────────────────────────────

class AddMonitorRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    check_interval_hours: int = Field(24, ge=1, le=168)
    alert_on_grade_drop: bool = True
    alert_on_blacklist: bool = True
    alert_on_spoofability_change: bool = True
    slack_webhook: Optional[str] = None
    pagerduty_key: Optional[str] = None
    alert_email: Optional[str] = None
    webhook_url: Optional[str] = None

    @field_validator("domain")
    @classmethod
    def clean(cls, v): return _clean_domain(v)


# ── Scheduler ─────────────────────────────────────────────────────────────────

class AddScheduleRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    frequency: str = Field("daily", pattern="^(hourly|daily|weekly)$")
    label: Optional[str] = Field(None, max_length=100)

    @field_validator("domain")
    @classmethod
    def clean(cls, v): return _clean_domain(v)


# ── Portfolio ─────────────────────────────────────────────────────────────────

class AddPortfolioRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    label: Optional[str] = Field(None, max_length=100)

    @field_validator("domain")
    @classmethod
    def clean(cls, v): return _clean_domain(v)


# ── Reports ───────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)

    @field_validator("domain")
    @classmethod
    def clean(cls, v): return _clean_domain(v)


class ComplianceReportRequest(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    framework: str = Field("pci-dss", pattern="^(pci-dss|soc2|iso27001)$")

    @field_validator("domain")
    @classmethod
    def clean(cls, v): return _clean_domain(v)


# ── Waitlist / Billing / Admin ────────────────────────────────────────────────

class WaitlistRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    name: str = Field(..., min_length=1, max_length=100)
    plan: str = Field("pro", pattern="^(free|pro|enterprise)$")
    company: str = Field("", max_length=100)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v or "." not in v.split("@")[-1]:
            raise ValueError("Invalid email address")
        return v


class CheckoutRequest(BaseModel):
    plan: str = Field(..., pattern="^(pro|enterprise)$")
    email: Optional[str] = Field(None)
    name: Optional[str] = Field(None, max_length=100)
    phone: Optional[str] = Field(None, max_length=20)


class KeyProvisionRequest(BaseModel):
    new_key: str = Field(..., min_length=8, max_length=128)
    tier: str = Field("free", pattern="^(free|pro|enterprise)$")
    expires_at: Optional[str] = Field(None)


class KeyProvisionResponse(BaseModel):
    key: str
    tier: str
    message: str
