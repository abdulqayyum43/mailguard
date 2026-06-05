"""Pytest test suite for MailGuard Email Security Analyzer."""
import sys
import os
import pytest

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer.spf import check_spf
from analyzer.dmarc import check_dmarc
from analyzer.spoofability import assess_spoofability
from analyzer.scorer import _score_and_issues, _recommendations, _grade


# ── SPF Tests ──────────────────────────────────────────────────────────────────

class TestSPFParser:
    def test_spf_hardfail_all(self):
        """SPF with -all should set hardfail_all=True."""
        from unittest.mock import patch, MagicMock
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            mock_answer = MagicMock()
            mock_rdata = MagicMock()
            mock_rdata.strings = [b"v=spf1 include:_spf.google.com -all"]
            mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))
            instance.resolve.return_value = mock_answer

            result = check_spf("example.com")
            assert result["found"] is True
            assert result["hardfail_all"] is True
            assert result["all_mechanism"] == "-all"

    def test_spf_softfail_all(self):
        """SPF with ~all should set softfail_all=True, hardfail_all=False."""
        from unittest.mock import patch, MagicMock
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            mock_answer = MagicMock()
            mock_rdata = MagicMock()
            mock_rdata.strings = [b"v=spf1 include:sendgrid.net ~all"]
            mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))
            instance.resolve.return_value = mock_answer

            result = check_spf("example.com")
            assert result["found"] is True
            assert result["hardfail_all"] is False
            assert result["softfail_all"] is True
            assert result["all_mechanism"] == "~all"

    def test_spf_no_record(self):
        """Missing SPF record should return found=False."""
        import dns.exception
        from unittest.mock import patch, MagicMock
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = dns.exception.DNSException("NXDOMAIN")

            result = check_spf("no-spf.example.com")
            assert result["found"] is False

    def test_spf_lookup_count(self):
        """DNS lookup count should be tracked for include: mechanisms."""
        from unittest.mock import patch, MagicMock
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            mock_answer = MagicMock()
            mock_rdata = MagicMock()
            mock_rdata.strings = [b"v=spf1 include:_spf.google.com include:mail.example.com -all"]
            mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))
            instance.resolve.return_value = mock_answer

            result = check_spf("example.com")
            assert result["dns_lookup_count"] >= 2


# ── DMARC Tests ────────────────────────────────────────────────────────────────

class TestDMARCParser:
    def test_dmarc_reject_policy(self):
        """DMARC with p=reject should set enforced=True."""
        from unittest.mock import patch, MagicMock
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            mock_answer = MagicMock()
            mock_rdata = MagicMock()
            mock_rdata.strings = [b"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"]
            mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))
            instance.resolve.return_value = mock_answer

            result = check_dmarc("example.com")
            assert result["found"] is True
            assert result["policy"] == "reject"
            assert result["enforced"] is True
            assert result["has_reporting"] is True
            assert result["pct"] == 100

    def test_dmarc_quarantine_policy(self):
        """DMARC with p=quarantine should set enforced=True."""
        from unittest.mock import patch, MagicMock
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            mock_answer = MagicMock()
            mock_rdata = MagicMock()
            mock_rdata.strings = [b"v=DMARC1; p=quarantine; rua=mailto:rua@example.com"]
            mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))
            instance.resolve.return_value = mock_answer

            result = check_dmarc("example.com")
            assert result["policy"] == "quarantine"
            assert result["enforced"] is True
            assert result["has_reporting"] is True

    def test_dmarc_none_policy(self):
        """DMARC with p=none should set enforced=False."""
        from unittest.mock import patch, MagicMock
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            mock_answer = MagicMock()
            mock_rdata = MagicMock()
            mock_rdata.strings = [b"v=DMARC1; p=none"]
            mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))
            instance.resolve.return_value = mock_answer

            result = check_dmarc("example.com")
            assert result["policy"] == "none"
            assert result["enforced"] is False

    def test_dmarc_no_record(self):
        """Missing DMARC record should return found=False."""
        import dns.exception
        from unittest.mock import patch, MagicMock
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = dns.exception.DNSException("NXDOMAIN")

            result = check_dmarc("no-dmarc.example.com")
            assert result["found"] is False
            assert result["policy"] is None
            assert result["enforced"] is False

    def test_dmarc_no_reporting(self):
        """DMARC without rua tag should set has_reporting=False."""
        from unittest.mock import patch, MagicMock
        with patch("dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            mock_answer = MagicMock()
            mock_rdata = MagicMock()
            mock_rdata.strings = [b"v=DMARC1; p=quarantine"]
            mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))
            instance.resolve.return_value = mock_answer

            result = check_dmarc("example.com")
            assert result["has_reporting"] is False


# ── Spoofability Tests ─────────────────────────────────────────────────────────

def _spf_dict(found=True, hardfail=True):
    return {
        "found": found, "record": "v=spf1 -all" if found else None,
        "all_mechanism": "-all" if hardfail else "~all",
        "hardfail_all": hardfail, "softfail_all": not hardfail and found,
        "neutral_all": False, "pass_all": False,
        "exceeds_lookup_limit": False, "dns_lookup_count": 1,
        "syntax_error": None, "includes": [], "mechanisms": ["-all"],
    }


def _dmarc_dict(found=True, policy="reject", enforced=True):
    return {
        "found": found, "record": "v=DMARC1; p=reject" if found else None,
        "policy": policy if found else None, "subdomain_policy": None,
        "enforced": enforced, "pct": 100, "rua": ["mailto:dmarc@example.com"],
        "ruf": [], "adkim": "r", "aspf": "r", "has_reporting": True,
    }


def _dkim_dict(found=True):
    return {
        "found": found, "selectors_probed": 36, "selectors_found": [],
        "has_weak_key": False, "has_short_key": False,
        "weakest_key_bits": 2048 if found else None,
        "strongest_key_bits": 2048 if found else None,
    }


class TestSpoofability:
    def test_low_risk_full_protection(self):
        """SPF -all + DMARC reject = LOW risk."""
        result = assess_spoofability(
            _spf_dict(found=True, hardfail=True),
            _dkim_dict(found=True),
            _dmarc_dict(found=True, policy="reject", enforced=True),
        )
        assert result["risk"] == "LOW"
        assert result["can_spoof_from_header"] is False

    def test_high_risk_no_spf_no_dmarc(self):
        """No SPF and no DMARC = HIGH risk."""
        result = assess_spoofability(
            _spf_dict(found=False),
            _dkim_dict(found=False),
            _dmarc_dict(found=False),
        )
        assert result["risk"] == "HIGH"
        assert result["can_spoof_from_header"] is True

    def test_medium_risk_softfail(self):
        """SPF ~all (softfail) with DMARC none = MEDIUM risk."""
        result = assess_spoofability(
            _spf_dict(found=True, hardfail=False),
            _dkim_dict(found=True),
            _dmarc_dict(found=True, policy="none", enforced=False),
        )
        assert result["risk"] == "MEDIUM"

    def test_medium_risk_quarantine(self):
        """DMARC p=quarantine counts as weak → MEDIUM risk (quarantine != reject)."""
        result = assess_spoofability(
            _spf_dict(found=True, hardfail=True),
            _dkim_dict(found=True),
            _dmarc_dict(found=True, policy="quarantine", enforced=True),
        )
        assert result["risk"] == "MEDIUM"


# ── Scorer / Grading Tests ─────────────────────────────────────────────────────

def _make_scan_components(
    spf_found=True, spf_hardfail=True, spf_softfail=False,
    dmarc_found=True, dmarc_policy="reject", dmarc_enforced=True, dmarc_reporting=True,
    dkim_found=True, dkim_weak=False,
    mta_sts_ok=True, starttls=True, bl_clean=True,
    spoof_risk="LOW",
):
    spf = {
        "found": spf_found, "record": "v=spf1 -all",
        "all_mechanism": "-all", "hardfail_all": spf_hardfail,
        "softfail_all": spf_softfail, "pass_all": False, "neutral_all": False,
        "exceeds_lookup_limit": False, "dns_lookup_count": 1, "syntax_error": None,
        "includes": [], "mechanisms": ["-all"],
    }
    dmarc = {
        "found": dmarc_found, "record": "v=DMARC1; p=reject",
        "policy": dmarc_policy if dmarc_found else None,
        "subdomain_policy": None, "pct": 100, "rua": ["mailto:x@example.com"],
        "ruf": [], "adkim": "r", "aspf": "r",
        "has_reporting": dmarc_reporting, "enforced": dmarc_enforced,
    }
    dkim = {
        "found": dkim_found, "selectors_probed": 36, "selectors_found": [],
        "has_weak_key": dkim_weak, "has_short_key": False,
        "weakest_key_bits": 512 if dkim_weak else 2048,
        "strongest_key_bits": 2048,
    }
    mta_sts = {
        "dns_record_found": mta_sts_ok, "dns_record": "v=STSv1; id=1;",
        "policy_fetched": mta_sts_ok, "policy_mode": "enforce" if mta_sts_ok else None,
        "policy_mx_hosts": ["mail.example.com"], "policy_max_age": 86400,
        "fetch_error": None, "fully_configured": mta_sts_ok,
    }
    mx = {
        "found": True,
        "records": [{"hostname": "mail.example.com", "priority": 10,
                     "ip_addresses": ["1.2.3.4"], "starttls_supported": starttls,
                     "tls_version": "TLSv1.3", "tls_cipher": None, "banner": None,
                     "banner_exposes_version": False, "connect_error": None}],
        "all_support_starttls": starttls, "any_support_starttls": starttls,
        "starttls_count": 1 if starttls else 0, "total_mx_count": 1,
    }
    bl_listings = [] if bl_clean else [
        {"ip": "1.2.3.4", "rbl": "zen.spamhaus.org", "listed": True, "reason": "Listed"},
        {"ip": "1.2.3.4", "rbl": "bl.spamcop.net", "listed": True, "reason": "Listed"},
    ]
    blacklist = {
        "ips_checked": ["1.2.3.4"], "listings": bl_listings,
        "listed_count": 0 if bl_clean else 2, "clean": bl_clean,
    }
    mail_tls = {
        "servers_checked": [], "any_deprecated_tls": False, "any_weak_cipher": False,
    }
    spoof = {
        "risk": spoof_risk, "can_spoof_display_name": spoof_risk != "LOW",
        "can_spoof_from_header": spoof_risk == "HIGH",
        "spf_contribution": "", "dmarc_contribution": "",
        "dkim_contribution": "", "rationale": "",
    }
    return spf, dkim, dmarc, mta_sts, mx, blacklist, mail_tls, spoof


class TestScorer:
    def test_perfect_score(self):
        """Fully configured domain should score 100 and grade A+."""
        components = _make_scan_components()
        score, issues = _score_and_issues(*components)
        assert score == 100
        assert issues == []

    def test_perfect_grade(self):
        """Score 100 → A+."""
        assert _grade(100) == "A+"
        assert _grade(90) == "A+"

    def test_grade_a(self):
        """Score 80-89 → A."""
        assert _grade(89) == "A"
        assert _grade(80) == "A"

    def test_grade_b(self):
        """Score 70-79 → B."""
        assert _grade(79) == "B"
        assert _grade(70) == "B"

    def test_grade_c(self):
        """Score 60-69 → C."""
        assert _grade(69) == "C"
        assert _grade(60) == "C"

    def test_grade_d(self):
        """Score 50-59 → D."""
        assert _grade(59) == "D"
        assert _grade(50) == "D"

    def test_grade_f(self):
        """Score below 50 → F."""
        assert _grade(49) == "F"
        assert _grade(0) == "F"

    def test_missing_spf_deduction(self):
        """Missing SPF should reduce score and add issue."""
        components = _make_scan_components(spf_found=False)
        score, issues = _score_and_issues(*components)
        assert score < 100
        assert any("SPF" in i for i in issues)

    def test_missing_dmarc_deduction(self):
        """Missing DMARC should reduce score."""
        components = _make_scan_components(dmarc_found=False)
        score, issues = _score_and_issues(*components)
        assert score < 100
        assert any("DMARC" in i for i in issues)

    def test_dmarc_none_policy_deduction(self):
        """DMARC p=none should reduce score vs p=reject."""
        components = _make_scan_components(dmarc_policy="none", dmarc_enforced=False)
        score, issues = _score_and_issues(*components)
        assert score < 100

    def test_blacklisted_deduction(self):
        """Being on a blacklist should reduce score."""
        components = _make_scan_components(bl_clean=False)
        score, issues = _score_and_issues(*components)
        assert score < 100
        assert any("blacklist" in i.lower() or "listed" in i.lower() for i in issues)

    def test_recommendations_generated(self):
        """Issues should produce non-empty recommendations."""
        components = _make_scan_components(spf_found=False, dmarc_found=False)
        _, issues = _score_and_issues(*components)
        recs = _recommendations(issues)
        assert len(recs) > 0

    def test_weak_dkim_deduction(self):
        """Weak DKIM key should produce an issue and reduce score."""
        components = _make_scan_components(dkim_weak=True)
        score, issues = _score_and_issues(*components)
        assert score < 100
        assert any("DKIM" in i or "key" in i.lower() for i in issues)

    def test_no_starttls_deduction(self):
        """MX servers without STARTTLS should reduce score."""
        components = _make_scan_components(starttls=False)
        score, issues = _score_and_issues(*components)
        assert score < 100
        assert any("STARTTLS" in i or "starttls" in i.lower() or "TLS" in i for i in issues)


# ── API Integration Tests ──────────────────────────────────────────────────────

class TestAPIIntegration:
    @pytest.fixture
    def client(self):
        pytest.importorskip("fastapi")
        try:
            from fastapi.testclient import TestClient
            from main import app
            c = TestClient(app, raise_server_exceptions=False)
            c.__enter__()
            yield c
            c.__exit__(None, None, None)
        except Exception as e:
            pytest.skip(f"Could not import main.app: {e}")

    def test_health_endpoint(self, client):
        """GET /health should return 200."""
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"

    def test_analyze_missing_api_key(self, client):
        """POST /analyze without API key should return 401 or 422."""
        r = client.post("/analyze", json={"domain": "example.com"})
        assert r.status_code in (401, 403, 422)

    def test_waitlist_signup(self, client):
        """POST /waitlist should accept a valid email."""
        r = client.post("/waitlist", json={
            "email": "test@example.com",
            "name": "Test User",
            "plan": "pro",
        })
        assert r.status_code in (200, 201)

    def test_admin_requires_secret(self, client):
        """Admin endpoints should require X-Admin-Secret header."""
        r = client.get("/admin/system")
        assert r.status_code in (401, 403)
