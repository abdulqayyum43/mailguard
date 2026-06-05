"""Spoofability risk assessment — pure logic, no I/O."""


def assess_spoofability(spf: dict, dkim: dict, dmarc: dict) -> dict:
    result = dict(
        risk="LOW",
        can_spoof_display_name=True,   # always possible without BIMI/brand indicators
        can_spoof_from_header=False,
        spf_contribution="",
        dmarc_contribution="",
        dkim_contribution="",
        rationale="",
    )

    spf_weak = (
        not spf["found"]
        or spf["pass_all"]
        or spf["neutral_all"]
        or (not spf["hardfail_all"] and not spf["softfail_all"])
    )
    spf_soft = spf["found"] and spf["softfail_all"]
    dmarc_none = not dmarc["found"] or dmarc["policy"] == "none"
    dmarc_weak = dmarc_none or dmarc["policy"] == "quarantine"
    dkim_absent = not dkim["found"]

    # Contribution descriptions
    if not spf["found"]:
        result["spf_contribution"] = "No SPF record — senders are not restricted"
    elif spf["pass_all"]:
        result["spf_contribution"] = "SPF uses +all — any server can send as this domain"
    elif spf["softfail_all"]:
        result["spf_contribution"] = "SPF uses ~all (softfail) — messages are not rejected"
    elif spf["hardfail_all"]:
        result["spf_contribution"] = "SPF uses -all — unauthorized senders are rejected"
    else:
        result["spf_contribution"] = "SPF configured without explicit all mechanism"

    if not dmarc["found"]:
        result["dmarc_contribution"] = "No DMARC record — receiving servers have no enforcement instructions"
    elif dmarc["policy"] == "none":
        result["dmarc_contribution"] = "DMARC p=none — monitoring only, spoofed messages are delivered"
    elif dmarc["policy"] == "quarantine":
        result["dmarc_contribution"] = "DMARC p=quarantine — spoofed messages sent to spam but not rejected"
    else:
        result["dmarc_contribution"] = "DMARC p=reject — spoofed messages are rejected"

    if dkim_absent:
        result["dkim_contribution"] = "No DKIM found — message integrity cannot be verified"
    else:
        result["dkim_contribution"] = f"DKIM configured ({len(dkim['selectors_found'])} selector(s) found)"

    # Determine risk level
    if spf_weak and dmarc_none:
        result["risk"] = "HIGH"
        result["can_spoof_from_header"] = True
        result["rationale"] = (
            "Domain can be freely spoofed. "
            + result["spf_contribution"] + " "
            + result["dmarc_contribution"]
        )
    elif spf_soft or dmarc_weak or dkim_absent:
        result["risk"] = "MEDIUM"
        result["can_spoof_from_header"] = True
        result["rationale"] = (
            "Partial protections in place but domain may still be spoofable. "
            + result["spf_contribution"] + " "
            + result["dmarc_contribution"]
        )
    else:
        result["risk"] = "LOW"
        result["can_spoof_from_header"] = False
        result["rationale"] = (
            "Strong protections in place. "
            + result["spf_contribution"] + " "
            + result["dmarc_contribution"]
        )

    return result
