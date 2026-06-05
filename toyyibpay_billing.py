"""
ToyyibPay billing integration for MailGuard.
Malaysian payment gateway — supports FPX, credit/debit cards.

API reference: https://toyyibpay.com/apireference/
Payment page:  https://toyyibpay.com/{billCode}

Callback POST fields (sent server-to-server):
  billcode, order_id, status (1=success, 2=pending, 3=fail), reason, transaction_id, msg
"""

import httpx
import secrets
import logging
from config import settings

logger = logging.getLogger("sslguard.toyyibpay")

TOYYIBPAY_API = "https://toyyibpay.com/index.php/api"
TOYYIBPAY_PAY = "https://toyyibpay.com"

PLANS = {
    "pro":        {"name": "MailGuard Pro",        "amount": 2900,  "label": "RM 29/mo"},
    "enterprise": {"name": "MailGuard Enterprise", "amount": 9900,  "label": "RM 99/mo"},
}


def create_bill(
    plan: str,
    buyer_name: str = "Customer",
    buyer_email: str = "",
    buyer_phone: str = "0123456789",
) -> dict:
    """
    Create a ToyyibPay bill and return {"url": "...", "bill_code": "...", "ref": "..."}.
    On error returns {"error": "..."}.
    """
    plan_info = PLANS.get(plan)
    if not plan_info:
        return {"error": f"Unknown plan '{plan}'. Use 'pro' or 'enterprise'."}

    ref = f"mailg-{plan[:3]}-{secrets.token_hex(8)}"
    callback_url = f"{settings.public_url}/billing/toyyibpay/callback"
    return_url   = f"{settings.public_url}/billing/success?plan={plan}&ref={ref}"

    payload = {
        "userSecretKey":          settings.toyyibpay_secret_key,
        "categoryCode":           settings.toyyibpay_category_code,
        "billName":               plan_info["name"],
        "billDescription":        f"MailGuard {plan.capitalize()} subscription — {plan_info['label']}",
        "billPriceSetting":       "1",          # fixed price
        "billPayorInfo":          "1",          # collect name/email/phone
        "billAmount":             str(plan_info["amount"]),   # in sen (RM cents)
        "billReturnUrl":          return_url,
        "billCallbackUrl":        callback_url,
        "billExternalReferenceNo": ref,
        "billTo":                 buyer_name,
        "billEmail":              buyer_email,
        "billPhone":              buyer_phone,
        "billSplitPayment":       "0",
        "billSplitPaymentArgs":   "",
        "billPaymentChannel":     "0",          # all channels
        "billContentEmail":       (
            f"Thank you for subscribing to MailGuard {plan.capitalize()}! "
            "Your API key will be emailed to you shortly."
        ),
        "billChargeToCustomer":   "1",          # fees borne by customer
        "billExpiryDays":         "3",          # bill expires in 3 days
    }

    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.post(f"{TOYYIBPAY_API}/createBill", data=payload)
            r.raise_for_status()
            data = r.json()

            if not data or not isinstance(data, list) or "BillCode" not in data[0]:
                logger.error("ToyyibPay unexpected response: %s", data)
                return {"error": "Unexpected response from ToyyibPay", "raw": str(data)}

            bill_code = data[0]["BillCode"]
            return {
                "url":       f"{TOYYIBPAY_PAY}/{bill_code}",
                "bill_code": bill_code,
                "ref":       ref,
                "plan":      plan,
                "amount":    plan_info["amount"],
                "label":     plan_info["label"],
            }

    except httpx.HTTPError as exc:
        logger.error("ToyyibPay HTTP error: %s", exc)
        return {"error": f"Payment gateway error: {exc}"}


def verify_callback(status: str) -> bool:
    """Return True if payment was successful (status == '1')."""
    return str(status) == "1"
