"""Email phishing detection — combined header + body pipeline.

Public surface
--------------
- analyze_email(raw, user) -> dict     : pure function used by both DRF and templates
- EmailPhishingDetection (DRF)         : POST raw email source, get verdict JSON

The body classifier is a shared, pre-trained joblib pipeline (TF-IDF + LR)
loaded lazily on first scan. Re-train with `python api/email_phishing/train_model.py`.
"""
from __future__ import annotations

import email
from email.message import Message
from typing import Any

import joblib
import requests
from bs4 import BeautifulSoup
from django.conf import settings
from rest_framework import authentication, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.models import UserModel

from .models import EmailReport
from .serializers import GetEmailReportSerializer

BAD_REQUEST = status.HTTP_400_BAD_REQUEST
GET_REQUEST = status.HTTP_200_OK
CREATE_REQUEST = status.HTTP_201_CREATED

EMAIL_RAPIDAPI_KEY = settings.EMAIL_RAPIDAPI_KEY
MODEL_PATH = str(settings.BASE_DIR.parent) + "/pickle/email_model.joblib"

PHISH_HIGH = 0.70
PHISH_LOW = 0.40


_pipeline = None
_pipeline_load_error: Exception | None = None


def get_pipeline():
    global _pipeline, _pipeline_load_error
    if _pipeline is not None or _pipeline_load_error is not None:
        return _pipeline
    try:
        _pipeline = joblib.load(MODEL_PATH)
    except Exception as exc:
        _pipeline_load_error = exc
        _pipeline = None
    return _pipeline


def parse_raw_email(raw: str) -> dict[str, Any]:
    raw = (raw or "").strip()
    if not raw:
        return {"sender": "", "subject": "", "body": "", "auth_results_headers": [], "looks_like_full_message": False}

    msg: Message = email.message_from_string(raw)
    has_headers = any(msg.get(h) for h in ("From", "To", "Subject", "Authentication-Results", "Received"))
    if not has_headers:
        return {"sender": "", "subject": "", "body": raw, "auth_results_headers": [], "looks_like_full_message": False}

    sender = (msg.get("From") or "").strip()
    subject = (msg.get("Subject") or "").strip()
    auth_headers = msg.get_all("Authentication-Results", []) + msg.get_all("ARC-Authentication-Results", [])
    body = _extract_body(msg)
    return {
        "sender": sender,
        "subject": subject,
        "body": body,
        "auth_results_headers": [str(h) for h in auth_headers],
        "looks_like_full_message": True,
    }


def _extract_body(msg: Message) -> str:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            ctype = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                continue
            if payload is None:
                continue
            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="ignore")
            except (LookupError, AttributeError):
                text = payload.decode("utf-8", errors="ignore")
            if ctype == "text/plain":
                plain_parts.append(text)
            elif ctype == "text/html":
                html_parts.append(text)
    else:
        ctype = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            text = payload.decode(charset, errors="ignore") if payload else ""
        except Exception:
            payload_str = msg.get_payload()
            text = payload_str if isinstance(payload_str, str) else ""
        if ctype == "text/html":
            html_parts.append(text)
        else:
            plain_parts.append(text)

    if plain_parts:
        return "\n\n".join(p.strip() for p in plain_parts if p.strip())
    if html_parts:
        soup = BeautifulSoup("\n".join(html_parts), "html.parser")
        return soup.get_text(separator=" ", strip=True)
    return ""


def parse_auth_results(headers: list[str]) -> dict[str, Any]:
    """Combine all Authentication-Results headers into per-mechanism verdicts."""
    result: dict[str, Any] = {"spf": None, "dkim": None, "dmarc": None}
    for raw in headers:
        for component in str(raw).split(";"):
            kv = component.strip().split("=", 1)
            if len(kv) != 2:
                continue
            key = kv[0].strip().lower()
            if key not in result:
                continue
            verdict = kv[1].strip().split()[0].lower()
            passed = verdict == "pass"
            if result[key] is None:
                result[key] = passed
            elif passed:
                result[key] = True

    reported = [v for v in result.values() if v is not None]
    if not reported:
        status_label = "unknown"
    elif len(reported) == 3 and all(reported):
        status_label = "pass"
    elif any(v is False for v in result.values()):
        status_label = "fail"
    else:
        status_label = "unknown"
    return {**result, "status": status_label}


def lookup_domain_reputation(sender: str, timeout: float = 4.0) -> dict[str, Any]:
    if "@" not in sender:
        return {}
    domain = sender.split("@", 1)[1].strip().rstrip(">")
    if not domain:
        return {}
    try:
        resp = requests.get(
            "https://mailcheck.p.rapidapi.com/",
            params={"domain": domain},
            headers={
                "X-RapidAPI-Key": EMAIL_RAPIDAPI_KEY,
                "X-RapidAPI-Host": "mailcheck.p.rapidapi.com",
            },
            timeout=timeout,
        )
        if resp.status_code != 200:
            return {}
        data = resp.json()
        return {
            "domain": data.get("domain", domain),
            "valid": data.get("valid"),
            "block": data.get("block"),
            "disposable": data.get("disposable"),
            "email_forwarder": data.get("email_forwarder"),
            "mx_host": data.get("mx_host", "") or "",
            "mx_ip": data.get("mx_ip", "") or "",
            "mx_info": data.get("mx_info", "") or "",
            "risk": data.get("risk"),
        }
    except (requests.RequestException, ValueError):
        return {}


def combine_verdict(body_prob: float, header_status: str) -> tuple[str, list[str]]:
    reasons: list[str] = []

    if body_prob >= PHISH_HIGH:
        reasons.append(f"Body classifier flags this as phishing ({body_prob*100:.1f}%).")
        return EmailReport.VERDICT_PHISHING, reasons

    if body_prob >= PHISH_LOW:
        if header_status == "fail":
            reasons.append(
                f"Body looks mid-suspicious ({body_prob*100:.1f}%) and the sender failed SPF/DKIM/DMARC."
            )
            return EmailReport.VERDICT_PHISHING, reasons
        reasons.append(f"Body classifier is on the fence ({body_prob*100:.1f}%).")
        if header_status == "pass":
            reasons.append("Sender authentication passed, but content style is borderline.")
        else:
            reasons.append("No Authentication-Results header to corroborate the sender.")
        return EmailReport.VERDICT_SUSPICIOUS, reasons

    if header_status == "fail":
        reasons.append(
            f"Body looks normal ({body_prob*100:.1f}%) but sender authentication failed — possible impersonation."
        )
        return EmailReport.VERDICT_SUSPICIOUS, reasons

    reasons.append(f"Body classifier is confident this is not phishing ({body_prob*100:.1f}%).")
    if header_status == "pass":
        reasons.append("Sender passed SPF, DKIM, and DMARC.")
    return EmailReport.VERDICT_CLEAN, reasons


def analyze_email(raw: str, user, lookup_reputation: bool = True) -> dict[str, Any]:
    pipeline = get_pipeline()
    if pipeline is None:
        raise RuntimeError(
            "Email body classifier failed to load. Run "
            "`python api/email_phishing/train_model.py` to build pickle/email_model.joblib."
        )

    parsed = parse_raw_email(raw)
    body = parsed["body"] or ""
    if not body.strip():
        raise ValueError("No email body found. Paste either the full email source or just the body text.")

    body_prob = float(pipeline.predict_proba([body])[0, 1])
    body_phish_score = round(body_prob * 100, 2)

    auth = parse_auth_results(parsed["auth_results_headers"])
    header_status = auth["status"]

    rep = lookup_domain_reputation(parsed["sender"]) if (lookup_reputation and parsed["sender"]) else {}

    verdict, reasons = combine_verdict(body_prob, header_status)

    report = EmailReport.objects.create(
        user=user,
        sender=parsed["sender"][:320],
        subject=parsed["subject"][:1000],
        body_phish_score=body_phish_score,
        header_status=header_status,
        header_spf=auth["spf"],
        header_dkim=auth["dkim"],
        header_dmarc=auth["dmarc"],
        domain=rep.get("domain", ""),
        valid=rep.get("valid"),
        block=rep.get("block"),
        disposable=rep.get("disposable"),
        email_forwarder=rep.get("email_forwarder"),
        mx_host=rep.get("mx_host", ""),
        mx_ip=rep.get("mx_ip", ""),
        mx_info=rep.get("mx_info", ""),
        risk=rep.get("risk"),
        final_verdict=verdict,
    )

    return {
        "report_id": str(report.id),
        "verdict": verdict,
        "reasons": reasons,
        "body_phish_score": body_phish_score,
        "header_status": header_status,
        "header_spf": auth["spf"],
        "header_dkim": auth["dkim"],
        "header_dmarc": auth["dmarc"],
        "sender": parsed["sender"],
        "subject": parsed["subject"],
        "domain_reputation": rep,
        "looks_like_full_message": parsed["looks_like_full_message"],
    }


class EmailPhishingDetection(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        raw = request.data.get("raw_email", "") or request.data.get("email_msg", "")
        if not raw or not raw.strip():
            return Response("raw_email field is required.", status=BAD_REQUEST)
        user = UserModel.objects.get(id=request.user.pk)
        try:
            result = analyze_email(raw, user)
        except (RuntimeError, ValueError) as exc:
            return Response(str(exc), status=BAD_REQUEST)
        return Response(result, status=CREATE_REQUEST)

    def get(self, request):
        reports = EmailReport.objects.filter(user=request.user).order_by("-created_at")
        serializer = GetEmailReportSerializer(instance=reports, many=True)
        return Response(serializer.data, status=GET_REQUEST)
