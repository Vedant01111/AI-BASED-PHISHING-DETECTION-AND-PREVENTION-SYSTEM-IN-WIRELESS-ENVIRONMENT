from django.db import models
import uuid
from django.contrib.auth import get_user_model

User = get_user_model()


class EmailReport(models.Model):
    """One row per email scan submitted to /scan/email/.

    Stores the parsed-from-source signals (sender/subject), the body classifier
    score, the SPF/DKIM/DMARC outcome derived from the Authentication-Results
    header (when present), the optional MailCheck domain reputation, and the
    final combined verdict.
    """

    VERDICT_CLEAN = "clean"
    VERDICT_SUSPICIOUS = "suspicious"
    VERDICT_PHISHING = "phishing"
    VERDICT_CHOICES = [
        (VERDICT_CLEAN, "Clean"),
        (VERDICT_SUSPICIOUS, "Suspicious"),
        (VERDICT_PHISHING, "Phishing"),
    ]

    HEADER_PASS = "pass"
    HEADER_FAIL = "fail"
    HEADER_UNKNOWN = "unknown"
    HEADER_CHOICES = [
        (HEADER_PASS, "Pass"),
        (HEADER_FAIL, "Fail"),
        (HEADER_UNKNOWN, "Unknown"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    # Parsed from the pasted message
    sender = models.CharField(max_length=320, blank=True)
    subject = models.TextField(blank=True)

    # Body classifier
    body_phish_score = models.FloatField(default=0.0)  # 0–100, P(phishing) * 100

    # Header analysis (Authentication-Results)
    header_status = models.CharField(max_length=16, choices=HEADER_CHOICES, default=HEADER_UNKNOWN)
    header_spf = models.BooleanField(null=True, blank=True)
    header_dkim = models.BooleanField(null=True, blank=True)
    header_dmarc = models.BooleanField(null=True, blank=True)

    # MailCheck domain reputation (optional — populated when API succeeds)
    domain = models.TextField(blank=True)
    valid = models.BooleanField(null=True, blank=True)
    block = models.BooleanField(null=True, blank=True)
    disposable = models.BooleanField(null=True, blank=True)
    email_forwarder = models.BooleanField(null=True, blank=True)
    mx_host = models.TextField(blank=True)
    mx_ip = models.TextField(blank=True)
    mx_info = models.TextField(blank=True)
    risk = models.IntegerField(null=True, blank=True)

    final_verdict = models.CharField(max_length=16, choices=VERDICT_CHOICES, default=VERDICT_CLEAN)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.sender or '(no sender)'} — {self.final_verdict}"
