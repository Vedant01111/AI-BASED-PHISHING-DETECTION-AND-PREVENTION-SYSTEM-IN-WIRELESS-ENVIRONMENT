from rest_framework import serializers

from .models import EmailReport


class EmailReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailReport
        fields = "__all__"


class GetEmailReportSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    class Meta:
        model = EmailReport
        fields = [
            "id", "user", "created_at",
            "sender", "subject",
            "body_phish_score",
            "header_status", "header_spf", "header_dkim", "header_dmarc",
            "domain", "valid", "block", "disposable", "email_forwarder",
            "mx_host", "mx_ip", "mx_info", "risk",
            "final_verdict",
        ]

    def get_user(self, obj):
        return obj.user.full_name
