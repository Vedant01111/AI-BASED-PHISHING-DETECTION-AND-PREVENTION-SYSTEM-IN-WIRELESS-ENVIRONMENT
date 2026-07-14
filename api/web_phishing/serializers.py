from rest_framework import serializers
from .models import WebReport

class WebReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebReport
        fields = '__all__'


class GetWebReportSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    class Meta:
        model = WebReport
        fields = [ "id", "user", "url", "phishing_score", "non_phishing_score", "is_ip_address", "long_url", "shor_turl", 
                  "symbol", "redirect", "prefix_suffix", "subdomains", "https", "domainreglen", "favicon", "non_std_port", 
                  "httpsdomainurl", "requesturl", "anchorurl", "linksinscripttags", "serverformhandler", "infoemail", "abnormalurl", 
                  "websiteforwarding", "statusbarcust", "disablerightclick", "usingpopupwindow", "iframeredirection", "ageofdomain", 
                  "dnsrecording", "websitetraffic", "pagerank", "googleindex", "linkspointingtopage", "statsreport", "stats_report",
                ]
    
    def get_user(self, obj):
        return obj.user.full_name