import pickle
from rest_framework import status, permissions,authentication
from rest_framework.response import Response
from authentication.models import UserModel
from rest_framework.views import APIView
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
from .models import WebReport
from .serializers import WebReportSerializer, GetWebReportSerializer
import numpy as np
import ipaddress
import requests
import socket
import whois
import re
from django.conf import settings

BAD_REQUEST = status.HTTP_400_BAD_REQUEST
GET_REQUEST = status.HTTP_200_OK
CREATE_REQUEST = status.HTTP_201_CREATED
RAPID_API_KEY = settings.WEB_RAPIDAPI_KEY

_gbc = None
_gbc_load_error = None

def get_gbc():
    global _gbc, _gbc_load_error
    if _gbc is not None or _gbc_load_error is not None:
        return _gbc
    try:
        with open(str(settings.BASE_DIR.parent) + "/pickle/model.pkl", "rb") as fh:
            _gbc = pickle.load(fh)
    except Exception as exc:
        _gbc_load_error = exc
        _gbc = None
    return _gbc

def save_data(data,phishing_score,non_phishing_score,user,url):
    organized_data = {
        "user": str(user.id),
        "url": url,
        "phishing_score": phishing_score,
        "non_phishing_score": non_phishing_score,
        "is_ip_address": data[0],
        "long_url": data[1],
        "shor_turl": data[2],
        "symbol": data[3],
        "redirect": data[4],
        "prefix_suffix": data[5],
        "subdomains": data[6],
        "https": data[7],
        "domainreglen": data[8],
        "favicon": data[9],
        "non_std_port": data[10],
        "httpsdomainurl": data[11],
        "requesturl": data[12],
        "anchorurl": data[13],
        "linksinscripttags": data[14],
        "serverformhandler": data[15],
        "infoemail": data[16],
        "abnormalurl": data[17],
        "websiteforwarding": data[18],
        "statusbarcust": data[19],
        "disablerightclick": data[20],
        "usingpopupwindow": data[21],
        "iframeredirection": data[22],
        "ageofdomain": data[23],
        "dnsrecording": data[24],
        "websitetraffic": data[25],
        "pagerank": data[26],
        "googleindex": data[27],
        "linkspointingtopage": data[28],
        "statsreport": data[29]
    }
    serializer = WebReportSerializer(data=organized_data)
    if serializer.is_valid():
        serializer.save()
        return True, serializer.data
    return False, serializer.errors

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""
        self.expiration_date = ""
        self.creation_date = ""
        self.visits = 0
        self.rank = 0
        self.index = 0

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc

            self.whois_response = whois.whois(self.domain)
            if self.whois_response.expiration_date and type(self.whois_response.expiration_date) is list:
                self.expiration_date = self.whois_response.expiration_date[0]
            elif self.whois_response.expiration_date and type(self.whois_response.expiration_date) is not list:
                self.expiration_date = self.whois_response.expiration_date
            else:
                self.expiration_date = None
            
            if self.whois_response.creation_date and type(self.whois_response.creation_date) is list:
                self.creation_date = self.whois_response.creation_date[0]
            elif self.whois_response.creation_date and type(self.whois_response.creation_date) is not list:
                self.creation_date = self.whois_response.creation_date
            else:
                self.creation_date = None
            
            url = "https://similarweb13.p.rapidapi.com/v2/getdomain"
            querystring = {"domain":self.domain}
            headers = {
                "X-RapidAPI-Key": RAPID_API_KEY,
                "X-RapidAPI-Host": "similarweb13.p.rapidapi.com"
            }
            response = requests.get(url, headers=headers, params=querystring)
            self.visits = response.json()['data']['Engagments']['Visits']
            self.rank = response.json()['data']['GlobalRank']['Rank']
            self.index = response.json()['data']['CategoryRank']['Rank']
        except requests.RequestException:
            pass
        except ValueError:
            pass
        except:
            pass
        
        self.features = [
            self.using_ip,
            self.long_url,
            self.short_url,
            self.symbol,
            self.redirecting,
            self.prefix_suffix,
            self.sub_domains,
            self.https,
            self.domain_reg_len,
            self.favicon,
            self.non_std_port,
            self.https_domain_url,
            self.request_url,
            self.anchor_url,
            self.links_in_script_tags,
            self.server_form_handler,
            self.info_email,
            self.abnormal_url,
            self.website_forwarding,
            self.status_bar_cust,
            self.disable_right_click,
            self.using_popup_window,
            self.iframe_redirection,
            self.age_of_domain,
            self.dns_recording,
            self.website_traffic,
            self.page_rank,
            self.google_index,
            self.links_pointing_to_page,
            self.stats_report,
        ]

    def using_ip(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except ValueError:
            return 1

    def long_url(self):
        url_length = len(self.url)
        if url_length < 54:
            return 1
        elif 54 <= url_length <= 75:
            return 0
        else:
            return -1

    def short_url(self):
        short_url_patterns = re.compile(
            r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
            r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
            r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
            r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
            r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
            r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net'
        )
        return -1 if short_url_patterns.search(self.url) else 1
    
    def symbol(self):
        return -1 if '@' in self.url else 1
    
    def redirecting(self):
        return -1 if self.url.count('//') > 6 else 1
    
    def prefix_suffix(self):
        try:
            return -1 if '-' in self.domain else 1
        except:
            return -1
    
    def sub_domains(self):
        dot_count = self.url.count('.')
        return 1 if dot_count == 1 else (0 if dot_count == 2 else -1)
    
    def https(self):
        try:
            return 1 if 'https' in self.urlparse.scheme else -1
        except:
            return 1

    def domain_reg_len(self):
        try:            
            if self.expiration_date and self.creation_date:
                age = self.expiration_date.year - self.creation_date.year
            return 1 if age >= 12 else -1
        except Exception as e:
            return -1

    def favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for link in head.find_all('link', href=True):
                    dots = link['href'].count('.')
                    if self.url in link['href'] or dots == 1 or self.domain in link['href']:
                        return 1
            return -1
        except Exception as e:
            return -1

    def non_std_port(self):
        try:
            port = self.domain.split(":")
            return -1 if len(port) > 1 else 1
        except Exception as e:
            return -1

    def https_domain_url(self):
        try:
            return -1 if 'https' in self.domain else 1
        except Exception as e:
            return -1

    def request_url(self):
        try:
            success = 0
            total = 0

            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    dots = element['src'].count('.')
                    if self.url in element['src'] or self.domain in element['src'] or dots == 1:
                        success += 1
                    total += 1

            try:
                percentage = success / float(total) * 100
                if percentage < 22.0:
                    return 1
                elif 22.0 <= percentage < 61.0:
                    return 0
                else:
                    return -1
            except ZeroDivisionError:
                return 0

        except Exception as e:
            return -1

    def anchor_url(self):
        try:
            total, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                total += 1
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe += 1

            try:
                percentage = (unsafe / total) * 100
                if percentage < 31.0:
                    return 1
                elif 31.0 <= percentage < 67.0:
                    return 0
                else:
                    return -1
            except ZeroDivisionError:
                return -1
        except Exception as e:
            return -1

    def links_in_script_tags(self):
        try:
            total, success = 0, 0

            for tag in ['link', 'script']:
                for element in self.soup.find_all(tag, href=True):
                    total += 1
                    dots = element['href'].count('.')
                    if self.url in element['href'] or self.domain in element['href'] or dots == 1:
                        success += 1

            try:
                percentage = (success / total) * 100
                if percentage < 17.0:
                    return 1
                elif 17.0 <= percentage < 81.0:
                    return 0
                else:
                    return -1
            except ZeroDivisionError:
                return 0
        except Exception as e:
            return -1

    def server_form_handler(self):
        try:
            forms = self.soup.find_all('form', action=True)
            if not forms:
                return 1

            for form in forms:
                if form['action'] == "" or form['action'] == "about:blank":
                    return -1
                elif self.url not in form['action'] and self.domain not in form['action']:
                    return 0

            return 1
        except Exception as e:
            return -1

    def info_email(self):
        try:
            if re.search(r"(?:mailto:)?[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", self.response.text):
                return -1
            else:
                return 1
        except Exception as e:
            return -1

    def abnormal_url(self):
        try:
            if self.response.text == self.whois_response:
                return 1
            else:
                return -1
        except Exception as e:
            return -1

    def website_forwarding(self):
        try:
            history_length = len(self.response.history)
            if history_length <= 1:
                return 1
            elif history_length <= 4:
                return 0
            else:
                return -1
        except Exception as e:
            return -1

    def status_bar_cust(self):
        try:
            if re.search(r"<script>.+onmouseover.+</script>", self.response.text):
                return 1
            else:
                return -1
        except Exception as e:
            return -1

    def disable_right_click(self):
        try:
            if re.search(r"event\.button\s*===\s*2", self.response.text):
                return 1
            else:
                return -1
        except Exception as e:
            return -1

    def using_popup_window(self):
        try:
            if re.search(r"alert\(", self.response.text):
                return 1
            else:
                return -1
        except Exception as e:
            return -1

    def iframe_redirection(self):
        try:
            if re.search(r"<iframe>|<frameBorder>", self.response.text):
                return 1
            else:
                return -1
        except Exception as e:
            return -1

    def age_of_domain(self):
        try:
            if self.creation_date:
                today = datetime.today()
                age = (today - self.creation_date).days
                return 1 if age >= 2191 else -1
            return -1
        except Exception as e:
            return -1

    def dns_recording(self):
        return self.age_of_domain()  # Reusing the age_of_domain method

    def website_traffic(self):
        try:            
            return 1 if int(self.visits) < 100000 else 0
        except Exception as e:
            return -1

    def page_rank(self):
        try:
            return 1 if 0 < int(self.rank) < 100000 else -1
        except Exception as e:
            return -1

    def google_index(self):
        try:
            return 1 if 0 < int(self.index) else -1
        except Exception as e:
            return 1

    def links_pointing_to_page(self):
        try:
            number_of_links = self.response.text.count("<a href=")
            if number_of_links == 0:
                return 1
            elif number_of_links <= 2:
                return 0
            else:
                return -1
        except Exception as e:
            return -1

    def stats_report(self):
        try:
            url_match = re.search(
                r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',
                self.url)
            ip_address = socket.gethostbyname(self.domain)
            ip_match = re.search(
                r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                r'107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                r'118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                r'216\.218\.185\.162|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                r'216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match or ip_match:
                return -1
            return 1
        except Exception as e:
            return 1

class WebPhishingDetection(APIView):
    authentication_classes = [authentication.TokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        try:
            request_data = request.data
            if not request.auth:
                return Response('User is not authenticated!', status=status.HTTP_400_BAD_REQUEST)            
            user_id = request.auth.user.pk
            if not UserModel.objects.filter(id=user_id).exists():
                return Response('You do not have access!', status=status.HTTP_400_BAD_REQUEST)
            user = UserModel.objects.get(id=user_id)
            url = request_data.get('url', '').strip()
            if not url:
                return Response("URL should not be empty!", status=status.HTTP_400_BAD_REQUEST)
            if WebReport.objects.filter(url=url).exists():
                web_data = WebReport.objects.filter(url=url)
                serializer = WebReportSerializer(instance=web_data, many=True)
                return Response({"data":serializer.data}, status=GET_REQUEST)
            feature_extractor = FeatureExtraction(url)
            features = [method() for method in feature_extractor.features]
            x = np.array(features).reshape(1,30)
            gbc = get_gbc()
            if gbc is None:
                return Response(
                    "URL classifier model failed to load. Check sklearn version compatibility with pickle/model.pkl.",
                    status=BAD_REQUEST, exception=True,
                )
            phishing_score = gbc.predict_proba(x)[0,0]
            phishing_score = round((phishing_score*100), 2)
            non_phishing_score = gbc.predict_proba(x)[0,1]
            non_phishing_score = round((non_phishing_score*100), 2)
            is_valid, data = save_data(features,phishing_score,non_phishing_score,user,url)
            if not is_valid:
                return Response("Invalid Query!", status=BAD_REQUEST, exception=True)
            return Response({"data":data}, status=CREATE_REQUEST)
        except Exception as e:
            print(e)
            return Response(str(e), status=BAD_REQUEST, exception=True)
    
    def get(self, request):
        try:
            reports = WebReport.objects.filter()
            serializer = GetWebReportSerializer(instance=reports, many=True)
            return Response(serializer.data, status=GET_REQUEST)
        except Exception as e:
            return Response(str(e), status=BAD_REQUEST)