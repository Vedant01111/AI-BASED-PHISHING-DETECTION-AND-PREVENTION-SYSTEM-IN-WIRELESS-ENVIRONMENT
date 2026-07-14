from django.contrib import admin
from django.urls import path,include,re_path
from authentication.initials import create_default_profile
from email_phishing.views import EmailPhishingDetection
from web_phishing.views import WebPhishingDetection
from django.conf import settings
from django.conf.urls.static import static
from django.db.models.signals import post_migrate
from authentication.views import Me

urlpatterns = [
    path('', include('frontend.urls')),
    path('admin/', admin.site.urls),
    re_path(r'^auth/', include('djoser.urls')),
    re_path(r'^auth/', include('djoser.urls.authtoken')),
    path('my-account/', Me.as_view()),
    path('scan-email/', EmailPhishingDetection.as_view()),
    path('scan-web/', WebPhishingDetection.as_view()),
]

if settings.DEBUG:
        urlpatterns += static(settings.STATIC_URL,document_root=settings.STATIC_ROOT)
        urlpatterns += static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)

post_migrate.connect(create_default_profile)