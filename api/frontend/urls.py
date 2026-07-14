from django.urls import path

from . import views

urlpatterns = [
    path('', views.LandingView.as_view(), name='landing'),

    path('sign-in/', views.SignInView.as_view(), name='sign-in'),
    path('sign-up/', views.SignUpView.as_view(), name='sign-up'),
    path('sign-out/', views.SignOutView.as_view(), name='sign-out'),

    path('profile/', views.ProfileView.as_view(), name='profile'),
    path('profile/password/', views.ProfilePasswordChangeView.as_view(), name='profile-password'),

    path('scan/web/', views.WebScanView.as_view(), name='scan-web'),
    path('scan/email/', views.EmailScanView.as_view(), name='scan-email'),

    path('reports/web/', views.WebReportsView.as_view(), name='reports-web'),
    path('reports/email/', views.EmailReportsView.as_view(), name='reports-email'),
]
