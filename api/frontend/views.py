import numpy as np
from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import (
    LoginView,
    LogoutView,
    PasswordChangeView,
)
from django.urls import reverse_lazy
from django.views.generic import FormView, ListView, TemplateView

from email_phishing.models import EmailReport
from email_phishing.views import analyze_email
from web_phishing.models import WebReport
from web_phishing.views import FeatureExtraction, get_gbc, save_data

from .forms import EmailScanForm, SignInForm, SignUpForm, WebScanForm


# ---------- Public ----------

class LandingView(TemplateView):
    template_name = 'landing.html'


# ---------- Auth ----------

class SignInView(LoginView):
    template_name = 'auth/sign_in.html'
    authentication_form = SignInForm
    redirect_authenticated_user = True


class SignUpView(FormView):
    template_name = 'auth/sign_up.html'
    form_class = SignUpForm
    success_url = reverse_lazy('landing')

    def form_valid(self, form):
        user = form.save()
        auth_login(self.request, user)
        messages.success(self.request, 'Welcome to iSecure! Your account has been created.')
        return super().form_valid(form)


class SignOutView(LogoutView):
    next_page = reverse_lazy('landing')


class ProfilePasswordChangeView(LoginRequiredMixin, PasswordChangeView):
    template_name = 'profile_password.html'
    success_url = reverse_lazy('profile')

    def form_valid(self, form):
        messages.success(self.request, 'Password changed successfully.')
        return super().form_valid(form)


# ---------- Profile ----------

class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = 'profile.html'


# ---------- Scans ----------

class WebScanView(LoginRequiredMixin, FormView):
    template_name = 'scan/web_form.html'
    form_class = WebScanForm

    def form_valid(self, form):
        url = form.cleaned_data['url'].strip()
        existing = WebReport.objects.filter(url=url).first()
        if existing:
            return self.render_to_response(self.get_context_data(form=form, report=existing, cached=True))
        try:
            gbc = get_gbc()
            if gbc is None:
                messages.error(self.request, 'URL classifier model failed to load. The bundled model.pkl needs scikit-learn 1.0.1.')
                return self.form_invalid(form)
            extractor = FeatureExtraction(url)
            features = [method() for method in extractor.features]
            x = np.array(features).reshape(1, 30)
            phishing_score = round(float(gbc.predict_proba(x)[0, 0]) * 100, 2)
            non_phishing_score = round(float(gbc.predict_proba(x)[0, 1]) * 100, 2)
            ok, data = save_data(features, phishing_score, non_phishing_score, self.request.user, url)
            if not ok:
                messages.error(self.request, f'Could not save scan: {data}')
                return self.form_invalid(form)
            report = WebReport.objects.get(url=url)
            return self.render_to_response(self.get_context_data(form=form, report=report, cached=False))
        except Exception as exc:
            messages.error(self.request, f'Scan failed: {exc}')
            return self.form_invalid(form)


class EmailScanView(LoginRequiredMixin, FormView):
    template_name = 'scan/email_form.html'
    form_class = EmailScanForm

    def form_valid(self, form):
        raw = form.cleaned_data['raw_email']
        try:
            result = analyze_email(raw, self.request.user)
        except (RuntimeError, ValueError) as exc:
            messages.error(self.request, str(exc))
            return self.form_invalid(form)
        return self.render_to_response(self.get_context_data(form=form, result=result))


# ---------- Reports ----------

class WebReportsView(LoginRequiredMixin, ListView):
    template_name = 'reports/web.html'
    context_object_name = 'reports'
    paginate_by = 25

    def get_queryset(self):
        return WebReport.objects.filter(user=self.request.user).order_by('-id')


class EmailReportsView(LoginRequiredMixin, ListView):
    template_name = 'reports/email.html'
    context_object_name = 'reports'
    paginate_by = 25

    def get_queryset(self):
        return EmailReport.objects.filter(user=self.request.user).order_by('-created_at')
