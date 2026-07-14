from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import AuthenticationForm, BaseUserCreationForm

User = get_user_model()


TAILWIND_INPUT = (
    'block w-full rounded-md border border-slate-300 bg-white px-3 py-2 '
    'text-sm text-slate-900 placeholder:text-slate-400 shadow-sm '
    'focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500'
)


def _tw(field, placeholder=None, **extra):
    attrs = {'class': TAILWIND_INPUT}
    if placeholder is not None:
        attrs['placeholder'] = placeholder
    attrs.update(extra)
    field.widget.attrs.update(attrs)
    return field


class SignInForm(AuthenticationForm):
    username = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(attrs={'class': TAILWIND_INPUT, 'placeholder': 'example@mail.com', 'autofocus': True}),
    )
    password = forms.CharField(
        label='Password',
        strip=False,
        widget=forms.PasswordInput(attrs={'class': TAILWIND_INPUT, 'placeholder': '••••••••'}),
    )


class SignUpForm(BaseUserCreationForm):
    first_name = forms.CharField(max_length=30)
    last_name = forms.CharField(max_length=30)
    email = forms.EmailField()

    class Meta:
        model = User
        fields = ('email', 'first_name', 'last_name')

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name in ('email', 'first_name', 'last_name', 'password1', 'password2'):
            if name in self.fields:
                _tw(self.fields[name], placeholder=self.fields[name].label)


class WebScanForm(forms.Form):
    url = forms.URLField(
        label='URL',
        widget=forms.URLInput(attrs={'class': TAILWIND_INPUT, 'placeholder': 'https://example.com'}),
    )


class EmailScanForm(forms.Form):
    raw_email = forms.CharField(
        label='Email source',
        widget=forms.Textarea(attrs={
            'class': TAILWIND_INPUT + ' font-mono text-xs',
            'rows': 16,
            'placeholder': (
                'Paste the full email source (use "Show original" / "View source" in your mail '
                'client). Headers are optional — body-only paste works too, but you lose the '
                'SPF / DKIM / DMARC signal.'
            ),
        }),
    )
