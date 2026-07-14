# iSecure — Phishing Detection Platform

A full-stack phishing detection system that classifies suspicious **emails** and **web URLs** using machine learning and rule-based heuristics. Built on Django with server-rendered templates styled with Tailwind CSS and progressively enhanced with Alpine.js.

---

## Features

- **Email Detection** — paste any email source (`Show original` from Gmail, `View source` from Outlook). The backend parses headers + body, runs a TF-IDF + LogisticRegression classifier on the body, parses SPF / DKIM / DMARC from `Authentication-Results`, and combines the two signals into a single Phishing / Suspicious / Clean verdict with an explanation.
- **Web/URL Detection** — extracts 30 features from a target URL (IP-as-host, URL length, shortener patterns, prefix/suffix, subdomain count, HTTPS, WHOIS domain age, favicon origin, anchor/request URL ratios, iframe redirection, page rank, traffic, and more) and scores it with a pre-trained gradient boosting classifier loaded from `pickle/model.pkl`.
- **Session-based Authentication** — Django's built-in `LoginView`/`LogoutView` with email as the username field. The original DRF Token / Djoser endpoints remain available for any non-browser clients.
- **Reports** — every scan is persisted (`EmailReport`, `WebReport`) and rendered as paginated tables.

---

## Architecture

```
phishing-detection/
├── api/                       # Django 4.2 project
│   ├── api/                   # Project settings + URL router
│   ├── authentication/        # Custom user model, Djoser, JWT
│   ├── email_phishing/        # Email parser + body classifier + header analysis
│   ├── web_phishing/          # URL feature extraction + classifier
│   ├── frontend/              # Server-rendered templates (Tailwind + Alpine)
│   │   ├── views.py           # FormViews / ListViews that reuse the scan helpers
│   │   ├── forms.py
│   │   ├── urls.py
│   │   ├── templates/         # base.html, landing, auth/, scan/, reports/
│   │   └── static/frontend/   # Logos, icons, landing imagery
│   ├── manage.py
│   └── db.sqlite3
├── pickle/model.pkl           # Pre-trained URL phishing classifier (30 features)
├── pickle/email_model.joblib  # Pre-trained email body classifier (TF-IDF + LR)
├── spam_mails.csv             # Email training corpus (~50 MB) — input to email train_model.py
├── requirements.txt           # Python dependencies
├── install_project.bat        # Windows: bootstrap venv + install deps + migrate
└── run_project.bat            # Windows: start the Django server
```

### Tech Stack

| Layer        | Technology                                                                 |
|--------------|----------------------------------------------------------------------------|
| Backend      | Django 4.2.7, Django REST Framework 3.14, Djoser, SimpleJWT                |
| ML / Data    | scikit-learn 1.0.1, pandas 2.2, numpy 1.26, joblib, BeautifulSoup4         |
| URL Intel    | python-whois, RapidAPI (MailCheck, SimilarWeb)                             |
| Database     | SQLite (default `db.sqlite3`)                                              |
| Frontend     | Django templates · Tailwind CSS (Play CDN) · Alpine.js                     |

No Node.js / npm toolchain is required — Tailwind and Alpine load from CDNs.

---

## Requirements

- **Python** ≥ 3.6 and < 3.12 (the bundled scikit-learn 1.0.1 wheel does not build on 3.12+)
- (Optional) RapidAPI key for the MailCheck and SimilarWeb endpoints — currently hardcoded in `email_phishing/views.py` and `web_phishing/views.py` (see *Security Notes*). The app degrades gracefully if these calls fail.

---

## Installation

### Quick Start (Windows)

```bat
install_project.bat
run_project.bat
```

`install_project.bat` creates a virtualenv, installs Python deps, runs Django migrations, and collects static files. `run_project.bat` starts the Django server on port 8000 and opens your browser.

### Manual Setup (macOS / Linux / Windows)

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

cd api
python manage.py migrate
python manage.py collectstatic --noinput
python manage.py runserver        # http://127.0.0.1:8000
```

Visit `http://127.0.0.1:8000/` — the landing page, all auth, all scans, and all reports are served from the same port.

---

## URL Map

### Browser pages (server-rendered templates)

| Path                  | Template                  | Auth      |
|-----------------------|---------------------------|-----------|
| `/`                   | `landing.html`            | public    |
| `/sign-in/`           | `auth/sign_in.html`       | anonymous |
| `/sign-up/`           | `auth/sign_up.html`       | anonymous |
| `/sign-out/` (POST)   | redirects to `/`          | required  |
| `/profile/`           | `profile.html`            | required  |
| `/profile/password/`  | `profile_password.html`   | required  |
| `/scan/web/`          | `scan/web_form.html`      | required  |
| `/scan/email/`        | `scan/email_form.html`    | required  |
| `/reports/web/`       | `reports/web.html`        | required  |
| `/reports/email/`     | `reports/email.html`      | required  |

### JSON API (DRF Token auth, unchanged)

| Method | Path                  | Purpose                                                     |
|--------|-----------------------|-------------------------------------------------------------|
| POST   | `/auth/users/`        | Register a new user (Djoser)                                |
| POST   | `/auth/token/login/`  | Obtain auth token                                           |
| GET    | `/my-account/`        | Current user profile                                        |
| POST   | `/scan-email/`        | Submit `{"raw_email": "<RFC 822 source>"}` → JSON verdict    |
| POST   | `/scan-web/`          | Extract 30 features from a URL and return phishing score    |
| GET    | `/scan-{email,web}/`  | List the caller's scan history                              |

---

## How Detection Works

### Retraining the URL classifier

The bundled `pickle/model.pkl` was originally produced with scikit-learn 1.0.1, whose tree-node binary layout is incompatible with sklearn ≥ 1.3. To rebuild the model on whatever scikit-learn you currently have installed:

```bash
# one-time: fetch the UCI Mohammad phishing dataset (~800 KB)
mkdir -p api/web_phishing/data
curl -L -o api/web_phishing/data/phishing.arff \
  "https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff"

# train and overwrite pickle/model.pkl
python api/web_phishing/train_model.py
```

The script trains a `GradientBoostingClassifier` on 11,055 labeled examples (~97% test accuracy) and writes a sklearn-version-matched `pickle/model.pkl`. Re-run after any future major sklearn bump.

### URL Phishing — 30 Features

`web_phishing.views.FeatureExtraction` derives a `[-1, 0, 1]` vote for each feature (suspicious / neutral / safe). Notable signals:

- **Lexical**: IP-as-host, URL length, shortener patterns (`bit.ly`, `t.co`, …), `@` symbol, `//` redirects, `-` in domain, subdomain depth.
- **HTTPS / TLS**: scheme check, `https` token inside the domain.
- **Page content**: anchor URL ratios, `<img>/<iframe>/<embed>` request-URL origin, `<script>/<link>` references, server form handler targets, `mailto:` patterns, popup / right-click disable / iframe redirection.
- **Network / WHOIS**: domain registration length, age of domain, DNS recording, SimilarWeb traffic & rank, Google index, blacklist IP/URL match.

The 30-feature vector is fed to the pre-trained classifier loaded from `pickle/model.pkl` for `predict_proba`.

### Email Phishing — Combined Header + Body Pipeline

`/scan/email/` accepts the **full RFC 822 source** of a single email (or just the body if that's all the user has). Detection runs two independent signals and combines them.

**1. Body classifier** (`pickle/email_model.joblib`)

A scikit-learn `Pipeline` trained on the bundled `spam_mails.csv` (~18 K labeled examples).
- `FeatureUnion` of word-level (1-2 gram) + char-level (3-5 char_wb) TF-IDF
- `LogisticRegression(C=4.0, class_weight='balanced')`
- 0.997 ROC-AUC, 97.5 % accuracy on a 20% holdout

Outputs `P(phishing) ∈ [0, 1]`. Re-train any time with:

```bash
python api/email_phishing/train_model.py
```

**2. Header analysis** (`parse_auth_results`)

Iterates **all** `Authentication-Results` / `ARC-Authentication-Results` headers, OR-combines pass results across them, and produces one of:

- `pass` — SPF, DKIM **and** DMARC all reported `pass`
- `fail` — at least one mechanism explicitly `fail`
- `unknown` — header missing or only partial-pass

**3. Combined verdict** (`combine_verdict`)

| `body P(phishing)` | header status | Verdict |
|---|---|---|
| ≥ 70% | any | 🚨 **Phishing** |
| 40 – 70% | `fail` | 🚨 **Phishing** (likely impersonation) |
| 40 – 70% | `unknown` | ⚠️ **Suspicious** |
| 40 – 70% | `pass` | ⚠️ **Suspicious** (verify sender) |
| < 40% | `fail` | ⚠️ **Suspicious** (sender impersonation) |
| < 40% | `pass` / `unknown` | ✅ **Clean** |

The result page renders the final verdict, the body % score, the per-mechanism SPF/DKIM/DMARC breakdown, and a short list of the rule-evaluator's *reasons* — so the user always understands why a scan was flagged.

**4. Optional sender-domain reputation**

If the email had a parseable `From:` header, the backend additionally calls the MailCheck RapidAPI for the *domain* (correctly, not the full address as the original code did). Failures are silently ignored — the verdict isn't blocked on it. When the call succeeds, `disposable`, `block`, `risk`, and MX info are persisted alongside the rest of the report.

---

## Security Notes

This project is an academic prototype. Before deploying anything publicly you should:

- **Rotate the RapidAPI key** hardcoded in `api/email_phishing/views.py` and `api/web_phishing/views.py`, and move it to environment variables.
- **Avoid loading the bundled model files from untrusted sources** — both `pickle/model.pkl` and `pickle/email_model.joblib` deserialize Python objects, which can execute arbitrary code if the file is tampered with. Treat them as artifacts that must come from a trusted build (or always retrain from CSV/ARFF locally).
- **Lock down `DEBUG=False`** and configure `ALLOWED_HOSTS` / `CORS_ALLOWED_ORIGINS` in `api/api/settings.py` for production.
- **Audit dependencies** — several pins in `requirements.txt` are old enough to have known CVEs.

---




