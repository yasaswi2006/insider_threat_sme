# TERPE: Threat Exposure and Risk Profiling Engine

Insider-threat detection for small and medium-sized enterprises (SMEs).

TERPE flags employees whose computer activity looks like data theft or misuse. For every employee and every day it combines three kinds of evidence into one risk score: unusual behaviour (machine learning), breaks of access rules, and known attack sequences. Every alert shows the exact files, computers, times and rules behind it, so a security analyst can see what happened and decide what to do.

**Live application:** https://insiderthreatsme-npdrkcjc6uxwmmury2hh3q.streamlit.app/
**Backend API:** https://insider-threat-sme.onrender.com (health check: `/health`)

---

## Contents

1. [Problem](#1-problem)
2. [What TERPE does](#2-what-terpe-does)
3. [Method](#3-method)
4. [Results](#4-results)
5. [Application](#5-application)
6. [Architecture and technology](#6-architecture-and-technology)
7. [Project structure](#7-project-structure)
8. [Running locally](#8-running-locally)
9. [Deployment](#9-deployment)
10. [Reproducing the results](#10-reproducing-the-results)
11. [API reference](#11-api-reference)
12. [Dataset](#12-dataset)
13. [Limitations and future work](#13-limitations-and-future-work)

---

## 1. Problem

An insider threat is harm caused by someone who already has legitimate access to an organisation's systems, such as an employee copying confidential files before leaving. Firewalls and antivirus software do not stop these people, because they are allowed in.

Small and medium-sized businesses rarely have a security team or expensive monitoring tools. They need something that:

- works from logs they already have (sign-ins, USB use, file copies),
- raises a small number of alerts a single person can review,
- explains each alert in plain terms instead of giving a bare score.

## 2. What TERPE does

- Learns each employee's normal setup: which computers they use, whether they use USB drives, whether they work late, and which file types they handle.
- Checks every sign-in, USB connection and file copy against that setup and marks it **Allowed**, **Needs review** or **Violation**, with the reason.
- Compares each day's activity with the employee's own past and with colleagues in the same job role, using an Isolation Forest model.
- Detects known attack sequences, such as signing in after hours, plugging in a USB drive and then copying files.
- Adds all of this into a running risk score that builds up over repeated suspicious days and fades over quiet ones, and raises an alert when it crosses a set line.
- Provides a web dashboard with role-based accounts, so each user sees only what their role allows and every action is recorded.

## 3. Method

### 3.1 Overview

```
Activity logs (sign-ins, USB, file copies, employee directory)
        |
        v
Step 1  Learn each employee's normal setup (first 30 days)
        |
        +--> Step 2  Rule checks on every event        -> rule-break score   p(t)
        +--> Step 3  Behaviour vs own past and peers   -> unusualness score a(t)
        +--> Step 4  Attack-sequence detection         -> sequence count    c(t)
                     |
                     v
Step 5  Day score e(t) = a(t) + p(t) + c(t)
        Risk R(t) = 0.8^(days since last activity) x R(t-1) + e(t)
        Alert when R(t) reaches the alert line (top 1% of all employee-days)
```

### 3.2 Step 1: Learn each employee's normal setup

The first 30 days after an employee's first sign-in form a learning window. From it TERPE records:

| Item | Meaning |
|---|---|
| Approved computers | Every computer the employee signed in to; the most used one is their main computer |
| USB approval | Whether they used a USB or other removable device at all |
| After-hours approval | Whether they ever signed in before 07:00, after 19:00 or at the weekend |
| Known file types | The file extensions they copied (.doc, .pdf, .exe and so on) |

A real company would set these permissions in its IT policy. The research dataset has no such policy, so TERPE learns them from the first month.

### 3.3 Step 2: Rule checks

After the learning window, every event is checked against five rules:

| Rule | Result | Weight |
|---|---|---|
| Computer not approved for this person (IT administrators exempt) | Violation | 3 |
| USB not approved for this person | Violation | 3 |
| New program file (.exe, .dll, .bat, .msi, .ps1, .vbs) copied by a non-IT employee | Violation | 3 |
| After-hours work by someone not approved for it | Needs review | 1 |
| File type the person has never handled before | Needs review | 1 |

The rule-break score for a day is the sum over rules of `weight x ln(1 + number of times broken)`, scaled to a 0 to 3 range. The logarithm stops fifty identical violations from counting fifty times as much as one.

### 3.4 Step 3: Behaviour compared with the past and with colleagues

Each day is summarised by 13 counts: sign-ins, distinct computers, after-hours sign-ins, USB connections, after-hours USB connections, files copied, sign-ins on non-approved computers, program files copied, distinct file types, files copied after hours, and three first-time flags (first USB use, first after-hours sign-in, first sign-in on another person's computer).

Each count is standardised two ways:

- **Against the employee's own past days only.** Each day is compared with the days before it, never with later days, so the same calculation works on live data.
- **Against colleagues in the same job role on the same day,** which catches people who behave unusually from their first day.

The raw counts and both comparisons (39 values per day) go into an **Isolation Forest** (200 trees, unsupervised, no labels used). An Isolation Forest finds unusual records by splitting the data at random: unusual days are separated after only a few splits. The unusualness score is how far a day's score lies above the 95th percentile of all days.

### 3.5 Step 4: Attack sequences

Three ordered patterns are checked within each employee-day, using event timestamps:

1. Signs in after hours, then connects a USB device, then copies files.
2. Signs in to a computer that is not theirs, then copies files on that computer.
3. Uses a USB device for the first time ever and copies files the same day.

### 3.6 Step 5: Risk score and alerts

The day score is the sum of the three evidence values, each with equal weight, so nothing is tuned on the answer key. The risk score carries over from day to day, losing 20% per calendar day:

```
R(t) = 0.8^(days since the previous active day) x R(t-1) + e(t)
```

An alert is raised when the risk score reaches the alert line. The line is set so that 1% of all employee-days raise an alert, which keeps the workload manageable for a small team. Employees are ranked by the highest risk score they reach.

### 3.7 What changed from the previous model

The first version of this project used only an Isolation Forest on six daily counts. It also compared each day with the employee's whole history, including future days, which a live system cannot do. The current model removes that look-ahead, adds the rule checks and attack sequences, and records the evidence behind every alert.

## 4. Results

Evaluated on the CERT Insider Threat dataset r4.2: 1,000 simulated employees, 70 of whom are known insiders. The dataset's answer key is used only to score the results, never to build or tune the model.

To show what each part contributes, the method was built up one step at a time from the previous model and measured after each step (an ablation study). All rows use the same data and the same 1% alert line.

| Model | Insiders in top 10 | Top 20 | Top 50 | Insiders caught during attack | Normal employees wrongly flagged | AUC | Average precision |
|---|---|---|---|---|---|---|---|
| Previous model (unusualness score only) | 5 | 10 | 22 | 10 / 70 | 16 | 0.84 | 0.33 |
| + compare only with past days | 5 | 7 | 14 | 7 / 70 | 13 | 0.86 | 0.28 |
| + compare with same-role colleagues | 5 | 9 | 14 | 12 / 70 | 36 | 0.78 | 0.27 |
| + 7 extra behaviour counts | 5 | 8 | 17 | 21 / 70 | 43 | 0.82 | 0.28 |
| + rule checks | 8 | 15 | 30 | 33 / 70 | 43 | 0.87 | 0.50 |
| **Current model (+ attack sequences)** | **10** | **19** | **37** | **40 / 70** | **44** | **0.88** | **0.61** |
| Rules only, no machine learning | 10 | 20 | 36 | 43 / 70 | 147 | 0.85 | 0.61 |

**How to read the columns**

- **Insiders in top 10 / 20 / 50:** real insiders among the employees with the highest risk scores. An analyst usually reviews only the top of the list.
- **Insiders caught during attack:** insiders who received an alert between their first malicious action and one week after their last.
- **Normal employees wrongly flagged:** non-insiders (out of 930) who received at least one alert.
- **AUC:** the probability that a randomly chosen insider has a higher risk score than a randomly chosen normal employee (0.5 is guessing, 1.0 is perfect).
- **Average precision:** how closely the insiders are packed at the top of the ranking (0 to 1). It is the stricter measure when, as here, only 7% of employees are insiders.

**Findings**

- The rule checks give the largest single improvement, and the attack sequences add to it. The current model catches 40 of 70 insiders during their attack, against 10 for the previous model, usually on the first malicious day.
- Machine learning alone does not beat the previous model. The second row is lower because it no longer looks at future days, an advantage the previous model had and a live system cannot.
- Rules alone find insiders well but wrongly flag 147 normal employees. Combining rules with machine learning and the running risk score keeps detection high while cutting false alerts by about 70%.

**By insider type (current model)**

| Insider type in the dataset | Insiders | Flagged |
|---|---|---|
| Starts working late and copying data to USB, then leaves | 30 | 29 |
| Disgruntled IT administrator plants a keylogger | 10 | 10 |
| Job-hunts, then copies data before leaving | 30 | 2 |

The job-hunting insiders were already approved USB users, and their main warning sign is web browsing, which this version does not use.

## 5. Application

### 5.1 Roles

Anyone can request an account from the sign-in page. An administrator approves or rejects the request and assigns a role.

| Role | Can see and do |
|---|---|
| Viewer | Overview, How it works, Results |
| Analyst | Everything a viewer can, plus individual employees, file-level activity and the risk check |
| Administrator | Everything an analyst can, plus approving and managing accounts and reading the audit log |
| Owner | The first administrator. Only the owner can give someone the administrator role, and no one else can change the owner's account |

### 5.2 Pages

| Page | Purpose |
|---|---|
| Overview | Company-wide risk: employees with alerts, rule breaks, highest-risk employees, weekly trend |
| Employees | One employee's risk over time; for any day, the reasons, every file copied, the computers used and how the day compares with their past and their colleagues |
| File activity | Every file copy across the company that broke a rule or needs review |
| Risk check | Enter one day of activity for an employee and see how it would be scored |
| How it works | Plain-language description of the method |
| Results | Evaluation results and what they mean |
| User management | Approve requests, change roles, disable accounts, reset passwords, read the audit log |
| My account | Change your own password |

**Evaluation mode** (sidebar switch) marks the employees that the dataset's answer key lists as insiders, so alerts can be checked against the truth. A real company would not have an answer key.

### 5.3 Security

- Passwords are hashed with PBKDF2-HMAC-SHA256 (600,000 iterations, a random salt per user) and are never stored in plain text.
- Passwords must have at least 10 characters with upper and lower case letters, a number and a symbol, and must not contain the username.
- Five failed sign-ins lock an account for 15 minutes.
- Temporary passwords issued by an administrator must be changed at the next sign-in.
- Sessions use signed tokens that expire after 8 hours.
- Every sign-in, failed sign-in, account change, employee investigation and risk check is written to the audit log.

## 6. Architecture and technology

```
Browser
   |
   v
Streamlit dashboard (app.py)            Streamlit Community Cloud
   |   HTTPS, signed session token
   v
FastAPI backend (api.py, auth.py)       Render
   |                    |
   v                    v
Results files       PostgreSQL           Neon (user accounts and audit log)
(results_v2/)
   ^
   |
Offline pipeline (pipeline.py) run on the CERT r4.2 logs
```

| Layer | Technology |
|---|---|
| Data processing and features | Python, pandas, NumPy, PyArrow (Parquet) |
| Machine learning | scikit-learn Isolation Forest for training; NumPy-only scoring at run time (`iforest_lite.py`) |
| Backend | FastAPI, Uvicorn, PyJWT |
| Accounts storage | PostgreSQL (Neon) in deployment, SQLite locally |
| Dashboard | Streamlit, Plotly |
| Hosting | Render (backend), Streamlit Community Cloud (dashboard) |

The backend keeps its memory below 512 MB (Render's free plan): numbers are stored as 32-bit values, only the columns needed for charts are kept in memory, per-day details are read from disk on demand, and the model is loaded on first use.

## 7. Project structure

```
insider_threat_sme/
  app.py               Streamlit dashboard
  api.py               FastAPI backend: data, risk check, accounts, audit log
  auth.py              Accounts, roles, password hashing, sessions, audit log
  pipeline.py          Builds all results from the raw CERT logs and runs the ablation study
  iforest_lite.py      Scores the trained Isolation Forest with NumPy only
  download_data.py     Downloads the needed CERT r4.2 files (about 290 MB)
  make_synthetic.py    Small synthetic dataset in CERT format, for testing the pipeline
  requirements.txt     Python packages
  RUN_LOCAL.bat        One-click start on Windows
  DOWNLOAD_DATA.bat    One-click data download on Windows
  .streamlit/
    config.toml        Dashboard theme
  results_v2/          Pipeline outputs used by the backend
    daily.parquet          one row per employee-day: counts, comparisons, scores, risk, reasons
    file_events.parquet    every file copy with its result and the rules it broke
    access_events.parquet  sign-ins and USB connections that were not allowed
    users.parquet          one row per employee: role, department, highest risk, alert days
    ablation.csv           evaluation results
    policy.json            access rules, working hours, weights
    model_v2.joblib        trained model (scikit-learn)
    model_lite.joblib      the same model as plain arrays, used by the backend
  v1_backup/           Code and results of the previous model
```

## 8. Running locally

Requirements: Python 3.11 or newer.

**Windows, one click:** double-click `RUN_LOCAL.bat`. On first run it installs the packages and asks for the administrator password. The dashboard opens at http://localhost:8501. Sign in as `yasaswi` with that password. Keep both command windows open while using it.

**Any system, manually:**

```bash
python -m pip install -r requirements.txt

# terminal 1: backend
export ADMIN_USERNAME=yasaswi
export ADMIN_PASSWORD='<strong password>'
export JWT_SECRET='<long random string>'
python -m uvicorn api:app --host 127.0.0.1 --port 8000

# terminal 2: dashboard
mkdir -p .streamlit && echo 'API_URL = "http://127.0.0.1:8000"' > .streamlit/secrets.toml
python -m streamlit run app.py
```

On Windows PowerShell use `$env:ADMIN_USERNAME="yasaswi"` instead of `export`.

## 9. Deployment

**Backend on Render.** Web service from this repository, `main` branch.

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn api:app --host 0.0.0.0 --port $PORT`
- Environment variables:

| Variable | Purpose |
|---|---|
| `JWT_SECRET` | Long random string used to sign sessions |
| `ADMIN_USERNAME` | Owner account, created on first start if no administrator exists |
| `ADMIN_PASSWORD` | Password for that account; change it after the first sign-in |
| `DATABASE_URL` | PostgreSQL connection string (Neon). Without it, accounts are kept in a local file that Render erases on every restart |

**Dashboard on Streamlit Community Cloud.** App file `app.py`, `main` branch. The only secret needed is:

```toml
API_URL = "https://insider-threat-sme.onrender.com"
```

Pushing to `main` redeploys both automatically. On Render's free plan the backend sleeps when unused, so the first request after a pause can take up to a minute.

## 10. Reproducing the results

```bash
python -m pip install -r requirements.txt huggingface_hub
python download_data.py                         # about 290 MB into data/
python pipeline.py --data data --out results_v2 # about 2 minutes
```

The pipeline prints the ablation table and writes every file in `results_v2/`. To test the pipeline without the real data:

```bash
python make_synthetic.py synth
python pipeline.py --data synth --out synth_out
```

## 11. API reference

All endpoints except `/health`, `/auth/signup` and `/auth/login` require the header `Authorization: Bearer <token>`. Interactive documentation is available at `/docs` on the backend.

| Method and path | Role | Description |
|---|---|---|
| `GET /health` | none | Service status |
| `POST /auth/signup` | none | Request an account (pending approval) |
| `POST /auth/login` | none | Sign in; returns a session token |
| `GET /auth/me` | any | Current user |
| `POST /auth/change-password` | any | Change own password |
| `GET /overview` | viewer | Company-wide figures |
| `GET /users/top?n=` | viewer | Employees ranked by highest risk |
| `GET /evaluation` | viewer | Ablation results and access rules |
| `GET /users/{id}/profile` | analyst | One employee's summary |
| `GET /users/{id}/timeline` | analyst | Daily scores and risk |
| `GET /users/{id}/day/{yyyy-mm-dd}` | analyst | Reasons, files, events and comparisons for one day |
| `GET /users/{id}/files` | analyst | All file copies by one employee |
| `GET /files/feed?verdict=` | analyst | Company-wide file copies that broke a rule or need review |
| `POST /score` | analyst | Score one day of activity |
| `GET /admin/users` | admin | All accounts |
| `POST /admin/users` | admin | Create an account with a temporary password |
| `PATCH /admin/users/{id}` | admin | Change role or status (approve, reject, disable) |
| `POST /admin/users/{id}/reset-password` | admin | Issue a temporary password |
| `GET /admin/audit` | admin | Audit log |

## 12. Dataset

CERT Insider Threat Test Dataset, release r4.2, published by the CERT Division of the Software Engineering Institute, Carnegie Mellon University: Lindauer, B. (2020). *Insider Threat Test Dataset*. https://doi.org/10.1184/R1/12841247.v1

| Item | Value |
|---|---|
| Period | 2 January 2010 to 17 May 2011 |
| Employees | 1,000, with monthly directory snapshots (role, department, supervisor) |
| Sign-in and sign-out events | 854,859 |
| USB connect and disconnect events | 405,380 |
| File copies to USB | 445,581 |
| Insiders | 70 (30, 30 and 10 across three scenarios) |

The raw data is not stored in this repository. Run `download_data.py` to fetch it.

## 13. Limitations and future work

**Limitations**

- The dataset is synthetic and contains far more insiders than a real company would.
- The dataset has no access policy, so each employee's permissions are learned from their first 30 days.
- Release r4.2 records only files copied to USB, not every file opened, edited or deleted.
- Web browsing and email are not used, which is why job-hunting insiders are mostly missed.
- A high risk score is a reason to look closer, not proof of wrongdoing. Decisions about people need human review.

**Future work**

- Add web-browsing and email signals (job sites, cloud storage uploads, emails to personal addresses).
- Test on CERT r5.2 and r6.2; r6.2 also records file opens, edits and deletions.
- Let administrators edit access permissions in the dashboard instead of learning them.
- Collect analyst feedback on alerts to adjust rule weights over time.
- Send alert notifications by email.
