# TERPE v2 — Threat Exposure & Risk Profiling Engine

**Policy-grounded, peer-aware insider-threat detection for SMEs**, evaluated on the CMU CERT Insider Threat dataset r4.2.

TERPE v2 fuses three independent kinds of evidence into one accumulated risk per employee:

1. **Behaviour anomaly (ML).** An Isolation Forest compares each user-day with the employee's own past days *and* with same-role peers.
2. **Access-policy verdicts (rules).** Every logon, USB connection and file transfer is checked against an explicit access policy and labelled **Authorised / Review / Violation**, with the reason.
3. **Exfiltration chains (sequences).** Ordered event patterns that match known insider scenarios, e.g. *after-hours logon → USB connected → files copied*.

The result is an alert that names the exact files, PCs and rules behind it, rather than a bare anomaly score.

---

## 1. What is new compared with TERPE v1

| v1 | v2 | Why it matters |
|---|---|---|
| z-scores computed over the **whole period** (including future days) | **Causal** self-baseline: each day is compared only with earlier days | v1 could not run live, and its evaluation was optimistic |
| Only compares a user with themself | **Dual baseline**: self + same-role peers on the same day | Catches insiders who are abnormal from day one |
| 6 count features | + foreign-PC logons, executable transfers, file-type diversity, after-hours file copies, **first-ever** USB / after-hours / foreign-PC behaviour | CERT scenarios are about *new* behaviour |
| `file_copies` was just a number | **Every file transfer is listed** with time, PC, file name, type and an authorisation verdict with reasons | Analysts see *what* was accessed and *whether it was allowed* |
| — | **Context-provisioned policy layer** (`policy.json`): every rule is checked against the employee's *own* approved context — approved PCs, USB approval, after-hours approval, usual file types | Deterministic, auditable evidence that an SME can configure |
| — | **Exfiltration-chain detector** | The ordered combination is the attack, not any single event |
| risk decayed per active day | Risk decays per **calendar day**; alert threshold set by an **alert budget** (top 1 % of user-days), not by labels | Matches analyst workload; no label leakage |
| Single shared password | **Accounts** with sign-up → admin approval, roles (admin / analyst / viewer), PBKDF2-SHA256 password hashing (Python standard library), lockout, forced password change, **audit log of every investigation** | Required for a real security tool; the monitor itself is monitored |
| No baseline comparison | **Ablation study**: v1 replica vs each added layer, with AUC, AP, Precision@k, detection rate, detection delay and false-alert employees | Shows quantitatively what each contribution adds |

### Research contribution (one sentence)
*A hybrid insider-risk model that fuses context-provisioned access-policy verdicts with an unsupervised dual-baseline behaviour detector and ordered exfiltration-chain evidence in a calendar-decayed risk state, evaluated by ablation against a pure anomaly-detection baseline under a fixed analyst alert budget.*

---

## 2. Pipeline

```
CERT r4.2 logs (logon, device, file, LDAP)          answers/ (labels — evaluation only)
        │
        ▼
Provisioning (first 30 days per employee) → approved PCs, USB approval, after-hours approval, usual file types
        │
        ▼
Policy layer → every event: AUTHORISED / REVIEW / VIOLATION + violated rules
        │
        ▼
Daily features (13) → causal self z-scores + same-day same-role-peer z-scores
        │
        ├──► Isolation Forest ─► anomaly excess  a_t
        ├──► policy score       p_t = Σ_rule severity · log(1 + count)   (normalised)
        └──► chain detector     c_t = number of exfiltration chains matched
                     │
                     ▼
     risk_t = 0.8^(days since previous activity) · risk_(t-1) + a_t + p_t + c_t
                     │
                     ▼
     alert if risk_t ≥ threshold (top 1 % of user-days = analyst alert budget)
```

### Access-policy rules (`results_v2/policy.json`)

| Rule | Verdict | Meaning |
|---|---|---|
| `FOREIGN_PC` | Violation | Used a PC outside the employee's approved PCs (IT admins exempt) |
| `USB_NOT_PROVISIONED` | Violation | Removable media used by an employee not approved for USB |
| `EXECUTABLE_TRANSFER` | Violation | A *new* executable type moved via removable media by a non-IT role |
| `AFTER_HOURS` | Review | Outside 07:00–19:00 / weekends, by an employee not approved for after-hours work |
| `NEW_FILE_TYPE` | Review | File type the employee never handled during provisioning |

In CERT r4.2 the file log records **files copied to removable media**, which is the exfiltration channel the dataset models. The same policy engine works on any file-access event (open/write/delete), e.g. CERT r6.2 or real SME logs.

---

## 3. Evaluation (CERT r4.2, 1000 employees, 70 insiders)

Run `python pipeline.py` and the table is written to `results_v2/ablation.csv` and shown on the dashboard's *Methodology & Evaluation* page.

| Layer | User AUC | User AP | P@10 | P@20 | P@50 | Insiders detected | False-alert employees | Day AUC (observable) |
|---|---|---|---|---|---|---|---|---|
| L0 · TERPE v1 replica | 0.840 | 0.332 | 0.50 | 0.50 | 0.44 | 10/70 | 16 | 0.704 |
| L1 · + causal self-baseline | 0.858 | 0.280 | 0.50 | 0.35 | 0.28 | 7/70 | 13 | 0.698 |
| L2 · + peer baseline | 0.778 | 0.270 | 0.50 | 0.45 | 0.28 | 12/70 | 36 | 0.646 |
| L3 · + context features | 0.822 | 0.281 | 0.50 | 0.40 | 0.34 | 21/70 | 43 | 0.639 |
| L4 · + policy fusion | 0.868 | 0.501 | 0.80 | 0.75 | 0.60 | 33/70 | 43 | 0.714 |
| **L5 · + exfiltration chains (TERPE v2)** | 0.875 | 0.606 | 1.00 | 0.95 | 0.74 | 40/70 | 44 | 0.714 |
| R · rules only (no ML) | 0.846 | 0.611 | 1.00 | 1.00 | 0.72 | 43/70 | 147 | 0.666 |

**Reading the table**
- **TERPE v1 (L0)** puts 5 insiders in its top 10 and detects 10 of 70 insiders inside their malicious window.
- **TERPE v2 (L5)** puts **10 of 10** insiders in its top 10 and 19 of 20 in its top 20, raises user-level AP from 0.33 to **0.61**, and detects **40 of 70** insiders (4× v1), with a median detection delay of 0 days (alerted on the first malicious day).
- **The ML-only layers (L1–L3) do not help on their own.** The causal baseline removes v1's optimistic look-ahead (so its numbers drop), and peer/context features add noise when used alone. Their value appears once fused with the policy layer.
- **Rules alone (R)** rank insiders as well as v2 but raise alerts on **147** normal employees; fusing with the ML and accumulating risk keeps v2's recall while cutting false-alert employees to **44**. That trade-off is the core argument for the hybrid design.
- **By scenario:** scenario 1 (after-hours USB exfiltration) 29/30 insiders alerted, scenario 3 (disgruntled IT admin) 10/10, scenario 2 (job-hunting before leaving) only 2/30, because those insiders were already approved USB users and their main signal is web browsing, which v2 does not use yet (future work).
- *Day AUC (observable)* only counts malicious days that contain logon/USB/file events; many CERT malicious days are web/email-only and invisible to these logs.

Labels are used **only** to score each row, never to train or tune.

---

## 4. Project structure

```
pipeline.py          builds everything in results_v2/ from the raw CERT data + runs the ablation study
api.py               FastAPI backend: data, live scoring, accounts, admin, audit log
auth.py              accounts, roles, password hashing, JWT sessions, audit log
app.py               Streamlit dashboard
download_data.py     downloads the needed CERT r4.2 files (~290 MB)
results_v2/          pipeline outputs used by the API
.streamlit/config.toml   dark theme
v1_backup/           the original TERPE v1 code and results
```

---

## 5. Running locally

```bash
python -m pip install -r requirements.txt
python -m pip install huggingface_hub && python download_data.py     # once
python pipeline.py --data data --out results_v2                     # ~5–10 min

# terminal 1 — backend (PowerShell: use  $env:NAME="value"  instead of  set)
set JWT_SECRET=<long random string>
set ADMIN_USERNAME=admin
set ADMIN_PASSWORD=<strong password>
python -m uvicorn api:app --host 0.0.0.0 --port 8000

# terminal 2 — dashboard
python -m streamlit run app.py
```

Sign in with the admin account, then change its password under **My Account**. New people use **Request access** on the sign-in page; approve them under **Admin Console → Access requests**.

## 6. Deployment

**Backend host** environment variables:

| Variable | Required | Notes |
|---|---|---|
| `JWT_SECRET` | yes | long random string; generate with `python -c "import secrets;print(secrets.token_urlsafe(48))"` |
| `ADMIN_USERNAME`, `ADMIN_PASSWORD` | first start | creates the first admin if none exists |
| `DATABASE_URL` | recommended | Postgres URL (e.g. free Neon / Supabase). Without it, accounts live in a SQLite file, which free hosts like Render **wipe on every restart** |
| `RESULTS_DIR` | no | default `results_v2` |

**Streamlit Cloud** → App settings → Secrets: only

```toml
API_URL = "https://<your-backend-host>"
```

The old `APP_PASSWORD` and `API_KEY` secrets are no longer used and should be deleted.

## 7. Roles

| Role | Can do |
|---|---|
| Viewer | Overview, Methodology & Evaluation |
| Analyst | + investigate employees, file-level access log, organisation-wide file monitor, live scoring |
| Admin | + approve/reject sign-ups, change roles, disable accounts, reset passwords, audit log |

## 8. Limitations

- CERT r4.2 is synthetic and "dense-needle" (an unrealistically high share of malicious activity).
- r4.2 has no real access-control list, so USB approval, assigned PC and usual file types are learned from each employee's first 30 days. A real SME would set these from its IT policy in `policy.json`.
- Web (http) and email logs are not used yet. Scenario 2 (job-hunting before leaving) is partly a web-browsing signal.
- A high risk score is evidence for human review, not proof of malicious intent.
