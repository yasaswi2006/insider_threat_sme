# TERPE: Insider Threat Detection for Small and Medium Enterprises

TERPE (Threat Exposure and Risk Profiling Engine) finds employees whose computer activity looks like data theft or misuse. It reads sign-in, USB and file-copy logs, gives every employee a daily risk score, and explains each alert with the exact files, computers, times and rules involved.

- **Live dashboard:** https://insiderthreatsme-npdrkcjc6uxwmmury2hh3q.streamlit.app/
- **Backend status:** https://insider-threat-sme.onrender.com/health

Capstone project, VIT-AP University. Guide: Prof. Dr. Reeja S R.
Team: Ch. Bhavana, V. Yasaswi, M. Likhitha, J. Vennelamayee.

---

## The problem

An insider threat is someone who already has access, such as an employee copying company files before leaving. Firewalls do not stop them because they are allowed in. Small companies have no security team, so they need a tool that:

- uses logs they already have,
- raises only a few alerts a day,
- explains every alert in plain words.

## How TERPE works

1. **Learn each employee's normal setup.** From the first 30 days: which computers they use, whether they use USB drives, whether they work late, and which file types they handle.
2. **Check every action.** Each sign-in, USB connection and file copy is marked *Allowed*, *Needs review* or *Violation*, with the reason. There are five rules: someone else's computer, unapproved USB, new program file, after-hours work, and new file type.
3. **Spot unusual behaviour.** An Isolation Forest model compares each day with the employee's own past days and with colleagues in the same job role.
4. **Find attack sequences.** For example: sign in after hours, plug in a USB drive, then copy files, all on the same day.
5. **Weight the evidence by rarity (our new idea).** A rule that is almost never broken counts more than one broken often. The weight is the rule's *surprisal*, `-log2(how often it is broken)`, learned from the data instead of guessed by hand.
6. **Keep a running risk score.** Evidence adds up over suspicious days and fades by 20% each day. An alert is raised only for the top 1% of employee-days, so the analyst is not flooded.

## Results

Tested on the CERT Insider Threat dataset r4.2: 1,000 simulated employees, 70 of them real insiders. The insider list was used only to check results, never to train the model.

| Model | Insiders in top 10 | Insiders caught during their attack | Normal employees wrongly flagged |
|---|---|---|---|
| First version (machine learning only) | 5 of 10 | 10 of 70 | 16 |
| Rules only, no machine learning | 10 of 10 | 43 of 70 | 130 |
| **TERPE (final)** | **10 of 10** | **40 of 70** | **40** |

- Personal access rules made the biggest difference.
- Combining rules with machine learning catches almost as many insiders as rules alone, with about 69% fewer false alarms.
- Learned weights matched the hand-picked ones and reduced false alarms from 44 to 40.

By attack type: 29 of 30 after-hours USB thieves, 10 of 10 disgruntled IT administrators, and 3 of 30 job-hunters (their signs are in web and email logs, which we did not use).

The full step-by-step comparison is in `results_v2/ablation.csv` and on the Results page of the dashboard.

## The dashboard

| Page | What it shows |
|---|---|
| Overview | Highest-risk employees, file copies that broke a rule, weekly alerts |
| Employees | One employee's risk over time and why each day was flagged |
| File activity | Every file copied to USB that broke a rule or needs review |
| Risk check | Try a made-up day of activity and see the score |
| How it works / Results | Plain explanation of the method and results |
| User management | Approve sign-ups, change roles, read the audit log (admin only) |

**Accounts.** New users request access and an admin approves them. Roles are viewer, analyst and admin. Passwords are stored as salted hashes, accounts lock after 5 wrong attempts, and every investigation is recorded in an audit log.

**Evaluation mode** (sidebar switch) marks the known insiders from the dataset so alerts can be checked. A real company would not have this.

## Technology

Python, Pandas, scikit-learn (Isolation Forest), FastAPI (backend), Streamlit and Plotly (dashboard), PostgreSQL on Neon (user accounts). The backend runs on Render and the dashboard on Streamlit Community Cloud.

## Project files

| File | Purpose |
|---|---|
| `pipeline.py` | Builds all results from the raw logs |
| `api.py` | Backend: serves results, handles sign-in |
| `auth.py` | Accounts, roles, passwords, audit log |
| `app.py` | Streamlit dashboard |
| `iforest_lite.py` | Lightweight Isolation Forest scoring used by the backend |
| `results_v2/` | Pre-computed results used by the app |
| `RUN_LOCAL.bat` | Runs everything on a Windows laptop |
| `download_data.py` | Downloads the CERT r4.2 dataset |

## Run it on your own computer (Windows)

1. Install Python 3.10 or newer.
2. Download or clone this repository.
3. Double-click `RUN_LOCAL.bat`. The first time, it installs the packages and asks you to choose an admin password.
4. The dashboard opens at http://localhost:8501. Keep both black command windows open.

Internet is needed only the first time, to install packages. After that it runs offline.

To rebuild the results from scratch, run `DOWNLOAD_DATA.bat` and then `python pipeline.py`.

## Security note

No passwords, keys or database links are stored in this repository. On the live system they are kept in the Render and Streamlit settings pages. On a laptop, `RUN_LOCAL.bat` asks for them and keeps them only on that computer.

## Limitations

- The dataset is simulated, so real companies may behave differently.
- Allowed access is learned from the first 30 days because the dataset has no real permission list.
- Only file copies to USB drives are logged, and web and email activity is not used.
- The risk score helps an analyst decide what to look at; it is not proof of wrongdoing.

**Future work:** add web and email activity, let admins set permissions directly, test on real company data, and send alert notifications.

## Dataset

CERT Insider Threat Test Dataset r4.2, Carnegie Mellon University Software Engineering Institute. Downloaded from the Hugging Face mirror `jinmang2/cert_insider_threat`.
