

1. First: protect the working version
In your project folder:

cd C:\Users\mohan\insider_project

Make a backup right now:

Copy-Item app.py app_WORKING_FINAL_BACKUP.py

Now you have:

app.py
app_WORKING_FINAL_BACKUP.py
If anything goes wrong later, you can restore it.

Even safer: make a ZIP backup
From PowerShell:

Compress-Archive -Path app.py,api.py,engine.py,results,data,README.md -DestinationPath TERPE_FINAL_WORKING_BACKUP.zip -Force

That gives you:

TERPE_FINAL_WORKING_BACKUP.zip
Do not delete this ZIP. Keep a copy somewhere outside the project folder too, such as your Desktop/Google Drive.

2. Yes, update README
Now that the project is actually working, the README should describe the final working version, not the old versions.

You can open README.md and add/update sections such as:

# TERPE – Threat Exposure & Risk Profiling Engine

## Overview

TERPE (Threat Exposure & Risk Profiling Engine) is a behavioral security intelligence platform designed for SME environments.

It combines behavioral anomaly detection, stateful risk accumulation, and user-level behavioral profiling to identify potentially suspicious employee activity.

## Key Features

- Employee behavioral monitoring
- Daily anomaly detection using Isolation Forest
- Stateful risk accumulation and decay
- Peak risk scoring
- User-level risk profiling
- Behavioral explanations
- Ground-truth evaluation using CERT r4.2
- Interactive Streamlit dashboard
- FastAPI backend
- Live scoring
- User investigation timeline
- Risk distribution and leaderboard

## Monitored Behaviors

TERPE analyzes:

- Logon activity
- Distinct PCs used
- After-hours logons
- USB connections
- After-hours USB activity
- File copies

## System Architecture

Frontend:
- Streamlit

Backend:
- FastAPI

Machine Learning:
- Isolation Forest

Data:
- CERT r4.2 research dataset

Risk Engine:
- Stateful risk accumulation
- Risk decay
- Alert threshold

## Dashboard

The dashboard provides:

1. Overview
2. Investigate User
3. Live Scoring

The Overview dashboard allows users to select the number of users displayed and dynamically recalculates the selected-population metrics.

## Important Evaluation Metrics

The dashboard reports:

- Users displayed
- High-risk users
- High-risk rate
- Anomalous user-days
- Ground-truth insiders

Ground-truth labels are used only in evaluation mode.

## Project Structure

```text
insider_project/
│
├── app.py
├── api.py
├── engine.py
├── data/
├── results/
├── Untitled.ipynb
├── README.md
└── requirements.txt
Running the Application
Start the FastAPI backend:

python -m uvicorn api:app --host 0.0.0.0 --port 8000

Then start Streamlit:

python -m streamlit run app.py

The Streamlit application will be available locally at:

http://localhost:8501
Disclaimer
TERPE identifies anomalous and potentially risky behavior. A high-risk classification does not by itself confirm malicious or insider activity. Ground-truth labels are used for research evaluation.


---

# 3. DON'T change the working `app.py`

This is important.

You currently have a working state.

**Do not:**

- ❌ rewrite `app.py`
- ❌ copy another old version over it
- ❌ change the KPI calculations again
- ❌ delete `results/`
- ❌ delete `data/`
- ❌ delete `api.py`
- ❌ delete `engine.py`

Only edit `README.md`.

---

# 4. Save the README

After editing:

```powershell
git status
You should see something like:

modified: README.md
If app.py also appears as modified, stop before committing and tell me. We don't want to accidentally overwrite the working version.

5. Then save everything to GitHub
Once git status shows only the changes you actually want:

git add README.md

Then:

git commit -m "Update TERPE project documentation"

Then:

git push origin main

Do NOT run:
git push origin master
Your branch is main.

Your final safety setup
I strongly recommend keeping these three things:

C:\Users\mohan\insider_project\
    app.py                       ← WORKING VERSION
    app_WORKING_FINAL_BACKUP.py  ← backup
    TERPE_FINAL_WORKING_BACKUP.zip ← emergency backup
And your GitHub repository:

insider_threat_sme
So even if you accidentally break something later, you have a known-working copy to restore.

Most importantly: since it finally works, don't make any more code changes unless there is an actual bug.

 Yes, update README
Now that the project is actually working, the README s how to do from this step ste by step

Absolutely. Since the project is finally working, don't touch app.py now. We will update only README.md, step by step.

Step 1 — Make a backup first
Open PowerShell.

Run:

cd C:\Users\mohan\insider_project

Then:

Copy-Item app.py app_WORKING_FINAL_BACKUP.py

Now your working app has a backup.

Step 2 — Open README.md
In the same PowerShell window, run:

notepad README.md

Notepad will open your current README.

Important
Don't delete anything yet.

First, copy the existing README content and paste it here if you want me to update your existing README without accidentally removing something important.

If you want to replace the README completely with a clean final version, tell me and I'll give you the exact complete content to paste.

For now, leave Notepad open and don't change app.py.

completely the final version
Yes. Since you want the complete final README, we'll replace the old README entirely.

Step 1 — Open README
In PowerShell:

cd C:\Users\mohan\insider_project
notepad README.md

When Notepad opens, press:

Ctrl + A → Delete

Then paste the entire content below.

TERPE — Threat Exposure & Risk Profiling Engine
Behavioral Security Intelligence for SMEs
TERPE (Threat Exposure & Risk Profiling Engine) is a behavioral security analytics platform designed to help Small and Medium-sized Enterprises (SMEs) identify potentially suspicious employee activity.

The system analyzes employee behavioral patterns, detects unusual activity using machine learning, and combines anomaly scores with stateful risk accumulation to provide a user-level risk profile.

Important: TERPE identifies anomalous or potentially risky behavior. A high-risk classification does not by itself confirm malicious or insider activity.

1. Project Overview
Traditional anomaly detection systems may treat every unusual activity as an independent alert. TERPE extends this approach by combining:

Behavioral activity monitoring
Machine learning-based anomaly detection
Stateful risk accumulation
Risk decay over time
User-level risk profiling
Behavioral explanations
Interactive security analytics
The system is designed around the idea that repeated unusual behavior can provide more useful security signals than isolated anomalies.

2. Objectives
The main objectives of TERPE are:

Detect unusual employee behavior.
Identify users exhibiting elevated behavioral risk.
Track risk accumulation over time.
Provide explanations for unusual behavior.
Allow security analysts to investigate individual users.
Provide an interactive dashboard for security monitoring.
Evaluate model behavior using labeled research data.
3. Monitored Behavioral Features
TERPE analyzes the following daily behavioral features:

Feature	Description
logons	Number of logon events
distinct_pcs	Number of distinct computers accessed
after_hours_logons	Logons occurring outside normal working hours
usb_connects	USB connection activity
usb_after_hours	USB activity occurring after hours
file_copies	File copy activity
These behavioral features are used to identify deviations from normal user behavior.

4. Machine Learning
Isolation Forest
TERPE uses an Isolation Forest for daily behavioral anomaly detection.

The model learns patterns in employee activity and identifies observations that are unusual compared with the broader behavioral population.

The model uses:

logons
distinct_pcs
after_hours_logons
usb_connects
usb_after_hours
file_copies
The anomaly score is then used by the subsequent TERPE risk-profiling layer.

Why Isolation Forest?
Isolation Forest is suitable for behavioral anomaly detection because it is designed to identify observations that are relatively isolated from the rest of the data.

5. Stateful Risk Engine
TERPE does not treat every anomaly as a completely independent security event.

Instead, anomalous behavior contributes to a user's accumulated risk.

The system applies:

Risk accumulation
Risk decay
Alert thresholds
Historical behavioral context
The simplified risk update is:

new_risk =
    decay × previous_risk
    +
    positive_excess_anomaly_score
This allows risk to persist when unusual behavior continues while gradually decreasing when unusual behavior is no longer observed.

6. Behavioral Explanation
TERPE provides behavioral explanations based on deviations from an individual user's normal behavioral baseline.

The system calculates behavioral deviations for monitored features and highlights activities that differ significantly from the user's usual pattern.

Examples include:

Unusually high number of logons
Increased after-hours activity
Unusual USB activity
Increased file copying
Access from multiple computers
The explanation layer is intended to help analysts understand why a user was flagged, rather than presenting only a numerical risk score.

7. System Architecture
                    ┌──────────────────────┐
                    │      CERT Data       │
                    │   Behavioral Logs    │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Data Processing &    │
                    │ Feature Engineering  │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │   Isolation Forest   │
                    │ Anomaly Detection     │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Stateful Risk Engine │
                    │ Accumulation/Decay   │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │ Behavioral           │
                    │ Explanation Layer    │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │      FastAPI         │
                    │       Backend        │
                    └──────────┬───────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │     Streamlit        │
                    │      Dashboard       │
                    └──────────────────────┘
8. Technology Stack
Frontend
Streamlit
Pandas
Plotly
Backend
FastAPI
Uvicorn
Python
Machine Learning
Scikit-learn
Isolation Forest
Joblib
Data Processing
Pandas
NumPy
Dataset
CERT Insider Threat Dataset r4.2
Development Tools
Jupyter Notebook
Git
GitHub
PowerShell
9. Dashboard
TERPE provides an interactive Streamlit dashboard with three main sections.

9.1 Overview
The Overview page provides:

Number of users displayed
High-risk users
High-risk rate
Anomalous user-days
Ground-truth insiders in evaluation mode
Top-risk user leaderboard
Risk distribution
TERPE model pipeline information
The user-display slider controls the selected population shown in the dashboard.

The selected population is recalculated when the slider changes.

9.2 Investigate User
The Investigate User page allows an analyst to select an employee and examine:

Monitoring history
Alert days
Risk behavior
Daily anomaly information
Behavioral explanations
User-level activity patterns
This allows analysts to move from population-level monitoring to individual investigation.

9.3 Live Scoring
The Live Scoring page allows new behavioral observations to be submitted to the backend and evaluated using the deployed TERPE scoring pipeline.

The system returns the resulting anomaly/risk information and indicates whether the activity reaches the configured alert condition.

10. API Endpoints
The FastAPI backend provides the following main endpoints:

Health Check
GET /health
Used to verify that the backend is running.

Example response:

{
  "status": "ok",
  "users_loaded": 1000
}

Top Users
GET /users/top
Returns users ordered according to their risk information.

The endpoint supports a configurable number of users.

User Timeline
GET /users/{user_id}/timeline
Returns behavioral and risk information for an individual user over time.

User Explanation
GET /users/{user_id}/explain
Provides behavioral information associated with unusual activity for an individual user.

Live Scoring
POST /score
Accepts behavioral information and performs live risk/anomaly scoring.

11. Risk Thresholds
The deployed TERPE model uses the following stored model metadata:

Risk threshold:
0.602134385738842

Alert threshold:
0.15524637949938055

Risk decay:
0.8
The model uses the six behavioral features described earlier.

The stored model metadata is maintained in:

results/model.joblib
12. Evaluation Mode
TERPE includes an evaluation mode that uses the ground-truth labels available in the CERT research dataset.

Ground-truth information is used for evaluation purposes and is not required for normal behavioral monitoring.

The dashboard distinguishes between:

Model prediction
Whether the user's calculated risk exceeds the configured risk threshold.

Ground truth
Whether the research dataset labels the user as an insider.

These two concepts should not be treated as identical.

A matching count between predicted high-risk users and ground-truth insiders does not by itself mean that the model has 100% accuracy.

Proper evaluation requires metrics based on:

True Positives
True Negatives
False Positives
False Negatives
13. Important Metric Definitions
Users Displayed
The number of users currently selected by the dashboard slider.

High-Risk Users
The number of selected users whose peak_risk exceeds the configured high-risk threshold.

High-Risk Rate
High-risk users
---------------- × 100
Users displayed
This is a percentage of the currently selected population. It does not represent a decrease in an individual user's underlying risk.

Anomalous User-Days
The sum of the anomaly_days values for the selected users.

This represents anomalous user-day occurrences rather than unique calendar dates.

Ground-Truth Insiders
The number of selected users whose dataset label indicates ground-truth insider activity.

14. Project Structure
insider_project/
│
├── app.py
├── api.py
├── engine.py
├── data/
│
├── results/
│   └── model.joblib
│
├── Untitled.ipynb
├── README.md
└── requirements.txt
Additional backup files may exist locally during development but are not required for the final application.

15. Installation
Clone or download the project and navigate to the project directory:

cd insider_project

Create a virtual environment:

python -m venv venv

Activate it on Windows:

venv\Scripts\activate

Install dependencies:

pip install -r requirements.txt

If Plotly is missing:

python -m pip install plotly

16. Running the Backend
Start the FastAPI backend:

python -m uvicorn api:app --host 0.0.0.0 --port 8000

The backend will run locally on:

http://localhost:8000
Keep this terminal running.

17. Running the Streamlit Dashboard
Open a second terminal.

Navigate to the project:

cd C:\Users\mohan\insider_project

Start Streamlit:

python -m streamlit run app.py

The dashboard will normally be available at:

http://localhost:8501
18. Authentication
The Streamlit application uses configured application credentials and communicates with the FastAPI backend using the configured API key.

Secrets should be stored through Streamlit's secrets mechanism rather than hard-coded into the application source.

Example configuration:

API_URL = "your-backend-url"
API_KEY = "your-api-key"
APP_PASSWORD = "your-application-password"
Do not commit real passwords or API keys to GitHub.

19. Deployment
The backend can be deployed as a FastAPI service and the Streamlit application can be deployed separately.

The deployed architecture is:

User
  │
  ▼
Streamlit Dashboard
  │
  │ API requests
  ▼
FastAPI Backend
  │
  ▼
TERPE Model + Risk Engine
  │
  ▼
Stored Data / Model Results
20. Security Considerations
TERPE is intended as a behavioral security monitoring and decision-support system.

The system should not automatically treat an anomalous user as malicious.

Security analysts should consider:

Historical behavior
Organizational context
Repeated activity
Behavioral explanations
Risk accumulation
Ground-truth/evaluation information where available
before taking any operational action.

21. Limitations
The current implementation has several limitations:

Anomaly detection identifies unusual behavior but does not prove malicious intent.
Behavioral explanations are approximations of the model's contributing signals rather than an exact reconstruction of the machine-learning decision process.
Ground-truth labels are available because the demonstration uses a research dataset; real SME deployments may not have such labels.
False positives and false negatives are possible.
Model performance depends on the quality and representativeness of the behavioral data.
Risk thresholds may require recalibration for different organizations and environments.
22. Future Enhancements
Potential future improvements include:

Real-time event ingestion
Organization-specific behavioral baselines
Role-aware risk profiling
Automated alert notifications
Advanced explainability
Model monitoring and drift detection
More detailed analyst investigation workflows
Database-backed event storage
Multi-tenant SME deployment
Advanced security analytics and reporting
23. Disclaimer
TERPE is a research and demonstration system for behavioral security analytics.

A model-generated anomaly or elevated-risk score should not be interpreted as definitive evidence of malicious activity or insider threat.

Human review and organizational context are required before taking security or employment-related action.

24. Project Status
Status: Working Prototype

The current implementation includes:

Behavioral anomaly detection
Isolation Forest
Stateful risk profiling
Risk accumulation and decay
Behavioral explanations
FastAPI backend
Streamlit dashboard
User investigation
Live scoring
Evaluation mode
CERT r4.2 ground-truth evaluation
Step 2 — Save it
In Notepad:

Ctrl + S

Then close Notepad.

Step 3 — VERY IMPORTANT: check that you didn't accidentally change app.py
Go back to PowerShell:

cd C:\Users\mohan\insider_project

Run:

git status

You should see README.md as modified.

If you see app.py modified too, don't commit yet. Tell me what git status shows.

Step 4 — Check README exists
Run:

dir README.md

You should see the file.

Step 5 — Commit ONLY README
Once git status confirms only the README change:

git add README.md

Then:

git commit -m "Finalize TERPE documentation"

Then:

git push origin main

Don't touch app.py anymore. 🔒
Your working app.py stays exactly as it is, while the README gets updated on GitHub.

just give me my read me propelry you do the changes and give me

Worked for 17s

Done. I made the complete final README for your actual TERPE project and kept it focused on what your project actually contains.

📥 Download your final README
Download README_FINAL_TERPE.md

What to do now
Download the file.
Go to:
C:\Users\mohan\insider_project
Make sure your working app.py is untouched.
Replace the existing README.md with the downloaded file.
Rename:
README_FINAL_TERPE.md
to:
README.md
Then in PowerShell:

cd C:\Users\mohan\insider_project

Check:

git status

You should ideally see:

modified: README.md
Then:

git add README.md
git commit -m "Finalize TERPE documentation"
git push origin main

Do not run git add . right now. We only want to push the README and avoid accidentally changing your working application.

Your working app.py stays untouched. 🔒 


README_FINAL_TERPE.md
Document
TERPE --- Threat Exposure & Risk Profiling Engine
Behavioral Security Intelligence for SMEs
TERPE is a behavioral security analytics platform designed for small and
medium-sized enterprise (SME) environments. It analyzes employee
activity patterns, detects unusual behavior using machine learning,
accumulates behavioral risk over time, and provides an analyst-facing
dashboard for investigation.

Important: TERPE identifies anomalous or potentially risky
behavior. A high-risk score does not by itself confirm malicious
intent or an insider threat.

1. Project Overview
Traditional anomaly detection can generate isolated alerts for unusual
events. TERPE adds a stateful risk layer so that repeated unusual
behavior can contribute to accumulated user risk while older risk
gradually decays.

The system combines:

Behavioral anomaly detection
Isolation Forest
Stateful risk accumulation and decay
User-level risk profiling
Behavioral explanations
Interactive security monitoring
FastAPI-based scoring services
Streamlit analyst dashboard
CERT r4.2 evaluation labels
2. Objectives
The project aims to:

Detect unusual employee behavior.
Identify users with elevated behavioral risk.
Accumulate risk when unusual behavior persists.
Allow risk to decay when unusual behavior is no longer observed.
Provide behavioral context for flagged users.
Support analyst investigation through an interactive dashboard.
Evaluate model behavior using available ground-truth labels.
3. Behavioral Features
TERPE works with the following daily behavioral features:

Feature Description

logons Number of logon events

distinct_pcs Number of distinct PCs accessed

after_hours_logons Logons occurring outside normal
working hours

usb_connects Number of USB connection events

usb_after_hours USB activity occurring outside
normal working hours

file_copies Number of file-copy events
These features are used to characterize normal and unusual employee
activity.

4. Machine Learning
Isolation Forest
TERPE uses an Isolation Forest to detect unusual daily behavioral
patterns.

The model is trained on the six behavioral features:

logons
distinct_pcs
after_hours_logons
usb_connects
usb_after_hours
file_copies
The Isolation Forest produces an anomaly score. This score is then used
by the stateful risk layer.

Why Isolation Forest?
Isolation Forest is appropriate for this use case because it is an
unsupervised anomaly-detection method that identifies observations that
are relatively isolated from the normal behavioral population.

5. Stateful Risk Engine
TERPE combines anomaly detection with a stateful risk mechanism.

The risk state is carried forward between observations using risk decay.
In simplified form:

new_risk =
    decay × previous_risk
    +
    positive_excess_anomaly_score
The current stored model configuration uses:

Risk decay:       0.8
Risk threshold:   0.602134385738842
Alert threshold:  0.15524637949938055
The stored model metadata is maintained in:

results/model.joblib
Key concept
Isolation Forest detects whether daily behavior is unusual; the
stateful risk engine determines whether unusual behavior contributes
to persistent elevated risk over time.

6. Behavioral Explanations
TERPE provides user-level behavioral explanations using deviations from
an individual's historical behavioral baseline.

Examples of potentially unusual behavior include:

Increased logon activity
Increased after-hours logons
Access from an unusual number of PCs
Increased USB activity
After-hours USB activity
Increased file-copy activity
The explanation layer is intended to help analysts understand the
behavioral signals associated with an elevated-risk user.

The explanation is an approximate behavioral explanation and should
not be interpreted as an exact reconstruction of the internal decision
path of the machine-learning model.

7. System Architecture
                 CERT r4.2 Behavioral Data
                          │
                          ▼
                Data Processing /
                Feature Engineering
                          │
                          ▼
                  Isolation Forest
                 Daily Anomaly Score
                          │
                          ▼
                 Stateful Risk Engine
                Accumulation + Decay
                          │
                          ▼
                 Behavioral Explanation
                          │
                          ▼
                    FastAPI Backend
                          │
                          ▼
                  Streamlit Dashboard
8. Technology Stack
Frontend
Streamlit
Pandas
Plotly
Backend
FastAPI
Uvicorn
Python
Machine Learning
Scikit-learn
Isolation Forest
Joblib
Data Processing
Pandas
NumPy
Development
Jupyter Notebook
Git
GitHub
PowerShell
Dataset
CERT Insider Threat Dataset r4.2
9. Dashboard
The Streamlit application provides three main workflows.

9.1 Overview
The Overview dashboard provides:

Number of users displayed
High-risk users
High-risk rate
Anomalous user-days
Ground-truth insiders for evaluation
Top-risk users
Risk distribution
Model/risk information
The Number of users to display slider controls the selected
population used by the Overview metrics.

Metric definitions
Users displayed

The number of users currently selected by the slider.

High-risk users

The number of selected users whose peak_risk reaches the configured
high-risk threshold.

High-risk rate

High-risk users
---------------- × 100
Users displayed
This is a percentage of the selected population. It does not mean that
an individual user's risk score is decreasing when the percentage
decreases.

Anomalous user-days

The sum of the anomaly_days values for the selected users. This
represents anomalous user-day occurrences, not unique calendar dates.

Ground-truth insiders

The number of selected users whose dataset label indicates ground-truth
insider activity.

Ground-truth labels are used for evaluation and are separate from model
predictions.

9.2 Investigate User
The Investigate User workflow allows an analyst to select an employee
and examine:

User risk history
Timeline information
Anomalous activity
Behavioral explanations
User-level risk patterns
This supports moving from population-level monitoring to individual
investigation.

9.3 Live Scoring
The Live Scoring workflow allows a new behavioral observation to be sent
to the backend and evaluated using the TERPE scoring pipeline.

The scoring process uses the stored model and risk configuration to
return the resulting risk/anomaly information.

10. API
The FastAPI backend provides the main application services.

Health
GET /health
Used to verify that the backend is running and that users are loaded.

Example:

{
  "status": "ok",
  "users_loaded": 1000
}
Top Users
GET /users/top
Returns users ordered by risk and supports a configurable number of
users.

User Timeline
GET /users/{user_id}/timeline
Returns timeline/risk information for a selected user.

User Explanation
GET /users/{user_id}/explain
Returns behavioral explanation information for a selected user.

Live Score
POST /score
Accepts behavioral information and evaluates the observation using the
TERPE scoring pipeline.

Protected API endpoints require the configured API key.

11. Evaluation
The project uses ground-truth labels available in the CERT research
dataset for evaluation.

TERPE distinguishes between:

Model-derived risk
The user's risk is calculated from behavioral activity, anomaly
detection, and the stateful risk engine.

Ground-truth label
The research dataset provides a label used to evaluate model behavior.

A matching number of high-risk users and ground-truth insiders does
not by itself establish 100% model accuracy.

Proper model evaluation should consider:

True positives
True negatives
False positives
False negatives
Precision
Recall
F1-score
Confusion matrix
12. Project Structure
insider_project/
│
├── app.py
├── api.py
├── engine.py
├── data/
│
├── results/
│   └── model.joblib
│
├── Untitled.ipynb
├── README.md
└── requirements.txt
Development backup files may exist locally but are not required for the
final application.

13. Installation
Open PowerShell and navigate to the project:

cd C:\Users\mohan\insider_project
Create a virtual environment if required:

python -m venv venv
Activate it:

venv\Scripts\activate
Install project dependencies:

python -m pip install -r requirements.txt
If Plotly is missing:

python -m pip install plotly
14. Running the Backend
Start FastAPI:

python -m uvicorn api:app --host 0.0.0.0 --port 8000
The local backend is available at:

http://localhost:8000
Keep this terminal running.

15. Running the Streamlit Dashboard
Open a second PowerShell window:

cd C:\Users\mohan\insider_project
Start Streamlit:

python -m streamlit run app.py
The dashboard is normally available at:

http://localhost:8501
16. Configuration and Secrets
The Streamlit application uses configured secrets for the backend URL,
API key, and application password.

Example:

API_URL = "your-backend-url"
API_KEY = "your-api-key"
APP_PASSWORD = "your-application-password"
Do not commit real passwords or API keys to GitHub.

17. Deployment
The project can be deployed as two services:

                  User
                    │
                    ▼
             Streamlit App
                    │
             X-API-Key request
                    │
                    ▼
              FastAPI API
                    │
                    ▼
           TERPE Model + Risk
                 Engine
The Streamlit frontend communicates with the FastAPI backend through the
configured API URL.

18. Security Considerations
TERPE is a behavioral security monitoring and decision-support system.

An anomalous or elevated-risk result should not automatically be treated
as proof of malicious activity.

Analysts should consider:

Historical behavior
Repeated activity
User context
Behavioral explanations
Risk accumulation
Organizational context
before taking operational action.

19. Limitations
The current prototype has several limitations:

Anomaly detection identifies unusual behavior but does not prove
malicious intent.
False positives and false negatives are possible.
Behavioral explanations are approximate.
Ground-truth labels are available because the project uses a labeled
research dataset; real organizations may not have equivalent labels.
Risk thresholds may require recalibration for different
organizations.
Model performance depends on the quality and representativeness of
the available behavioral data.
The current prototype is intended for research, demonstration, and
analyst-support purposes.
20. Future Enhancements
Potential future improvements include:

Real-time event ingestion
Organization-specific behavioral baselines
Role-aware risk profiling
Automated alert notifications
Advanced explainability
Model drift monitoring
Database-backed event storage
Multi-tenant SME deployment
Advanced analyst reporting
Security-event integrations
21. Disclaimer
TERPE is a research and demonstration system for behavioral security
analytics.

A model-generated anomaly or elevated-risk score should not be
interpreted as definitive evidence of malicious activity or insider
threat.

Human review and organizational context are required before taking
security or employment-related action.

22. Project Status
Status: Working Prototype

Current implementation includes:

Behavioral anomaly detection
Isolation Forest
Stateful risk accumulation
Risk decay
User-level risk profiling
Behavioral explanations
FastAPI backend
Streamlit dashboard
User investigation
Live scoring
Evaluation using CERT r4.2 labels
Interactive risk visualization


