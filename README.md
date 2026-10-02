# Insider Threat Monitor for SMEs

## Overview

Insider Threat Monitor is a behavioral security analytics system designed to detect unusual employee activity and identify potential insider-threat behavior.

The system uses the CERT r4.2 research dataset and focuses on daily employee activity such as:

- Logins
- Different PCs used
- After-hours logins
- USB connections
- After-hours USB activity
- File copies

## System Architecture

Employee Activity Data
        ↓
Feature Engineering
        ↓
Isolation Forest
        ↓
Daily Anomaly Score
        ↓
Stateful Risk Engine
        ↓
Risk Accumulation / Decay
        ↓
Alert & Explanation
        ↓
Streamlit Dashboard

## Machine Learning

The project uses an Isolation Forest for unsupervised anomaly detection.

The model learns patterns of normal employee behavior and assigns an anomaly score to each user-day.

A stateful risk mechanism is then used to accumulate risk over time rather than treating every unusual day as an immediate security alert.

## Dashboard

The Streamlit dashboard contains:

### Overview
- Top-risk users
- Peak anomaly scores
- Peak accumulated risk
- Anomalous user-days
- Ground-truth evaluation mode

### Investigate a User
- User activity timeline
- Daily anomaly scores
- Accumulated risk
- Alert days
- Explanation of unusual activity

### Live Scoring
- Enter employee activity for a new day
- Generate an anomaly score
- Update running risk
- Display the largest behavioral deviations

## Technology Stack

- Python
- Pandas
- Scikit-learn
- Isolation Forest
- FastAPI
- Streamlit
- Plotly
- Joblib
- GitHub
- Render
- Streamlit Community Cloud

## API

The FastAPI backend provides:

- `/health`
- `/users/top`
- `/users/{user_id}/timeline`
- `/users/{user_id}/explain`
- `/score`

## Deployment

The system is deployed as two services:

- FastAPI backend → Render
- Streamlit frontend → Streamlit Community Cloud

## Dataset

CERT r4.2 is used as the research dataset for evaluating insider-threat detection.

Ground-truth labels are used only in evaluation mode. In a real SME deployment, ground-truth insider labels would generally not be available.

## Important Limitation

This project is a research prototype. The live risk state is maintained in memory by the API and therefore resets when the backend restarts.

