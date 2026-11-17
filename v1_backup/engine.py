import pandas as pd

def risk_engine(df, thr, k=2, decay=None):
    """
    For each user, walk through their active days in date order.
    - day scores above thr -> risk goes up by 1
    - normal day           -> risk resets to 0 (or shrinks by `decay`)
    - alert when risk >= k
    """
    df = df.sort_values(["user", "day"]).reset_index(drop=True)
    risk, cur, r = [], None, 0.0
    for u, s in zip(df["user"], df["anomaly_score"]):
        if u != cur:
            cur, r = u, 0.0
        if s > thr:
            r += 1
        else:
            r = 0.0 if decay is None else max(0.0, r - decay)
        risk.append(r)
    df["risk"] = risk
    df["alert"] = df["risk"] >= k
    return df
