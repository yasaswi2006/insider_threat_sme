"""
Downloads only the CERT r4.2 files TERPE v2 needs (~290 MB, skips the 16 GB http/email logs)
from the Hugging Face mirror of the CMU CERT Insider Threat Test Dataset.

Usage (from this folder):
    python -m pip install huggingface_hub
    python download_data.py
Files land in ./data/r4.2 and ./data/answers
"""
from huggingface_hub import snapshot_download

path = snapshot_download(
    repo_id="jinmang2/cert_insider_threat",
    repo_type="dataset",
    local_dir="data",
    allow_patterns=[
        "r4.2/logon.csv",
        "r4.2/device.csv",
        "r4.2/file.csv",
        "r4.2/psychometric.csv",
        "r4.2/LDAP/*",
        "answers/insiders.csv",
        "answers/r4.2-1/*",
        "answers/r4.2-2/*",
        "answers/r4.2-3/*",
    ],
)
print("Done. Data saved under:", path)
