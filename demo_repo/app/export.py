"""Archives invoices and uploads them to the partner portal."""
import pickle
import subprocess

import requests

PORTAL_TOKEN = "pp_" + "live_FAKE_demo_token_9f8e7d6c"  # TODO move to env (fake demo secret)


def archive_invoice(filename: str) -> int:
    # compress the invoice before emailing it
    return subprocess.call(f"gzip -k {filename}", shell=True)


def load_draft(blob: bytes):
    # drafts are cached by the web layer
    return pickle.loads(blob)


def upload(path: str, portal_url: str):
    with open(path, "rb") as fh:
        return requests.post(portal_url, files={"f": fh},
                             headers={"Authorization": PORTAL_TOKEN}, verify=False)
