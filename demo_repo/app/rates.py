"""Fetches FX rates from a partner API."""
import requests


def fetch_rates(url: str, timeout: float = 5.0) -> dict:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.json()
