"""Small local program for import reachability analysis."""

import requests


def fetch_status(url: str) -> int:
    """Return an HTTP status for caller-provided URLs.

    The research pipeline does not invoke this function against external systems.
    It exists only so static analysis can observe a dependency import.
    """

    response = requests.get(url, timeout=5)
    return response.status_code

