import csv
from urllib.parse import urljoin, urlparse

import requests

BASE_URL = "http://127.0.0.1:8765"      # test_website.py (localhost only)
TIMEOUT = 5
OBSERVATION_FILE = "http_scan_results.csv"
FINDINGS_FILE = "http_findings.csv"

# (method, path, status we expect from test_website.py)
REQUESTS_TO_MAKE = [
    ("GET", "/", 200),
    ("GET", "/health", 200),
    ("GET", "/redirect", 302),
    ("GET", "/does-not-exist", 404),
    ("POST", "/", None),             # unsupported-method check: expect an error status
]

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
]

# GOAT comment to say not the script is not liable for any assumptions
REVIEW = "Manual review required; not proof of exploitability."


def run_http_checks():
    """Run all checks, print a summary, write two CSV files. Returns the findings list."""
    print(f"[*] Starting HTTP checks on {BASE_URL}")
    observations = []
    findings = []
    seen = set()
    responses = {}
    successes = 0

    def add_finding(category, path, observation, review=REVIEW):
        key = (category, path, observation)
        if key not in seen:               # duplicate alerts are suppressed
            seen.add(key)
            findings.append({"category": category, "endpoint": path,
                             "observation": observation, "review_status": review})

    # Step 1: observe every request (never follow redirects).
    for method, path, expected in REQUESTS_TO_MAKE:
        url = BASE_URL + path
        try:
            response = requests.request(method, url, timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException as problem:
            print(f"[!] Connection error for {method} {path}: {type(problem).__name__}")
            observations.append({"method": method, "endpoint": path, "status_code": "ERROR",
                                 "response_length": 0, "content_type": "N/A", "server": "N/A"})
            continue

        successes += 1
        responses[(method, path)] = response
        observations.append({
            "method": method,
            "endpoint": path,
            "status_code": response.status_code,
            "response_length": len(response.content),
            "content_type": response.headers.get("Content-Type", "N/A"),
            "server": response.headers.get("Server", "N/A"),
        })
        print(f"[{method}] {path} | Status: {response.status_code} | "
              f"Length: {len(response.content)} bytes")

        if method == "GET" and expected and response.status_code != expected:
            add_finding("Observation", path,
                        f"Expected status {expected} but received {response.status_code}.")

    if successes == 0:
        print("\n--- HTTP CHECK SUMMARY ---")
        print("Target unreachable: no conclusion can be drawn. Is test_website.py running?")
        _save_csv(OBSERVATION_FILE, observations,
                  ["method", "endpoint", "status_code", "response_length", "content_type", "server"])
        return findings

    home = responses.get(("GET", "/"))
    if home is not None:
        # Step 2: missing security headers.
        for header in SECURITY_HEADERS:
            if header not in home.headers:
                add_finding("Configuration Review", "/", f"Missing security header: {header}")

        # Step 3: cookie attributes. Only the cookie NAME is reported, never its value.
        cookie_header = home.headers.get("Set-Cookie")
        if cookie_header:
            attributes = [part.strip().lower() for part in cookie_header.split(";")]
            name = attributes[0].split("=")[0] if attributes else "cookie"
            if "httponly" not in attributes:
                add_finding("Cookie Review", "/", f"Cookie '{name}' has no HttpOnly attribute.")
            if "secure" not in attributes:
                add_finding("Cookie Review", "/", f"Cookie '{name}' has no Secure attribute.")
            if not any(part.startswith("samesite") for part in attributes):
                add_finding("Cookie Review", "/", f"Cookie '{name}' has no SameSite attribute.")

        # Step 5: banner disclosure and plain HTTP.
        banner = home.headers.get("Server")
        if banner:
            add_finding("Informational", "/", f"Server header exposes value: {banner.strip()}",
                        "Informational disclosure; low severity alone.")
        if BASE_URL.startswith("http://"):
            add_finding("Informational", "/", "Site is served over plain HTTP (no TLS); "
                        "TLS configuration cannot be assessed.", "Informational.")

    # Step 4: redirect target must stay on the same host.
    redirect = responses.get(("GET", "/redirect"))
    if redirect is not None and 300 <= redirect.status_code < 400:
        location = redirect.headers.get("Location", "")
        target = urlparse(urljoin(BASE_URL + "/redirect", location))
        same_host = target.netloc == urlparse(BASE_URL).netloc
        add_finding("Redirect Review", "/redirect",
                    f"Redirects to '{location}' ({'same host' if same_host else 'DIFFERENT HOST'}).",
                    "Informational." if same_host else REVIEW)

    # Step 6: unsupported method should produce an error status, not a crash.
    post = responses.get(("POST", "/"))
    if post is not None:
        add_finding("Error Handling", "/",
                    f"Unsupported POST returned status {post.status_code}.", "Informational.")

    print("\n--- HTTP CHECK SUMMARY ---")
    if not findings:
        print("No indicators found. Note: this does not prove the site is secure.")
    for item in findings:
        print(f"[{item['category']}] {item['endpoint']}")
        print(f"  -> {item['observation']}")
        print(f"  -> Status: {item['review_status']}\n")
    print("Findings are configuration observations, not proof of exploitability.")

    _save_csv(OBSERVATION_FILE, observations,
              ["method", "endpoint", "status_code", "response_length", "content_type", "server"])
    _save_csv(FINDINGS_FILE, findings, ["category", "endpoint", "observation", "review_status"])
    return findings


def _save_csv(filename, rows, fieldnames):
    try:
        with open(filename, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        print(f"[*] Saved {filename}")
    except OSError as problem:
        print(f"[!] Could not write {filename}: {problem}")