import json
import os
import shutil
import subprocess
import sys
import time
import requests


def check_osm(container_name, api_key):
    """Query OSM API to check if the image is flagged as malicious."""
    url = "https://api.opensourcemalware.com/functions/v1/check-malicious"
    params = {
        "report_type": "container",
        "resource_identifier": container_name,
    }
    headers = {"Authorization": f"Bearer {api_key}"}

    try:
        response = requests.get(url, params=params, headers=headers, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        try:
            err_json = response.json()
            print(
                f"[OSM] API Error ({response.status_code}): {err_json.get('error', response.text)}",
                file=sys.stderr,
            )
        except Exception:
            print(f"[OSM] HTTP error: {http_err}", file=sys.stderr)
        return None
    except Exception as err:
        print(f"[OSM] Failed to check malware status: {err}", file=sys.stderr)
        return None


def run_osv_scanner(container_name):
    """Run osv-scanner against the Docker container image using the v2+ CLI syntax."""
    if not shutil.which("osv-scanner"):
        print(
            "\n[OSV-Scanner] Error: 'osv-scanner' is not installed or not in PATH.",
            file=sys.stderr,
        )
        return None

    target_image = container_name
    if ":" not in container_name and "@" not in container_name:
        target_image = f"{container_name}:latest"

    print(f"\nScanning '{target_image}' with OSV-Scanner...")
    try:
        result = subprocess.run(
            ["osv-scanner", "scan", "image", "--format", "json", target_image],
            capture_output=True,
            text=True,
        )

        if result.stdout.strip():
            return json.loads(result.stdout)
        elif result.stderr:
            print(f"[OSV-Scanner] Error output: {result.stderr.strip()}", file=sys.stderr)
            return None
    except json.JSONDecodeError:
        print("[OSV-Scanner] Failed to parse stdout as JSON.", file=sys.stderr)
        return None
    except Exception as err:
        print(f"[OSV-Scanner] Execution failed: {err}", file=sys.stderr)
        return None


def summarize_osv_severities(osv_data):
    """Parse OSV JSON output and aggregate vulnerability counts by severity tier."""
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    results = osv_data.get("results", [])
    for res in results:
        for pkg in res.get("packages", []):
            groups = pkg.get("groups", [])
            for group in groups:
                max_sev = group.get("max_severity")
                severity_label = "UNKNOWN"
                if max_sev:
                    try:
                        score = float(max_sev)
                        if score >= 9.0:
                            severity_label = "CRITICAL"
                        elif score >= 7.0:
                            severity_label = "HIGH"
                        elif score >= 4.0:
                            severity_label = "MEDIUM"
                        elif score > 0.0:
                            severity_label = "LOW"
                    except ValueError:
                        pass

                counts[severity_label] += 1

    return counts


def main():
    api_key = os.getenv("OSM_KEY")
    if not api_key:
        print("Error: The OSM_KEY environment variable is not set.", file=sys.stderr)
        print('Please run: export OSM_KEY="your_token_here"', file=sys.stderr)
        sys.exit(1)

    try:
        container_input = input("Enter Docker container (try: metal3d/xmrig): ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        sys.exit(0)

    if not container_input:
        print("Error: Container name cannot be empty.", file=sys.stderr)
        sys.exit(1)

    # Start timing after input is provided
    start_time = time.perf_counter()

    print("\n--- [1/2] Checking OSM (Malware Detection) ---")
    osm_data = check_osm(container_input, api_key)

    is_malicious = osm_data.get("malicious", False) if osm_data else False
    has_threat_id = (
        isinstance(osm_data.get("details"), dict) and "threat_id" in osm_data["details"]
    )

    if is_malicious and has_threat_id:
        print("ALERT: Container FLAGGED as MALICIOUS by OSM!")
        print(json.dumps(osm_data, indent=2))
    else:
        print("Result: Container is NOT flagged as malicious in OSM database.")

    print("\n--- [2/2] Running OSV-Scanner (CVE Analysis) ---")
    osv_data = run_osv_scanner(container_input)

    if osv_data:
        counts = summarize_osv_severities(osv_data)
        total_vulns = sum(counts.values())

        if total_vulns > 0:
            print(f"\nResult: Found {total_vulns} total vulnerability entry(s).\n")
            print("Vulnerability Breakdown by Severity:")
            print(f"  🔴 Critical : {counts['CRITICAL']}")
            print(f"  🟠 High     : {counts['HIGH']}")
            print(f"  🟡 Medium   : {counts['MEDIUM']}")
            print(f"  🔵 Low      : {counts['LOW']}")
            if counts["UNKNOWN"] > 0:
                print(f"  ⚪ Unknown  : {counts['UNKNOWN']}")
        else:
            print("Result: No known vulnerabilities found by OSV-Scanner.")

    # Calculate and display elapsed execution time
    elapsed_time = time.perf_counter() - start_time
    print(f"\n⏱️ Scan completed in {elapsed_time:.2f} seconds.")


if __name__ == "__main__":
    main()
