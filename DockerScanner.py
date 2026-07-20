import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import requests
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()

# In-memory cache for API fetched CWE details: { "CWE-125": ("Name", "Description") }
CWE_CACHE = {}


def get_cwe_details(cwe_id):
    """Fetch Name and Description for a CWE ID using official MITRE REST API & CIRCL fallbacks."""
    if not cwe_id or cwe_id == "N/A":
        return "N/A", "No description available"

    if cwe_id in CWE_CACHE:
        return CWE_CACHE[cwe_id]

    match = re.search(r"\d+", cwe_id)
    if not match:
        return "N/A", "No description available"

    cwe_num = match.group(0)

    # 1. Primary Attempt: Official MITRE CWE API
    try:
        mitre_url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_num}"
        resp = requests.get(mitre_url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            weaknesses = data.get("Weaknesses", [])
            if weaknesses:
                item = weaknesses[0]
                name = item.get("Name", "N/A")
                desc = item.get("Description", "No description available")
                desc = str(desc).strip().replace("\n", " ")

                res = (name, desc)
                CWE_CACHE[cwe_id] = res
                return res
    except Exception:
        pass

    # 2. Secondary Fallback Attempt: CIRCL API
    circl_urls = [
        f"https://cvepremium.circl.lu/api/cwe/{cwe_num}",
        f"https://vulnerability.circl.lu/api/cwe/{cwe_num}",
    ]

    for url in circl_urls:
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()

                if isinstance(data, dict) and "data" in data and isinstance(data["data"], list) and data["data"]:
                    item = data["data"][0]
                elif isinstance(data, list) and data:
                    item = data[0]
                elif isinstance(data, dict):
                    item = data
                else:
                    continue

                name = (
                    item.get("Name")
                    or item.get("name")
                    or item.get("title")
                    or "N/A"
                )
                desc = (
                    item.get("Description")
                    or item.get("description")
                    or item.get("summary")
                    or item.get("abstract")
                    or "No description available"
                )

                if isinstance(desc, list):
                    desc = " ".join(desc)
                desc = str(desc).strip().replace("\n", " ")

                res = (name, desc)
                CWE_CACHE[cwe_id] = res
                return res
        except Exception:
            pass

    fallback = ("N/A", "No description available")
    CWE_CACHE[cwe_id] = fallback
    return fallback


def get_cisa_kev_set():
    """Download CISA KEV catalog and return a set of CVE IDs currently being exploited."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return {
                item["cveID"]
                for item in data.get("vulnerabilities", [])
                if "cveID" in item
            }
    except Exception:
        pass
    return set()


def get_epss_scores(cve_list):
    """Query FIRST.org API to get EPSS scores for a list of CVEs."""
    valid_cves = [cve for cve in cve_list if cve.startswith("CVE-")]
    if not valid_cves:
        return {}

    epss_map = {}
    chunk_size = 50
    for i in range(0, len(valid_cves), chunk_size):
        chunk = valid_cves[i : i + chunk_size]
        url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                for entry in data:
                    cve_id = entry.get("cve")
                    epss_val = entry.get("epss")
                    if cve_id and epss_val:
                        epss_map[cve_id] = float(epss_val)
        except Exception:
            pass
    return epss_map


def get_cwe_map(cve_list):
    """Query OSV/NVD endpoints to retrieve CWE IDs for filtered CVEs."""
    valid_cves = [cve for cve in cve_list if cve.startswith("CVE-")]
    if not valid_cves:
        return {}

    cwe_map = {}
    for cve in valid_cves:
        try:
            resp = requests.get(f"https://api.osv.dev/v1/vulns/{cve}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                cwes = data.get("database_specific", {}).get("cwes", [])
                if cwes:
                    cwe_item = cwes[0]
                    cwe_map[cve] = (
                        cwe_item.get("cweId")
                        if isinstance(cwe_item, dict)
                        else str(cwe_item)
                    )
                    continue

            nvd_resp = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}",
                timeout=5,
            )
            if nvd_resp.status_code == 200:
                nvd_data = nvd_resp.json()
                vuln_items = nvd_data.get("vulnerabilities", [])
                if vuln_items:
                    weaknesses = vuln_items[0].get("cve", {}).get("weaknesses", [])
                    for w in weaknesses:
                        for desc in w.get("description", []):
                            val = desc.get("value", "")
                            if val.startswith("CWE-"):
                                cwe_map[cve] = val
                                break
                        if cve in cwe_map:
                            break
        except Exception:
            pass

    return cwe_map


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


def process_osv_data(osv_data):
    """Parse OSV JSON output, aggregate counts by severity, and build detailed findings."""
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }
    detailed_findings = []

    results = osv_data.get("results", [])
    for res in results:
        for pkg in res.get("packages", []):
            pkg_info = pkg.get("package", {})
            pkg_name = pkg_info.get("name", "Unknown")
            pkg_version = pkg_info.get("version", "Unknown")

            groups = pkg.get("groups", [])
            for group in groups:
                max_sev = group.get("max_severity")
                aliases = group.get("aliases", group.get("ids", []))
                cve_id = aliases[0] if aliases else "Unknown Vuln"

                severity_label = "UNKNOWN"
                score_str = "N/A"

                if max_sev:
                    try:
                        score = float(max_sev)
                        score_str = f"{score:.1f}"
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
                detailed_findings.append(
                    {
                        "severity": severity_label,
                        "cve": cve_id,
                        "package": pkg_name,
                        "version": pkg_version,
                        "cwe": "N/A",
                        "score": score_str,
                    }
                )

    return counts, detailed_findings


def render_rich_table(filtered_findings, cwe_map, epss_map, kev_set, filter_label):
    """Renders formatted Rich table to solve alignment/wrapping issues."""
    table = Table(
        title=f"--- Filtered Listing ({filter_label}) [{len(filtered_findings)} item(s)] ---",
        title_style="bold yellow",
        show_lines=False,
        header_style="bold cyan",
        expand=True
    )

    table.add_column("SEVERITY", style="bold red", width=10, no_wrap=True)
    table.add_column("CVE / ID", width=22, no_wrap=True)
    table.add_column("PACKAGE", max_width=28, overflow="fold")
    table.add_column("CWE ID", width=10, no_wrap=True)
    table.add_column("CWE NAME", max_width=22, overflow="ellipsis")
    table.add_column("CVSS", justify="right", width=6)
    table.add_column("EPSS", justify="right", width=8)
    table.add_column("KEV", justify="center", width=6)
    table.add_column("DESCRIPTION", max_width=40, overflow="ellipsis")

    for item in filtered_findings:
        cve = item["cve"]
        cwe_id = cwe_map.get(cve, "N/A")
        cwe_name, cwe_desc = get_cwe_details(cwe_id)

        # CVSS Styling
        try:
            score_num = float(item["score"])
            cvss_style = "bold red" if score_num >= 9.0 else "yellow"
            cvss_display = Text(f"{score_num:.1f}", style=cvss_style)
        except ValueError:
            cvss_display = Text(item["score"], style="dim")

        # EPSS Styling
        epss_val = epss_map.get(cve)
        if epss_val is not None:
            pct = epss_val * 100
            epss_style = "bold red" if pct >= 50.0 else ("yellow" if pct >= 10.0 else "default")
            epss_display = Text(f"{pct:.1f}%", style=epss_style)
        else:
            epss_display = Text("N/A", style="dim")

        # KEV Styling
        is_kev = cve in kev_set
        kev_display = Text("YES 🚨", style="bold red") if is_kev else Text("NO", style="dim green")

        table.add_row(
            item["severity"],
            cve,
            item["package"],
            cwe_id,
            cwe_name,
            cvss_display,
            epss_display,
            kev_display,
            cwe_desc
        )

    console.print(table)


def main():
    parser = argparse.ArgumentParser(
        description="Scan Docker images for malicious software (OSM) and CVE vulnerabilities (OSV-Scanner)."
    )
    parser.add_argument(
        "container",
        nargs="?",
        help="Docker container name (e.g., metal3d/xmrig or aquasec/trivy)",
    )
    parser.add_argument(
        "--critical",
        action="store_true",
        help="List specific Critical severity CVE findings",
    )
    parser.add_argument(
        "--high", action="store_true", help="List specific High severity CVE findings"
    )
    parser.add_argument(
        "--kev",
        action="store_true",
        help="Filter findings down to only Known Exploited Vulnerabilities (CISA KEV)",
    )
    parser.add_argument(
        "--cwe-true",
        action="store_true",
        help="Filter findings down to only vulnerabilities that returned a valid CWE ID",
    )

    # Mutually exclusive group so --epss-desc and --cvss-desc cannot be used simultaneously
    sort_group = parser.add_mutually_exclusive_group()
    sort_group.add_argument(
        "--epss-desc",
        action="store_true",
        help="Sort findings by EPSS score in descending order (highest probability first)",
    )
    sort_group.add_argument(
        "--cvss-desc",
        action="store_true",
        help="Sort findings by CVSS score in descending order (highest severity first)",
    )

    args = parser.parse_args()

    api_key = os.getenv("OSM_KEY")
    if not api_key:
        print("Error: The OSM_KEY environment variable is not set.", file=sys.stderr)
        print('Please run: export OSM_KEY="your_token_here"', file=sys.stderr)
        sys.exit(1)

    container_input = args.container
    if not container_input:
        try:
            container_input = input("Enter Docker container (e.g., aquasec/trivy): ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            sys.exit(0)

    if not container_input:
        print("Error: Container name cannot be empty.", file=sys.stderr)
        sys.exit(1)

    start_time = time.perf_counter()

    try:
        # 1. OSM Check
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

        # 2. OSV Check
        print("\n--- [2/2] Running OSV-Scanner (CVE Analysis) ---")
        osv_data = run_osv_scanner(container_input)

        if osv_data:
            counts, findings = process_osv_data(osv_data)
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

                target_severities = []
                if args.critical:
                    target_severities.append("CRITICAL")
                if args.high:
                    target_severities.append("HIGH")

                # Default to all findings if no specific severity flag is set
                if target_severities:
                    filtered_findings = [
                        f for f in findings if f["severity"] in target_severities
                    ]
                    filter_label = " & ".join(target_severities) + " Severity"
                else:
                    filtered_findings = findings
                    filter_label = "All Severities"

                # Pre-fetch KEV catalog
                print(f"\nFetching CISA KEV threat intelligence...")
                kev_set = get_cisa_kev_set()

                # Filter by KEV if requested
                if args.kev:
                    filtered_findings = [
                        f for f in filtered_findings if f["cve"] in kev_set
                    ]
                    filter_label += " | KEV Only 🚨"

                if filtered_findings:
                    print(f"Fetching EPSS and CWE threat intelligence...")
                    unique_cves = list({item["cve"] for item in filtered_findings})
                    epss_map = get_epss_scores(unique_cves)
                    cwe_map = get_cwe_map(unique_cves)

                    # Filter by valid CWE ID if requested
                    if args.cwe_true:
                        filtered_findings = [
                            f for f in filtered_findings 
                            if cwe_map.get(f["cve"]) and cwe_map.get(f["cve"]) != "N/A"
                        ]
                        filter_label += " | CWE True Only 🏷️"

                    # Sort by EPSS descending if requested
                    if args.epss_desc:
                        filtered_findings.sort(
                            key=lambda item: epss_map.get(item["cve"], 0.0),
                            reverse=True
                        )
                        filter_label += " | Sorted by EPSS ⬇️"

                    # Sort by CVSS descending if requested
                    elif args.cvss_desc:
                        def parse_score(item):
                            try:
                                return float(item["score"])
                            except ValueError:
                                return 0.0

                        filtered_findings.sort(key=parse_score, reverse=True)
                        filter_label += " | Sorted by CVSS ⬇️"

                    if filtered_findings:
                        # Render output via Rich
                        render_rich_table(filtered_findings, cwe_map, epss_map, kev_set, filter_label)
                    else:
                        print(f"No vulnerabilities found matching: {filter_label}")
                else:
                    print(f"No vulnerabilities found matching: {filter_label}")
            else:
                print("Result: No known vulnerabilities found by OSV-Scanner.")

        elapsed_time = time.perf_counter() - start_time
        print(f"\n⏱️ Scan completed in {elapsed_time:.2f} seconds.")

    except KeyboardInterrupt:
        elapsed_time = time.perf_counter() - start_time
        print("\n\n⚠️ Scan cancelled by user (Ctrl+C). Exiting prematurely.")
        print(f"⏱️ Elapsed time before cancellation: {elapsed_time:.2f} seconds.")
        sys.exit(130)


if __name__ == "__main__":
    main()
