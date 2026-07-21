import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()

# Persistent session configured for thread-safety and connection reuse
SESSION = requests.Session()
adapter = HTTPAdapter(
    pool_connections=30,
    pool_maxsize=30,
    max_retries=Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504]),
)
SESSION.mount("https://", adapter)
SESSION.mount("http://", adapter)

# Local offline database for common CWEs (Guarantees instant lookup & zero rate-limiting failures)
BUILTIN_CWE_DB = {
    "CWE-20": ("Improper Input Validation", "The product receives input or data but does not validate or incorrectly validates that the input has the properties required to process the data safely."),
    "CWE-22": ("Path Traversal", "The product uses external input to construct a pathname that resolves outside of the restricted directory."),
    "CWE-59": ("Link Following", "The product attempts to access a file based on filename without preventing shortcuts/links resolving to unintended resources."),
    "CWE-75": ("Failure to Sanitize Special Elements", "The product fails to properly sanitize special elements before passing data to downstream components."),
    "CWE-90": ("LDAP Injection", "The product constructs an LDAP statement using externally-influenced input without proper neutralization."),
    "CWE-94": ("Code Injection", "The product constructs all or part of a code segment using externally-influenced input."),
    "CWE-95": ("Eval Injection", "The product receives input from an upstream component but does not neutralize syntax before dynamic evaluation."),
    "CWE-119": ("Improper Restriction of Memory Buffer Operations", "The product performs operations on a memory buffer but reads from or writes to an unintended memory location."),
    "CWE-120": ("Buffer Copy Without Checking Size", "The product copies a buffer without checking that the destination buffer is large enough."),
    "CWE-121": ("Stack-based Buffer Overflow", "A stack-based buffer overflow condition exists where memory allocated on the stack is overwritten."),
    "CWE-122": ("Heap-based Buffer Overflow", "A heap overflow condition exists where memory allocated on the heap is overwritten."),
    "CWE-125": ("Out-of-bounds Read", "The product reads data past the end or before the beginning of the intended buffer."),
    "CWE-178": ("Improper Handling of Case Sensitivity", "The product does not properly account for differences in case sensitivity when accessing resources."),
    "CWE-184": ("Incomplete List of Disallowed Inputs", "The protection mechanism relies on a list of disallowed inputs that is incomplete."),
    "CWE-190": ("Integer Overflow or Wraparound", "The product performs a calculation that can produce an integer overflow or wraparound."),
    "CWE-191": ("Integer Underflow", "An integer value is subtracted to a value below its minimum representable integer."),
    "CWE-193": ("Off-by-one Error", "The product calculates or uses an incorrect maximum or minimum value that is off by one."),
    "CWE-200": ("Exposure of Sensitive Information", "The product exposes sensitive information to an actor that is not explicitly authorized."),
    "CWE-203": ("Observable Discrepancy", "The product behaves differently in a way that reveals sensitive information to unauthorized actors."),
    "CWE-244": ("Heap Inspection", "Sensitive information stored in heap memory is not properly cleared before release."),
    "CWE-294": ("Authentication Bypass by Capture-replay", "The product does not prevent capture-replay attacks during authentication."),
    "CWE-295": ("Improper Certificate Validation", "The product does not validate or incorrectly validates a security certificate."),
    "CWE-319": ("Cleartext Transmission of Sensitive Information", "Sensitive data is transmitted in cleartext over an unencrypted communication channel."),
    "CWE-345": ("Insufficient Verification of Data Authenticity", "The product does not sufficiently verify the origin or authenticity of data."),
    "CWE-347": ("Improper Verification of Cryptographic Signature", "The product does not verify or incorrectly verifies a cryptographic signature."),
    "CWE-367": ("TOCTOU Race Condition", "The product checks resource state before use, but the state changes between check and use."),
    "CWE-400": ("Uncontrolled Resource Consumption", "The product does not properly control the allocation and maintenance of limited resources."),
    "CWE-415": ("Double Free", "The product calls free() twice on the same memory address."),
    "CWE-416": ("Use After Free", "The product reuses or references memory after it has been freed."),
    "CWE-426": ("Untrusted Search Path", "The product uses an untrusted search path that may contain malicious code."),
    "CWE-436": ("Interpretation Conflict", "Product A handles inputs differently than Product B, leading to security inconsistencies."),
    "CWE-444": ("HTTP Request Smuggling", "Inconsistent HTTP parsing allows attackers to smuggle requests past proxies."),
    "CWE-476": ("NULL Pointer Dereference", "The product dereferences a pointer that expected to be valid but is NULL."),
    "CWE-502": ("Deserialization of Untrusted Data", "The product deserializes untrusted data without sufficiently ensuring resulting data validity."),
    "CWE-522": ("Insufficiently Protected Credentials", "The product transmits or stores credentials without adequate protection."),
    "CWE-601": ("URL Redirection ('Open Redirect')", "The web application accepts user-controlled input to redirect to an external site."),
    "CWE-617": ("Reachable Assertion", "An assert() statement can be triggered by an attacker to crash the application."),
    "CWE-664": ("Improper Control of Resource Lifetime", "The product incorrectly maintains control over a resource throughout its lifecycle."),
    "CWE-674": ("Uncontrolled Recursion", "The product does not properly control recursion depth, leading to stack exhaustion."),
    "CWE-675": ("Multiple Operations on Resource", "The product performs multiple operations on a resource in an improper context."),
    "CWE-680": ("Integer Overflow to Buffer Overflow", "An integer overflow occurs during memory allocation calculations."),
    "CWE-755": ("Improper Handling of Exceptional Conditions", "The product incorrectly handles or fails to handle an exceptional condition."),
    "CWE-770": ("Allocation of Resources Without Limits", "The product allocates resources on behalf of an actor without imposing quotas or limits."),
    "CWE-787": ("Out-of-bounds Write", "The product writes data past the end or before the beginning of the intended buffer."),
    "CWE-789": ("Uncontrolled Memory Allocation", "Memory allocation size is derived from an untrusted source without upper bounds."),
    "CWE-835": ("Infinite Loop", "The product contains an iteration loop with an unreachable exit condition."),
    "CWE-908": ("Use of Uninitialized Resource", "The product accesses a resource that has not been initialized."),
    "CWE-918": ("Server-Side Request Forgery (SSRF)", "The web application fetches a remote resource without validating the supplied URL."),
}

# In-memory cache for fetched CWE details
CWE_CACHE = dict(BUILTIN_CWE_DB)


def fetch_single_cwe_detail(cwe_id):
    """Fetch Name and Description for a CWE ID with local database fallback and API queries."""
    if not cwe_id or cwe_id == "N/A":
        return cwe_id, ("N/A", "No description available")

    if cwe_id in CWE_CACHE:
        return cwe_id, CWE_CACHE[cwe_id]

    match = re.search(r"\d+", cwe_id)
    if not match:
        return cwe_id, ("N/A", "No description available")

    cwe_num = match.group(0)

    # MITRE REST API
    try:
        mitre_url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_num}"
        resp = SESSION.get(mitre_url, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            weaknesses = data.get("Weaknesses", [])
            if weaknesses:
                item = weaknesses[0]
                name = item.get("Name", "N/A")
                desc = item.get("Description", "No description available")
                desc = str(desc).strip().replace("\n", " ")

                res = (name, desc)
                return cwe_id, res
    except Exception:
        pass

    fallback = ("N/A", "No description available")
    return cwe_id, fallback


def get_cwe_details_batch(cwe_ids):
    """Batch fetch CWE details concurrently and populate CWE_CACHE safely."""
    unique_ids = [c for c in set(cwe_ids) if c and c != "N/A" and c not in CWE_CACHE]
    if not unique_ids:
        return

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(fetch_single_cwe_detail, cwe_id) for cwe_id in unique_ids]
        for future in as_completed(futures):
            try:
                cwe_id, details = future.result()
                CWE_CACHE[cwe_id] = details
            except Exception:
                pass


def fetch_single_cwe_mapping(cve):
    """Worker function to look up CWE ID for a single CVE using OSV and NVD APIs."""
    try:
        # OSV API check
        resp = SESSION.get(f"https://api.osv.dev/v1/vulns/{cve}", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            cwes = data.get("database_specific", {}).get("cwes", [])
            if cwes:
                cwe_item = cwes[0]
                val = cwe_item.get("cweId") if isinstance(cwe_item, dict) else str(cwe_item)
                if val.startswith("CWE-"):
                    return cve, val

        # NVD API fallback
        nvd_resp = SESSION.get(
            f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}",
            timeout=3,
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
                            return cve, val
    except Exception:
        pass

    return cve, "N/A"


def get_cwe_map(cve_list):
    """Query OSV/NVD endpoints concurrently using thread pooling."""
    valid_cves = list({cve for cve in cve_list if cve.startswith("CVE-")})
    if not valid_cves:
        return {}

    cwe_map = {}
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = [executor.submit(fetch_single_cwe_mapping, cve) for cve in valid_cves]
        for future in as_completed(futures):
            try:
                cve, cwe_id = future.result()
                cwe_map[cve] = cwe_id
            except Exception:
                pass

    return cwe_map


def get_cisa_kev_set():
    """Download CISA KEV catalog and return a set of CVE IDs currently being exploited."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        resp = SESSION.get(url, timeout=5)
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
    valid_cves = list({cve for cve in cve_list if cve.startswith("CVE-")})
    if not valid_cves:
        return {}

    epss_map = {}
    chunk_size = 50
    for i in range(0, len(valid_cves), chunk_size):
        chunk = valid_cves[i : i + chunk_size]
        url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
        try:
            resp = SESSION.get(url, timeout=5)
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


def check_osm(container_name, api_key):
    """Query OSM API to check if the image is flagged as malicious."""
    url = "https://api.opensourcemalware.com/functions/v1/check-malicious"
    params = {
        "report_type": "container",
        "resource_identifier": container_name,
    }
    headers = {"Authorization": f"Bearer {api_key}"}

    try:
        response = SESSION.get(url, params=params, headers=headers, timeout=10)
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
                        "score": score_str,
                    }
                )

    return counts, detailed_findings


def render_rich_table(filtered_findings, cwe_map, epss_map, kev_set, filter_label, verbose=False):
    """Renders formatted Rich table."""
    table = Table(
        title=f"--- Filtered Listing ({filter_label}) [{len(filtered_findings)} item(s)] ---",
        title_style="bold yellow",
        show_lines=False,
        header_style="bold cyan",
        expand=True,
    )

    table.add_column("SEVERITY", style="bold red", width=10, no_wrap=True)
    table.add_column("CVE / ID", width=22, no_wrap=True)
    table.add_column("PACKAGE", max_width=28, overflow="fold")
    table.add_column("CWE ID", width=10, no_wrap=True)
    table.add_column("CWE NAME", max_width=30, overflow="ellipsis")
    table.add_column("CVSS", justify="right", width=6)
    table.add_column("EPSS", justify="right", width=8)
    table.add_column("KEV", justify="center", width=6)

    if verbose:
        table.add_column("DESCRIPTION", max_width=45, overflow="ellipsis")

    for item in filtered_findings:
        cve = item["cve"]
        cwe_id = cwe_map.get(cve, "N/A")
        cwe_name, cwe_desc = CWE_CACHE.get(cwe_id, ("N/A", "No description available"))

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
            epss_style = (
                "bold red" if pct >= 50.0 else ("yellow" if pct >= 10.0 else "default")
            )
            epss_display = Text(f"{pct:.1f}%", style=epss_style)
        else:
            epss_display = Text("N/A", style="dim")

        # KEV Styling
        is_kev = cve in kev_set
        kev_display = (
            Text("YES 🚨", style="bold red") if is_kev else Text("NO", style="dim green")
        )

        row = [
            item["severity"],
            cve,
            item["package"],
            cwe_id,
            cwe_name,
            cvss_display,
            epss_display,
            kev_display,
        ]

        if verbose:
            row.append(cwe_desc)

        table.add_row(*row)

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
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed CWE descriptions in the output table",
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

    sort_group = parser.add_mutually_exclusive_group()
    sort_group.add_argument(
        "--epss-desc",
        action="store_true",
        help="Sort findings by EPSS score in descending order",
    )
    sort_group.add_argument(
        "--cvss-desc",
        action="store_true",
        help="Sort findings by CVSS score in descending order",
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

                if target_severities:
                    filtered_findings = [
                        f for f in findings if f["severity"] in target_severities
                    ]
                    filter_label = " & ".join(target_severities) + " Severity"
                else:
                    filtered_findings = findings
                    filter_label = "All Severities"

                print(f"\nFetching CISA KEV threat intelligence...")
                kev_set = get_cisa_kev_set()

                if args.kev:
                    filtered_findings = [f for f in filtered_findings if f["cve"] in kev_set]
                    filter_label += " | KEV Only 🚨"

                if filtered_findings:
                    print(f"Fetching EPSS and CWE threat intelligence (Parallel)...")
                    unique_cves = list({item["cve"] for item in filtered_findings})
                    epss_map = get_epss_scores(unique_cves)
                    cwe_map = get_cwe_map(unique_cves)

                    # Pre-fetch details for any CWEs not already in BUILTIN_CWE_DB
                    unique_cwes = list(set(cwe_map.values()))
                    get_cwe_details_batch(unique_cwes)

                    if args.cwe_true:
                        filtered_findings = [
                            f
                            for f in filtered_findings
                            if cwe_map.get(f["cve"]) and cwe_map.get(f["cve"]) != "N/A"
                        ]
                        filter_label += " | CWE True Only 🏷️"

                    if args.epss_desc:
                        filtered_findings.sort(
                            key=lambda item: epss_map.get(item["cve"], 0.0),
                            reverse=True,
                        )
                        filter_label += " | Sorted by EPSS ⬇️"

                    elif args.cvss_desc:

                        def parse_score(item):
                            try:
                                return float(item["score"])
                            except ValueError:
                                return 0.0

                        filtered_findings.sort(key=parse_score, reverse=True)
                        filter_label += " | Sorted by CVSS ⬇️"

                    if filtered_findings:
                        render_rich_table(
                            filtered_findings,
                            cwe_map,
                            epss_map,
                            kev_set,
                            filter_label,
                            verbose=args.verbose,
                        )
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
