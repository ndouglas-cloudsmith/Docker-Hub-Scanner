import os
import sys
import urllib.parse
import json
import requests

def check_container():
    # 1. Grab the API key from your environment variables
    api_key = os.getenv("OSM_KEY")
    if not api_key:
        print("Error: The OSM_KEY environment variable is not set.", file=sys.stderr)
        print("Please run: export OSM_KEY=\"your_token_here\"", file=sys.stderr)
        sys.exit(1)

    # 2. Prompt the user for the container name
    try:
        container_input = input("Enter the Docker Hub container (user/image): ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\nExiting.")
        sys.exit(0)

    if not container_input:
        print("Error: Container name cannot be empty.", file=sys.stderr)
        sys.exit(1)

    # 3. URL-encode the container name (e.g., aquasec/trivy -> aquasec%2Ftrivy)
    encoded_container = urllib.parse.quote(container_input, safe='')

    # 4. Set up the API request
    url = f"https://api.opensourcemalware.com/functions/v1/check-malicious"
    params = {
        "report_type": "container",
        "resource_identifier": container_input  # requests handles encoding query params automatically!
    }
    headers = {
        "Authorization": f"Bearer {api_key}"
    }

    try:
        # Send the GET request
        response = requests.get(url, params=params, headers=headers)
        
        # Check for HTTP errors (like 401 Unauthorized, etc.)
        response.raise_for_status()
        data = response.json()

    except requests.exceptions.HTTPError as http_err:
        # Try to print the API's custom error message if available
        try:
            err_json = response.json()
            print(f"API Error ({response.status_code}): {err_json.get('error', response.text)}", file=sys.stderr)
        except Exception:
            print(f"HTTP error occurred: {http_err}", file=sys.stderr)
        sys.exit(1)
    except Exception as err:
        print(f"An error occurred: {err}", file=sys.stderr)
        sys.exit(1)

    # 5. Process and format the output
    is_malicious = data.get("malicious", False)
    
    # Check if a threat ID exists in the nested "details" object
    has_threat_id = isinstance(data.get("details"), dict) and "threat_id" in data["details"]

    if is_malicious and has_threat_id:
        # Print the raw JSON beautifully indented (replicating jq)
        print(json.dumps(data, indent=2))
    else:
        # Fallback message if it's safe or missing threat details
        print("container not flagged as malicious")

if __name__ == "__main__":
    check_container()
