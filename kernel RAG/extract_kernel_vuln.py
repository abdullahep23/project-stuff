import requests
import time
import json

# NVD API endpoint
url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Your NVD API key
API_KEY = "76f076c3-5ad2-489e-81f7-f414e0f1ac6f"  # Replace with your actual API key

# Number of CVEs to fetch from the end
FETCH_COUNT = 100  

# Headers including the API key
headers = {
    "apiKey": API_KEY
}

# Get total number of CVEs first
print("🔄 Fetching total CVE count...")
params_total = {"keywordSearch": "Linux Kernel", "resultsPerPage": 1, "startIndex": 0}
response_total = requests.get(url, params=params_total, headers=headers)

if response_total.status_code != 200:
    print(f"❌ Error fetching total count: {response_total.status_code} - {response_total.text}")
    exit()

total_cves = response_total.json().get("totalResults", 0)

# Start index for the last 100 CVEs
start_index = max(0, total_cves - FETCH_COUNT)

print(f"🔄 Fetching last {FETCH_COUNT} CVEs (from index {start_index} to {total_cves})...")

# Parameters for fetching last 100 CVEs
params = {
    "keywordSearch": "Linux Kernel",
    "resultsPerPage": FETCH_COUNT,
    "startIndex": start_index
}

# Output file
output_file = "linux_kernel_last_100_cves.json"

# Fetch last 100 CVEs
response = requests.get(url, params=params, headers=headers)

if response.status_code != 200:
    print(f"❌ Error fetching CVEs: {response.status_code} - {response.text}")
    exit()

# Parse response
data = response.json()
vulnerabilities = data.get("vulnerabilities", [])

# Extract relevant details
cve_list = []
for cve in vulnerabilities:
    cve_id = cve["cve"]["id"]
    description = next((desc["value"] for desc in cve["cve"]["descriptions"] if desc["lang"] == "en"), "")
    
    # Extract severity
    metrics = cve["cve"].get("metrics", {})
    severity = "N/A"
    if "cvssMetricV31" in metrics:
        severity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
    elif "cvssMetricV30" in metrics:
        severity = metrics["cvssMetricV30"][0]["cvssData"]["baseSeverity"]
    elif "cvssMetricV2" in metrics:
        severity = metrics["cvssMetricV2"][0]["baseSeverity"]

    # Extract patches (GitHub, Kernel.org, etc.)
    references = cve["cve"].get("references", [])
    patch_links = []
    advisory_links = []
    
    for ref in references:
        url = ref["url"]
        tags = ref.get("tags", [])

        if "github.com" in url and "/commit/" in url:
            patch_links.append(url)
        elif "patch" in tags or "fix" in tags or "git.kernel.org" in url:
            patch_links.append(url)
        elif "security-advisory" in url or "advisory" in tags or "lists.debian.org" in url or "ubuntu.com" in url or "oracle.com" in url:
            advisory_links.append(url)

    # Extract affected systems (Fix applied here)
    affected_systems = []
    configurations = cve["cve"].get("configurations", [])

    if isinstance(configurations, list):  # Ensure configurations is a list
        for config in configurations:
            for node in config.get("nodes", []):  
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable", False):
                        affected_systems.append(cpe_match["criteria"])

    cve_list.append({
        "CVE ID": cve_id,
        "Description": description,
        "Severity": severity,
        "Patches": patch_links,
        "Security Advisories": advisory_links,
        "Affected Systems": affected_systems
    })

# Save results to JSON file
with open(output_file, "w", encoding="utf-8") as f:
    json.dump(cve_list, f, indent=4)

print(f"✅ Successfully fetched last {FETCH_COUNT} CVEs! Saved to '{output_file}'.")
