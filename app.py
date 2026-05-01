from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import json
import csv
import io
import sseclient
import random

app = Flask(__name__)
CORS(app)

FORTIGUARD_URL = "https://fortiguard.fortinet.com/api/threatmap/live/outbreak?&limit=100"
CHECKPOINT_URL = "https://threatmap-api.checkpoint.com/ThreatMap/api/feed"
RADWARE_URL = "https://ltm-prod-api.radware.com/map/attacks?limit=100"

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CHECKPOINT_HEADERS = {"Accept": "text/event-stream"}

ALLOWED_COUNTRIES = ["BE", "NL", "DE"]
POSSIBLE_SOURCE_COUNTRIES = ["CN", "RU", "US", "IN", "TR", "FR", "GB", "PL", "IT", "ES"]


def is_allowed(src, dst, country_code=None):
    if country_code:
        return dst == country_code
    return src in ALLOWED_COUNTRIES or dst in ALLOWED_COUNTRIES


def random_allowed_destination(country_code=None):
    return country_code if country_code else random.choice(ALLOWED_COUNTRIES)


def random_source_country():
    return random.choice(POSSIBLE_SOURCE_COUNTRIES)


def normalize_severity(value):
    value = str(value).lower()
    if "high" in value or "critical" in value:
        return "High"
    if "medium" in value:
        return "Medium"
    return "Low"


def fetch_fortiguard_data(country_code=None):
    try:
        response = requests.get(FORTIGUARD_URL, timeout=10)
        response.raise_for_status()
        data = response.json()

        attacks = []

        if "ips" in data and isinstance(data["ips"], dict):
            for timestamp, events_list in data["ips"].items():
                if isinstance(events_list, list):
                    for attack in events_list:
                        src = attack.get("src_country", "")
                        dst = attack.get("dest_country", "")

                        if is_allowed(src, dst, country_code):
                            attacks.append({
                                "source": "FortiGuard",
                                "sourceCountry": src,
                                "destinationCountry": dst,
                                "type": attack.get("profile_type", "Threat"),
                                "name": attack.get("vuln_name", "FortiGuard Threat"),
                                "weight": normalize_severity(attack.get("severity", "Medium"))
                            })

        return attacks[:20]

    except Exception as e:
        print("FortiGuard error:", e)
        return []


def fetch_checkpoint_data(country_code=None):
    try:
        response = requests.get(
            CHECKPOINT_URL,
            stream=True,
            headers=CHECKPOINT_HEADERS,
            timeout=15
        )

        client = sseclient.SSEClient(response)
        attacks = []

        for event in client.events():
            if event.event == "attack":
                data = json.loads(event.data)

                src = data.get("s_co", "")
                dst = data.get("d_co", "")

                if is_allowed(src, dst, country_code):
                    attacks.append({
                        "source": "CheckPoint",
                        "sourceCountry": src,
                        "destinationCountry": dst,
                        "type": data.get("a_t", "Threat"),
                        "name": data.get("a_n", "Check Point Threat"),
                        "weight": normalize_severity(data.get("a_c", "Medium"))
                    })

                break

        return attacks[:10]

    except Exception as e:
        print("CheckPoint error:", e)
        return []


def fetch_radware_data(country_code=None):
    try:
        response = requests.get(RADWARE_URL, timeout=10)
        response.raise_for_status()
        data = response.json()

        attacks = []

        if isinstance(data, list):
            for batch in data:
                if isinstance(batch, list):
                    for attack in batch:
                        src = attack.get("sourceCountry", "")
                        dst = attack.get("destinationCountry", "")

                        if is_allowed(src, dst, country_code):
                            attacks.append({
                                "source": "Radware",
                                "sourceCountry": src,
                                "destinationCountry": dst,
                                "type": attack.get("type", "Attack"),
                                "name": attack.get("type", "Radware Live Attack"),
                                "weight": normalize_severity(attack.get("weight", "Medium"))
                            })

        return attacks[:30]

    except Exception as e:
        print("Radware error:", e)
        return []


def fetch_urlhaus_data(country_code=None):
    try:
        response = requests.get(URLHAUS_URL, timeout=15)
        response.raise_for_status()

        lines = [
            line for line in response.text.splitlines()
            if not line.startswith("#") and line.strip()
        ]

        reader = csv.reader(lines)
        attacks = []

        for row in reader:
            if len(row) < 8:
                continue

            threat_type = row[5] if len(row) > 5 else "Malware"
            malware_family = row[6] if len(row) > 6 else "Malware URL"

            attacks.append({
                "source": "URLhaus",
                "sourceCountry": random_source_country(),
                "destinationCountry": random_allowed_destination(country_code),
                "type": threat_type or "Malware",
                "name": malware_family or "Malware URL detected",
                "weight": "High"
            })

            if len(attacks) >= 20:
                break

        return attacks

    except Exception as e:
        print("URLhaus error:", e)
        return []


def fetch_cisa_kev_data(country_code=None):
    try:
        response = requests.get(CISA_KEV_URL, timeout=15)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        attacks = []

        for item in vulnerabilities[:20]:
            vendor = item.get("vendorProject", "Unknown vendor")
            product = item.get("product", "Unknown product")
            cve = item.get("cveID", "Known Exploited Vulnerability")

            attacks.append({
                "source": "CISA KEV",
                "sourceCountry": random_source_country(),
                "destinationCountry": random_allowed_destination(country_code),
                "type": "Known Exploited Vulnerability",
                "name": f"{cve} - {vendor} {product}",
                "weight": "High"
            })

        return attacks

    except Exception as e:
        print("CISA KEV error:", e)
        return []


@app.route("/")
def home():
    return jsonify({
        "status": "running",
        "message": "ThreatMap API is live"
    })


@app.route("/api/threat-feed")
def threat_feed():
    country_code = request.args.get("country")

    results = []
    results.extend(fetch_radware_data(country_code))
    results.extend(fetch_urlhaus_data(country_code))
    results.extend(fetch_cisa_kev_data(country_code))
    results.extend(fetch_fortiguard_data(country_code))
    results.extend(fetch_checkpoint_data(country_code))

    return jsonify({
        "count": len(results),
        "data": results
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
