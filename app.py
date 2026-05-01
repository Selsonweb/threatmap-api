from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import json
import sseclient

app = Flask(__name__)
CORS(app)

FORTIGUARD_URL = "https://fortiguard.fortinet.com/api/threatmap/live/outbreak?&limit=100"
CHECKPOINT_URL = "https://threatmap-api.checkpoint.com/ThreatMap/api/feed"
RADWARE_URL = "https://ltm-prod-api.radware.com/map/attacks?limit=100"

CHECKPOINT_HEADERS = {"Accept": "text/event-stream"}


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
                        if country_code is None or attack.get("dest_country") == country_code:
                            attacks.append({
                                "source": "FortiGuard",
                                "sourceCountry": attack.get("src_country", ""),
                                "destinationCountry": attack.get("dest_country", ""),
                                "type": attack.get("profile_type", ""),
                                "name": attack.get("vuln_name", ""),
                                "weight": attack.get("severity", "")
                            })

        return attacks[:20]

    except Exception as e:
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

                record = {
                    "source": "CheckPoint",
                    "sourceCountry": data.get("s_co", ""),
                    "destinationCountry": data.get("d_co", ""),
                    "type": data.get("a_t", ""),
                    "name": data.get("a_n", ""),
                    "weight": data.get("a_c", "")
                }

                if country_code is None or record["destinationCountry"] == country_code:
                    attacks.append(record)

                break

        return attacks

    except Exception:
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
                        if country_code is None or attack.get("destinationCountry") == country_code:
                            attacks.append({
                                "source": "Radware",
                                "sourceCountry": attack.get("sourceCountry", ""),
                                "destinationCountry": attack.get("destinationCountry", ""),
                                "type": attack.get("type", ""),
                                "name": "",
                                "weight": attack.get("weight", "")
                            })

        return attacks[:20]

    except Exception:
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
    results.extend(fetch_fortiguard_data(country_code))
    results.extend(fetch_checkpoint_data(country_code))
    results.extend(fetch_radware_data(country_code))

    return jsonify({
        "count": len(results),
        "data": results
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
