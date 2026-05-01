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

ALLOWED_COUNTRIES = ["BE", "NL", "DE"]


def is_allowed(src, dst, country_code=None):
    if country_code:
        return dst == country_code
    return src in ALLOWED_COUNTRIES or dst in ALLOWED_COUNTRIES


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
                                "type": attack.get("profile_type", ""),
                                "name": attack.get("vuln_name", ""),
                                "weight": attack.get("severity", "")
                            })

        return attacks[:20]

    except Exception:
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
                        "type": data.get("a_t", ""),
                        "name": data.get("a_n", ""),
                        "weight": data.get("a_c", "")
                    })

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
                        src = attack.get("sourceCountry", "")
                        dst = attack.get("destinationCountry", "")

                        if is_allowed(src, dst, country_code):
                            attacks.append({
                                "source": "Radware",
                                "sourceCountry": src,
                                "destinationCountry": dst,
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
