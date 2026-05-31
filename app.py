import os
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS
import requests
import json
import csv
import sseclient
import random
import hashlib

app = Flask(__name__)
CORS(app)

DATABASE_URL = os.environ.get("DATABASE_URL")

FORTIGUARD_URL = "https://fortiguard.fortinet.com/api/threatmap/live/outbreak?&limit=100"
CHECKPOINT_URL = "https://threatmap-api.checkpoint.com/ThreatMap/api/feed"
RADWARE_URL = "https://ltm-prod-api.radware.com/map/attacks?limit=100"

URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

CHECKPOINT_HEADERS = {"Accept": "text/event-stream"}

ALLOWED_COUNTRIES = ["BE", "NL", "DE"]
POSSIBLE_SOURCE_COUNTRIES = ["CN", "RU", "US", "IN", "TR", "FR", "GB", "PL", "IT", "ES"]


def get_db_connection():
    return psycopg2.connect(DATABASE_URL, sslmode="require")


def init_db():
    if not DATABASE_URL:
        print("DATABASE_URL not found")
        return

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_logs (
                id SERIAL PRIMARY KEY,
                event_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                event_hash TEXT UNIQUE,
                provider TEXT,
                source_country TEXT,
                destination_country TEXT,
                threat_type TEXT,
                threat_name TEXT,
                severity TEXT,
                raw_data JSONB
            );
        """)

        conn.commit()
        cur.close()
        conn.close()
        print("Database initialized")

    except Exception as e:
        print("Database init error:", e)


def create_event_hash(attack):
    hash_text = f"""
    {attack.get("source")}
    {attack.get("sourceCountry")}
    {attack.get("destinationCountry")}
    {attack.get("type")}
    {attack.get("name")}
    {datetime.utcnow().strftime("%Y-%m-%d-%H")}
    """
    return hashlib.sha256(hash_text.encode("utf-8")).hexdigest()


def save_threat(attack):
    if not DATABASE_URL:
        return

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO threat_logs (
                event_hash,
                provider,
                source_country,
                destination_country,
                threat_type,
                threat_name,
                severity,
                raw_data
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (event_hash) DO NOTHING
        """, (
            create_event_hash(attack),
            attack.get("source"),
            attack.get("sourceCountry"),
            attack.get("destinationCountry"),
            attack.get("type"),
            attack.get("name"),
            attack.get("weight"),
            json.dumps(attack)
        ))

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        print("Database save error:", e)


def save_threats(attacks):
    for attack in attacks:
        save_threat(attack)


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
                        src = attack.get("sourceCountry") or random_source_country()
                        dst = attack.get("destinationCountry") or random_allowed_destination(country_code)

                        if not dst or dst.strip() == "":
                            dst = random_allowed_destination(country_code)

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
        "message": "ThreatMap API is live",
        "database": "connected" if DATABASE_URL else "not configured"
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

    save_threats(results)

    return jsonify({
        "count": len(results),
        "data": results
    })


@app.route("/api/stats/top-threats")
def top_threats():
    country_code = request.args.get("country", "BE")
    days = request.args.get("days", "30")

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT threat_type, COUNT(*) AS total
            FROM threat_logs
            WHERE destination_country = %s
            AND event_time >= NOW() - (%s || ' days')::interval
            GROUP BY threat_type
            ORDER BY total DESC
            LIMIT 10
        """, (country_code, days))

        data = cur.fetchall()
        cur.close()
        conn.close()

        return jsonify({
            "country": country_code,
            "days": days,
            "data": data
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats/top-source-countries")
def top_source_countries():
    country_code = request.args.get("country", "BE")
    days = request.args.get("days", "30")

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT source_country, COUNT(*) AS total
            FROM threat_logs
            WHERE destination_country = %s
            AND event_time >= NOW() - (%s || ' days')::interval
            GROUP BY source_country
            ORDER BY total DESC
            LIMIT 10
        """, (country_code, days))

        data = cur.fetchall()
        cur.close()
        conn.close()

        return jsonify({
            "country": country_code,
            "days": days,
            "data": data
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/stats/daily")
def daily_stats():
    country_code = request.args.get("country", "BE")
    days = request.args.get("days", "30")

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT DATE(event_time) AS date, COUNT(*) AS total
            FROM threat_logs
            WHERE destination_country = %s
            AND event_time >= NOW() - (%s || ' days')::interval
            GROUP BY DATE(event_time)
            ORDER BY date ASC
        """, (country_code, days))

        data = cur.fetchall()
        cur.close()
        conn.close()

        return jsonify({
            "country": country_code,
            "days": days,
            "data": data
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/stats/count")
def stats_count():
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT COUNT(*) FROM threat_logs")
        total = cur.fetchone()[0]

        cur.close()
        conn.close()

        return jsonify({
            "total_records": total
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
