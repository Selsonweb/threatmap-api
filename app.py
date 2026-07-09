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
    if not DATABASE_URL or not attacks:
        return

    try:
        conn = get_db_connection()
        cur = conn.cursor()

        for attack in attacks:
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
        print("Database batch save error:", e)

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
                "cve": cve,
                "vendor": vendor,
                "product": product,
                "weight": "High"
            })

        return attacks

    except Exception as e:
        print("CISA KEV error:", e)
        return []


def collect_and_save_threats(country_code=None):
    results = []
    results.extend(fetch_radware_data(country_code))
    results.extend(fetch_urlhaus_data(country_code))
    results.extend(fetch_cisa_kev_data(country_code))
    results.extend(fetch_fortiguard_data(country_code))
    results.extend(fetch_checkpoint_data(country_code))

    save_threats(results)
    return results


@app.route("/")
def home():
    return jsonify({
        "status": "running",
        "message": "ThreatMap API is live",
        "database": "connected" if DATABASE_URL else "not configured"
    })


@app.route("/api/threat-feed")
def threat_feed():
    country_code = request.args.get("country", "BE")

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT
                event_time,
                provider AS source,
                source_country AS "sourceCountry",
                destination_country AS "destinationCountry",
                threat_type AS type,
                threat_name AS name,
                severity AS weight
            FROM threat_logs
            WHERE destination_country = %s
            ORDER BY event_time DESC
            LIMIT 100
        """, (country_code,))

        data = cur.fetchall()
        cur.close()
        conn.close()

        return jsonify({
            "count": len(data),
            "data": data
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/cron/collect-threats")
def cron_collect_threats():
    country = request.args.get("country", "BE")

    if country not in ALLOWED_COUNTRIES:
        return jsonify({
            "status": "error",
            "message": "Invalid country",
            "allowed_countries": ALLOWED_COUNTRIES
        }), 400

    results = []
    errors = []

    try:
        results.extend(fetch_urlhaus_data(country))
    except Exception as e:
        errors.append({"source": "URLhaus", "error": str(e)})

    try:
        results.extend(fetch_cisa_kev_data(country))
    except Exception as e:
        errors.append({"source": "CISA KEV", "error": str(e)})

    try:
        results.extend(fetch_radware_data(country))
    except Exception as e:
        errors.append({"source": "Radware", "error": str(e)})

    save_threats(results)

    return jsonify({
        "status": "success",
        "message": "Threat collection completed",
        "country": country,
        "collected": len(results),
        "errors": errors
    })

def run_provider_collection(provider_name, fetch_function):
    country = request.args.get("country", "BE")

    if country not in ALLOWED_COUNTRIES:
        return jsonify({
            "status": "error",
            "message": "Invalid country",
            "allowed_countries": ALLOWED_COUNTRIES
        }), 400

    errors = []

    try:
        results = fetch_function(country)
        save_threats(results)

        return jsonify({
            "status": "success",
            "provider": provider_name,
            "country": country,
            "collected": len(results),
            "errors": errors
        })

    except Exception as e:
        errors.append({"source": provider_name, "error": str(e)})
        return jsonify({
            "status": "error",
            "provider": provider_name,
            "country": country,
            "collected": 0,
            "errors": errors
        }), 500


@app.route("/api/cron/urlhaus")
def cron_urlhaus():
    return run_provider_collection("URLhaus", fetch_urlhaus_data)


@app.route("/api/cron/cisa")
def cron_cisa():
    return run_provider_collection("CISA KEV", fetch_cisa_kev_data)


@app.route("/api/cron/radware")
def cron_radware():
    return run_provider_collection("Radware", fetch_radware_data)


@app.route("/api/cron/fortiguard")
def cron_fortiguard():
    return run_provider_collection("FortiGuard", fetch_fortiguard_data)


@app.route("/api/cron/checkpoint")
def cron_checkpoint():
    return run_provider_collection("CheckPoint", fetch_checkpoint_data)

@app.route("/api/stats/summary")
def stats_summary():
    country_code = request.args.get("country", "BE")
    days = request.args.get("days", "30")

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM threat_logs
            WHERE destination_country = %s
            AND event_time >= NOW() - (%s || ' days')::interval
        """, (country_code, days))
        total = cur.fetchone()["total"]

        cur.execute("""
            SELECT threat_type, COUNT(*) AS total
            FROM threat_logs
            WHERE destination_country = %s
            AND event_time >= NOW() - (%s || ' days')::interval
            GROUP BY threat_type
            ORDER BY total DESC
            LIMIT 1
        """, (country_code, days))
        top_threat = cur.fetchone()

        cur.execute("""
            SELECT source_country, COUNT(*) AS total
            FROM threat_logs
            WHERE destination_country = %s
            AND event_time >= NOW() - (%s || ' days')::interval
            GROUP BY source_country
            ORDER BY total DESC
            LIMIT 1
        """, (country_code, days))
        top_source = cur.fetchone()

        cur.execute("""
            SELECT COUNT(*) AS total
            FROM threat_logs
            WHERE destination_country = %s
            AND severity = 'High'
            AND event_time >= NOW() - (%s || ' days')::interval
        """, (country_code, days))
        high_severity = cur.fetchone()["total"]

        cur.execute("""
            SELECT threat_name, COUNT(*) AS total
            FROM threat_logs
            WHERE destination_country = %s
            AND threat_type = 'Known Exploited Vulnerability'
            AND event_time >= NOW() - (%s || ' days')::interval
            GROUP BY threat_name
            ORDER BY total DESC
            LIMIT 1
        """, (country_code, days))
        top_cve = cur.fetchone()

        cur.close()
        conn.close()

        return jsonify({
            "country": country_code,
            "days": days,
            "totalThreats": total,
            "topThreat": top_threat["threat_type"] if top_threat else None,
            "topThreatCount": top_threat["total"] if top_threat else 0,
            "topSourceCountry": top_source["source_country"] if top_source else None,
            "topSourceCount": top_source["total"] if top_source else 0,
            "highSeverity": high_severity,
            "topCVE": top_cve["threat_name"] if top_cve else None,
            "topCVECount": top_cve["total"] if top_cve else 0
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


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


@app.route("/api/stats/top-cves")
def top_cves():
    country_code = request.args.get("country", "BE")
    days = request.args.get("days", "30")

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT threat_name, COUNT(*) AS total
            FROM threat_logs
            WHERE destination_country = %s
            AND threat_type = 'Known Exploited Vulnerability'
            AND event_time >= NOW() - (%s || ' days')::interval
            GROUP BY threat_name
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

@app.route("/api/intelligence/top-cves")
def intelligence_top_cves():
    country_code = request.args.get("country", "BE")
    days = request.args.get("days", "30")

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT
                COALESCE(raw_data->>'cve', split_part(threat_name, ' - ', 1)) AS cve,
                COALESCE(raw_data->>'vendor', '') AS vendor,
                COALESCE(raw_data->>'product', '') AS product,
                COUNT(*) AS total
            FROM threat_logs
            WHERE
                destination_country = %s
                AND threat_type = 'Known Exploited Vulnerability'
                AND event_time >= NOW() - (%s || ' days')::interval
            GROUP BY cve, vendor, product
            ORDER BY total DESC
            LIMIT 20
        """, (country_code, days))

        rows = cur.fetchall()
        cur.close()
        conn.close()

        return jsonify([
            {
                "cve": row["cve"],
                "vendor": row["vendor"],
                "product": row["product"],
                "count": row["total"]
            }
            for row in rows
        ])

    except Exception as e:
        return jsonify({"error": str(e)}), 500

KNOWN_VENDORS = [
    "Check Point",
    "SolarWinds",
    "SimpleHelp",
    "Cisco",
    "Ivanti",
    "Ubiquiti",
    "PTC",
    "BerriAI",
    "Mirasvit",
    "Arista",
    "Splunk",
    "LiteSpeed",
    "Lantronix",
    "Google",
    "Oracle"
]


@app.route("/api/intelligence/top-cves")
def intelligence_top_cves():
    country_code = request.args.get("country", "BE")
    days = request.args.get("days", "30")

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)

        cur.execute("""
            SELECT
                threat_name,
                COUNT(*) AS total
            FROM threat_logs
            WHERE
                destination_country = %s
                AND threat_type = 'Known Exploited Vulnerability'
                AND event_time >= NOW() - (%s || ' days')::interval
            GROUP BY threat_name
            ORDER BY total DESC
            LIMIT 20
        """, (country_code, days))

        rows = cur.fetchall()
        result = []

        for row in rows:
            text = row["threat_name"]
            parts = text.split(" - ", 1)

            cve = parts[0]
            full_product = parts[1] if len(parts) > 1 else ""

            vendor = ""
            clean_product = full_product

            for known_vendor in KNOWN_VENDORS:
                if full_product.startswith(known_vendor):
                    vendor = known_vendor
                    clean_product = full_product.replace(known_vendor, "", 1).strip()
                    break

            if not vendor:
                vendor = full_product.split(" ")[0] if full_product else ""
                clean_product = full_product.replace(vendor, "", 1).strip()

            result.append({
                "cve": cve,
                "vendor": vendor,
                "product": clean_product,
                "count": row["total"]
            })

        cur.close()
        conn.close()

        return jsonify(result)

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
