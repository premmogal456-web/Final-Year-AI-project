from database import insert_log
import pickle
from collections import Counter
import re
import matplotlib.pyplot as plt

# -----------------------------
# Load ML Model
# -----------------------------
model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))


# -----------------------------
# Extract IP Address
# -----------------------------
def extract_ip(log_line):
    match = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", log_line)
    return match.group() if match else "Unknown"


# -----------------------------
# Severity Mapping
# -----------------------------
def get_severity(prediction):

    severity_map = {
        "safe": "Low",
        "brute_force": "High",
        "sql_injection": "Critical",
        "xss": "Medium",
        "ddos": "Critical",
        "command_injection": "High",
        "path_traversal": "High",
        "malware": "Critical",
        "unauthorized_access": "High"
    }

    return severity_map.get(prediction.lower(), "Medium")


# -----------------------------
# Prevention Mapping
# -----------------------------
def get_prevention(threat):

    prevention_map = {
        "sql_injection": "Use parameterized queries and validate inputs.",
        "xss": "Sanitize inputs and enable Content Security Policy.",
        "brute_force": "Enable account lockout and CAPTCHA.",
        "ddos": "Enable rate limiting and firewall protection.",
        "command_injection": "Restrict system commands and validate inputs.",
        "path_traversal": "Restrict file paths and validate filenames.",
        "malware": "Scan uploaded files and block executable extensions.",
        "unauthorized_access": "Implement strong authentication and role control.",
        "safe": "No action required."
    }

    return prevention_map.get(threat.lower(), "Monitor suspicious activity.")


# -----------------------------
# Main Analyzer
# -----------------------------
def analyze_logs(file_path):

    results = []
    threat_list = []
    attack_ip_list = []

    try:
        with open(file_path, "r", encoding="utf-8") as file:

            for line in file:
                clean_line = line.strip()

                if not clean_line:
                    continue

                ip = extract_ip(clean_line)

                # ML Prediction
                features = vectorizer.transform([clean_line])
                prediction = model.predict(features)[0]

                severity = get_severity(prediction)
                prevention = get_prevention(prediction)

                # Insert into database
                insert_log(ip, clean_line, prediction)

                threat_list.append(prediction)

                # Count attack IPs only
                if prediction.lower() != "safe":
                    attack_ip_list.append(ip)

                results.append({
                    "ip": ip,
                    "log": clean_line,
                    "threat": prediction,
                    "severity": severity,
                    "prevention": prevention
                })

    except Exception as e:
        print("Error analyzing logs:", e)
        return [], {}, 0, "N/A", 0

    # -----------------------------
    # Statistics
    # -----------------------------
    stats = dict(Counter(threat_list))
    total_logs = len(results)
    total_attacks = total_logs - stats.get("safe", 0)

    # Most Dangerous IP
    if attack_ip_list:
        ip_counter = Counter(attack_ip_list)
        most_dangerous_ip = ip_counter.most_common(1)[0][0]
    else:
        most_dangerous_ip = "N/A"

    # Threat Score
    threat_score = (total_attacks / total_logs) * 100 if total_logs > 0 else 0

    # -----------------------------
    # Generate Chart
    # -----------------------------
    if stats:
        plt.figure(figsize=(8, 5))
        plt.bar(stats.keys(), stats.values())
        plt.xlabel("Threat Type")
        plt.ylabel("Count")
        plt.title("Attack Distribution")
        plt.xticks(rotation=30)
        plt.tight_layout()
        plt.savefig("static/attack_chart.png")
        plt.close()

    return results, stats, total_logs, most_dangerous_ip, threat_score