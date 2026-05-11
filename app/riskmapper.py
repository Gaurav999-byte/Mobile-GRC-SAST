import json
import os
import re
from collections import defaultdict

RULES_PATH = os.path.join(os.path.dirname(__file__), "rules.json")

try:
    with open(RULES_PATH, "r", encoding="utf-8") as f:
        RULES = json.load(f)
except:
    RULES = {}


# =========================
# NORMALIZE TEXT
# =========================
def normalize(text):
    return re.sub(r"[^a-z0-9]+", " ", (text or "").lower()).strip()


# =========================
# RULE SCORING
# =========================
def score_rule(issue_text, rule_key):
    issue = normalize(issue_text)
    rule = normalize(rule_key)

    if not issue:
        return 0

    score = 0

    if issue == rule:
        score += 100

    if rule in issue:
        score += 50

    for word in rule.split():
        if word in issue:
            score += 10

    return score


# =========================
# BEST MATCH
# =========================
def best_rule_match(issue):
    best_key = None
    best_score = 0

    for key in RULES.keys():
        s = score_rule(issue, key)
        if s > best_score:
            best_score = s
            best_key = key

    if best_score < 20:
        return None

    return best_key


# =========================
# MAIN FUNCTION
# =========================
def map_findings(findings):

    grouped = defaultdict(lambda: {
        "severity": "Medium",
        "evidence": [],
        "iso27001": "",
        "gdpr": "",
        "owasp": "",
        "recommendation": ""
    })

    for f in findings:

        issue = f.get("description", f.get("issue", "")).strip()
        severity = f.get("severity", "Medium")
        evidence = f.get("evidence", "")

        if not issue:
            continue

        grouped[issue]["evidence"].append(evidence)

        order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

        if order.get(severity, 2) > order.get(grouped[issue]["severity"], 2):
            grouped[issue]["severity"] = severity

        key = best_rule_match(issue)

        if key:
            r = RULES.get(key, {})
            grouped[issue]["iso27001"] = r.get("ISO27001", "")
            grouped[issue]["gdpr"] = r.get("GDPR", "")
            grouped[issue]["owasp"] = r.get("OWASP_MASVS", "")
            grouped[issue]["recommendation"] = r.get("recommendation", "")
        else:
            grouped[issue]["recommendation"] = "Review manually"

    final_list = []

    for idx, (issue, data) in enumerate(grouped.items(), start=1):

        final_list.append({
            "id": idx,
            "issue": issue,
            "severity": data["severity"],
            "evidence": ", ".join(data["evidence"]),
            "iso27001": data["iso27001"],
            "gdpr": data["gdpr"],
            "owasp": data["owasp"],
            "recommendation": data["recommendation"]
        })

    return final_list


# =========================
# SUMMARY
# =========================
def severity_summary(mapped):

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}

    for f in mapped:
        sev = f.get("severity", "Medium")

        if sev in counts:
            counts[sev] += 1
        else:
            counts["Medium"] += 1

    return counts