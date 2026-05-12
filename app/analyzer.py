import re
from typing import List, Dict



# =========================
# DANGEROUS PERMISSIONS
# =========================
DANGEROUS_PERMS = {

    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_SETTINGS",
    "android.permission.SYSTEM_ALERT_WINDOW"
}


# =========================
# REGEX PATTERNS
# =========================
PATTERNS = {

    "Hardcoded API Keys":
    r"(?i)(api[_-]?key|secret|token)[\"'\s:=]{1,5}[A-Za-z0-9_\-]{8,}",

    "Plaintext HTTP":
    r"http://",

    "Weak Cryptography":
    r"(?i)\b(md5|sha1)\b",

    "Insecure Random":
    r"(?i)(\bSecureRandom\b|Random\.)",

    "Logging Sensitive Data":
    r"(?i)(log|print)\(.*(password|token|secret).*",

    "WebView JS Enabled":
    r"(?i)setJavaScriptEnabled\s*\(\s*true\s*\)",

    "File Path Exposure":
    r"/sdcard/|/storage/emulated/",

    "Unencrypted Storage":
    r"(?i)MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"
}


# =========================
# SEVERITY CLASSIFICATION
# =========================
def classify_severity(issue: str) -> str:

    issue = issue.lower()

    if any(k in issue for k in [
        "hardcoded",
        "weak cryptography",
        "unencrypted",
        "dangerous permission"
    ]):
        return "Critical"

    elif any(k in issue for k in [
        "debuggable",
        "exported",
        "cleartext"
    ]):
        return "High"

    elif any(k in issue for k in [
        "backup",
        "webview",
        "http",
        "random"
    ]):
        return "Medium"

    return "Low"


# =========================
# MAIN ANALYZER
# =========================
# =========================
# MAIN ANALYZER
# =========================
def analyze_apk(path: str) -> List[Dict]:

    findings = []

    print("[analyzer] analyzing:", path)

    # load androguard only during scan
    try:
        from androguard.misc import AnalyzeAPK
    except Exception:
        AnalyzeAPK = None

    if not AnalyzeAPK:

        return [{
            "issue": "Androguard not installed",
            "severity": "Low",
            "evidence": "Environment"
        }]

    try:

        a, d, dx = AnalyzeAPK(path)

        print("[analyzer] APK parsed successfully")

        # =========================
        # PACKAGE INFO
        # =========================
        findings.append({

            "issue":
            f"Package Name: {a.get_package()}",

            "severity":
            "Low",

            "evidence":
            "APK Metadata"
        })

        findings.append({

            "issue":
            f"Target SDK Version: {a.get_target_sdk_version()}",

            "severity":
            "Low",

            "evidence":
            "AndroidManifest.xml"
        })

        # =========================
        # DEBUGGABLE
        # =========================
        try:

            if a.is_debuggable():

                findings.append({

                    "issue":
                    "App is debuggable",

                    "severity":
                    "High",

                    "evidence":
                    "AndroidManifest.xml"
                })

        except:
            pass

        # =========================
        # BACKUP ENABLED
        # =========================
        try:

            manifest = str(
                a.get_android_manifest_xml()
            )

            if 'allowBackup="true"' in manifest:

                findings.append({

                    "issue":
                    "Backup Enabled",

                    "severity":
                    "Medium",

                    "evidence":
                    "AndroidManifest.xml"
                })

        except:
            pass

        # =========================
        # CLEARTEXT TRAFFIC
        # =========================
        try:

            manifest = str(
                a.get_android_manifest_xml()
            )

            if 'usesCleartextTraffic="true"' in manifest:

                findings.append({

                    "issue":
                    "Cleartext Traffic Enabled",

                    "severity":
                    "High",

                    "evidence":
                    "AndroidManifest.xml"
                })

        except:
            pass

        # =========================
        # DANGEROUS PERMISSIONS
        # =========================
        try:

            permissions = a.get_permissions()

            for perm in permissions:

                findings.append({

                    "issue":
                    f"Permission Used: {perm}",

                    "severity":
                    "Low",

                    "evidence":
                    "AndroidManifest.xml"
                })

                if perm in DANGEROUS_PERMS:

                    findings.append({

                        "issue":
                        f"Dangerous permission detected: {perm}",

                        "severity":
                        "High",

                        "evidence":
                        "AndroidManifest.xml"
                    })

        except:
            pass

        # =========================
        # ACTIVITIES
        # =========================
        try:

            activities = a.get_activities()

            findings.append({

                "issue":
                f"Total Activities: {len(activities)}",

                "severity":
                "Low",

                "evidence":
                "AndroidManifest.xml"
            })

        except:
            pass

        # =========================
        # SERVICES
        # =========================
        try:

            services = a.get_services()

            findings.append({

                "issue":
                f"Total Services: {len(services)}",

                "severity":
                "Low",

                "evidence":
                "AndroidManifest.xml"
            })

        except:
            pass

        # =========================
        # RECEIVERS
        # =========================
        try:

            receivers = a.get_receivers()

            findings.append({

                "issue":
                f"Broadcast Receivers: {len(receivers)}",

                "severity":
                "Low",

                "evidence":
                "AndroidManifest.xml"
            })

        except:
            pass

        # =========================
        # FILE SCAN
        # =========================
        try:

            for fname in a.get_files():

                if fname.endswith((
                    ".xml",
                    ".json",
                    ".txt"
                )):

                    try:

                        content = a.get_file(fname)

                        if not content:
                            continue

                        text = content.decode(
                            "utf-8",
                            errors="ignore"
                        )

                        for issue_name, regex in PATTERNS.items():

                            if re.search(regex, text):

                                findings.append({

                                    "issue":
                                    issue_name,

                                    "severity":
                                    classify_severity(
                                        issue_name
                                    ),

                                    "evidence":
                                    fname
                                })

                    except:
                        continue

        except:
            pass

    except Exception as e:

        print("[analyzer ERROR]", repr(e))

        findings.append({

            "issue":
            "APK Parsing Failure",

            "severity":
            "Low",

            "evidence":
            str(e)
        })

    # =========================
    # REMOVE DUPLICATES
    # =========================
    unique = []

    seen = set()

    for item in findings:

        key = (
            item.get("issue"),
            item.get("evidence")
        )

        if key not in seen:

            seen.add(key)

            unique.append(item)

    print(f"[analyzer] returning {len(unique)} findings")

    return unique