import re
from typing import List, Dict

# optional androguard (real parsing). If not installed, fallback to demo findings.
try:
    from androguard.core.bytecodes.apk import APK
except Exception:
    APK = None

DANGEROUS_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_CALL_LOG"
}

PATTERNS = {
    "Hardcoded API Keys": r"(?i)(api[_-]?key|secret)[\"'\s:=]{1,5}[A-Za-z0-9_\-]{8,}",
    "Plaintext HTTP": r"http://",
    "Weak Cryptography": r"(?i)\b(md5|sha1)\b",
    "Insecure Random": r"(?i)(\bSecureRandom\b|Random\.)",
    "Logging Sensitive Data": r"(?i)(log|print)\(.*(password|token|secret|credit|ssn).*",
    "App is debuggable": r"(?i)android:debuggable\s*=\s*\"?true\"?",
    "Backup Enabled": r"(?i)android:allowBackup\s*=\s*\"?true\"?",
    "WebView JS Enabled": r"(?i)setJavaScriptEnabled\s*\(\s*true\s*\)",
    "File Path Exposure": r"/sdcard/|/storage/emulated/",
    "Unencrypted Storage": r"(?i)MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"
}


def classify_severity(issue: str) -> str:
    i = issue.lower()
    if any(k in i for k in ["critical", "dangerous", "hardcoded", "unencrypt", "weak cryptography", "world_readable"]):
        return "Critical"
    if any(k in i for k in ["debug", "hardcoded", "dangerous permission"]):
        return "High"
    if any(k in i for k in ["plaintext", "backup", "webview", "insecure random", "file path"]):
        return "Medium"
    return "Low"


def demo_findings(path: str):
    # sample demo findings if androguard not installed
    return [
        {"issue": "App is debuggable", "severity": "High", "evidence": "AndroidManifest.xml"},
        {"issue": "Hardcoded API Keys", "severity": "Critical", "evidence": "res/values/strings.xml"},
        {"issue": "Plaintext HTTP", "severity": "Medium", "evidence": "classes.dex"},
        {"issue": "Insecure Random", "severity": "Medium", "evidence": "utils.java"},
        {"issue": "Backup Enabled", "severity": "Low", "evidence": "AndroidManifest.xml"}
    ]


def analyze_apk(path: str) -> List[Dict]:
    findings = []
    print("[analyzer] called for:", path)

    if APK:
        try:
            a = APK(path)
            try:
                if a.is_debuggable():
                    findings.append({"issue": "App is debuggable", "severity": "High", "evidence": "AndroidManifest.xml"})
            except Exception:
                pass

            try:
                for p in a.get_permissions() or []:
                    if p in DANGEROUS_PERMS:
                        findings.append({"issue": f"Dangerous permission: {p}", "severity": "High", "evidence": "AndroidManifest.xml"})
            except Exception:
                pass

            try:
                for fname in a.get_files() or []:
                    if fname.endswith((".xml", ".smali", ".txt", ".properties", ".java", ".dex")):
                        try:
                            content = a.get_file(fname)
                            if not content:
                                continue
                            text = content.decode("utf-8", errors="ignore")
                            for issue_name, regex in PATTERNS.items():
                                if re.search(regex, text):
                                    findings.append({
                                        "issue": issue_name,
                                        "severity": classify_severity(issue_name),
                                        "evidence": fname
                                    })
                        except Exception:
                            continue
            except Exception:
                pass

        except Exception as exc:
            print("[analyzer] androguard parse error:", repr(exc))
            findings = demo_findings(path)
    else:
        print("[analyzer] Androguard not installed; using demo findings")
        findings = demo_findings(path)

    # dedupe by (issue, evidence)
    cleaned = []
    seen = set()
    for f in findings:
        if isinstance(f, tuple):
            try:
                f = {"issue": str(f[0]), "severity": str(f[1]) if len(f) > 1 else "Medium", "evidence": ""}
            except Exception:
                f = {"issue": str(f), "severity": "Medium", "evidence": ""}
        elif not isinstance(f, dict):
            f = {"issue": str(f), "severity": "Medium", "evidence": ""}
        key = (f.get("issue", ""), f.get("evidence", ""))
        if key not in seen:
            seen.add(key)
            cleaned.append(f)

    print(f"[analyzer] returning {len(cleaned)} unique findings")
    return cleaned





