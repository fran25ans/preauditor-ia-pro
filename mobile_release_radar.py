#!/usr/bin/env python3
"""Mobile Release Radar: compare Android/iOS build artifacts before release."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import plistlib
import re
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree as ET


TOOL_NAME = "Mobile Release Radar"
TOOL_VERSION = "0.1.0"
ANDROID_EXTENSIONS = {".apk", ".aab"}
IOS_EXTENSIONS = {".ipa"}
TEXT_EXTENSIONS = {
    ".xml",
    ".json",
    ".txt",
    ".properties",
    ".plist",
    ".html",
    ".js",
    ".map",
    ".config",
    ".conf",
    ".pem",
}
MAX_TEXT_FILE_BYTES = 2_000_000
MAX_STRING_SCAN_FILES = 500
DANGEROUS_ANDROID_PERMISSIONS = {
    "android.permission.ACCEPT_HANDOVER",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BODY_SENSORS",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.GET_ACCOUNTS",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.USE_SIP",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
}
IOS_SENSITIVE_USAGE_KEYS = {
    "NSBluetoothAlwaysUsageDescription",
    "NSBluetoothPeripheralUsageDescription",
    "NSCalendarsUsageDescription",
    "NSCameraUsageDescription",
    "NSContactsUsageDescription",
    "NSFaceIDUsageDescription",
    "NSHealthShareUsageDescription",
    "NSHealthUpdateUsageDescription",
    "NSLocationAlwaysAndWhenInUseUsageDescription",
    "NSLocationAlwaysUsageDescription",
    "NSLocationWhenInUseUsageDescription",
    "NSMicrophoneUsageDescription",
    "NSMotionUsageDescription",
    "NSPhotoLibraryAddUsageDescription",
    "NSPhotoLibraryUsageDescription",
    "NSRemindersUsageDescription",
    "NSSpeechRecognitionUsageDescription",
    "NSUserTrackingUsageDescription",
}
SECRET_PATTERNS = [
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{16,})"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|es|dev|app|cloud|internal|local)\b", re.I)
NOISY_DOMAIN_PREFIXES = (
    "android.",
    "androidx.",
    "com.google.",
    "com.android.",
    "kotlin.",
    "kotlinx.",
    "java.",
    "javax.",
    "org.jetbrains.",
    "schemas.android.",
)
NOISY_HOSTS = {"www.w3.org", "schemas.android.com"}


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    evidence: str
    location: str
    recommendation: str
    standard: str


@dataclass
class MobileProfile:
    artifact: str
    platform: str
    sha256: str
    size_bytes: int
    generated_at: str
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    bundle_id: str = ""
    build_number: str = ""
    display_name: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    permissions: list[str] = field(default_factory=list)
    dangerous_permissions: list[str] = field(default_factory=list)
    exported_components: list[str] = field(default_factory=list)
    url_schemes: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def artifact_platform(path: Path, forced: str = "auto") -> str:
    if forced != "auto":
        return forced
    suffix = path.suffix.lower()
    if suffix in ANDROID_EXTENSIONS:
        return "android"
    if suffix in IOS_EXTENSIONS:
        return "ios"
    raise ValueError(f"No se reconoce el tipo de artefacto: {path}")


def mask_secret(value: str) -> str:
    clean = value.strip().strip("\"'")
    if len(clean) <= 10:
        return "***"
    return f"{clean[:4]}****{clean[-4:]}"


def add_finding(profile: MobileProfile, rule_id: str, title: str, severity: str, category: str, evidence: str, location: str, recommendation: str, standard: str) -> None:
    profile.findings.append(
        Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            category=category,
            evidence=evidence,
            location=location,
            recommendation=recommendation,
            standard=standard,
        )
    )


def safe_zip_texts(path: Path) -> tuple[list[tuple[str, str]], list[str]]:
    texts: list[tuple[str, str]] = []
    notes: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist()[:MAX_STRING_SCAN_FILES]:
                suffix = Path(info.filename).suffix.lower()
                if info.file_size > MAX_TEXT_FILE_BYTES:
                    continue
                if suffix not in TEXT_EXTENSIONS and "/" not in info.filename:
                    continue
                try:
                    raw = archive.read(info)
                except (KeyError, RuntimeError, zipfile.BadZipFile):
                    continue
                decoded = raw.decode("utf-8", errors="ignore")
                if decoded.strip():
                    texts.append((info.filename, decoded))
    except zipfile.BadZipFile as exc:
        notes.append(f"No se pudo abrir como ZIP: {exc}")
    return texts, notes


def collect_urls_and_domains(profile: MobileProfile, texts: list[tuple[str, str]]) -> None:
    urls: set[str] = set()
    domains: set[str] = set()
    for _, text in texts:
        for url in URL_RE.findall(text):
            normalized = url.rstrip(".,;)'\"")
            urls.add(normalized)
            host = re.sub(r"^https?://", "", normalized).split("/", 1)[0].split(":", 1)[0].lower()
            if "." in host and host not in NOISY_HOSTS and not host.startswith(NOISY_DOMAIN_PREFIXES):
                domains.add(host)
        for domain in DOMAIN_RE.findall(text):
            candidate = domain.lower()
            if candidate in NOISY_HOSTS or candidate.startswith(NOISY_DOMAIN_PREFIXES):
                continue
            domains.add(candidate)
    profile.urls = sorted(urls)
    profile.domains = sorted(domains)


def detect_generic_package_findings(profile: MobileProfile, texts: list[tuple[str, str]]) -> None:
    for filename, text in texts:
        for pattern in SECRET_PATTERNS:
            match = pattern.search(text)
            if match:
                evidence = match.group(0)
                if len(match.groups()) >= 2:
                    evidence = f"{match.group(1)}={mask_secret(match.group(2))}"
                else:
                    evidence = mask_secret(evidence)
                add_finding(
                    profile,
                    "MOB-001",
                    "Possible secret embedded in mobile artifact",
                    "Critical",
                    "Secrets",
                    evidence,
                    filename,
                    "Remove the secret from the mobile build and fetch sensitive values from a protected backend or runtime configuration.",
                    "OWASP MASVS-STORAGE / CWE-798",
                )
                break
        http_urls = [url.rstrip(".,;)'\"") for url in URL_RE.findall(text) if url.startswith("http://")]
        risky_http_urls = [url for url in http_urls if not any(noisy in url for noisy in ("w3.org", "schemas.android.com"))]
        if risky_http_urls:
            add_finding(
                profile,
                "MOB-002",
                "Cleartext HTTP endpoint found",
                "High",
                "Network",
                risky_http_urls[0],
                filename,
                "Use HTTPS endpoints and enforce transport security for production builds.",
                "OWASP MASVS-NETWORK",
            )
        if "addJavascriptInterface" in text:
            add_finding(
                profile,
                "AND-004",
                "WebView JavaScript bridge detected",
                "High",
                "Android WebView",
                "addJavascriptInterface",
                filename,
                "Restrict bridge exposure, validate trusted origins and avoid exposing sensitive native methods to untrusted content.",
                "OWASP MASVS-PLATFORM",
            )
        if re.search(r"TrustManager|HostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|checkServerTrusted", text):
            add_finding(
                profile,
                "MOB-003",
                "Potentially unsafe TLS trust customization",
                "High",
                "Network",
                "TrustManager/HostnameVerifier pattern",
                filename,
                "Validate whether certificate validation is weakened and enforce standard TLS validation or controlled certificate pinning.",
                "OWASP MASVS-NETWORK / CWE-295",
            )


def decode_android_manifest_with_apktool(path: Path) -> str:
    apktool = shutil.which("apktool")
    if not apktool:
        return ""
    with tempfile.TemporaryDirectory(prefix="mobile-radar-apktool-") as tmp:
        output_dir = Path(tmp) / "decoded"
        command = [apktool, "d", "-f", "-q", "-o", str(output_dir), str(path)]
        try:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)
        except (subprocess.SubprocessError, OSError):
            return ""
        manifest = output_dir / "AndroidManifest.xml"
        return manifest.read_text(encoding="utf-8", errors="replace") if manifest.exists() else ""


def xml_attr(element: ET.Element, local_name: str) -> str:
    for key, value in element.attrib.items():
        if key.endswith("}" + local_name) or key == local_name:
            return value
    return ""


def parse_android_manifest(profile: MobileProfile, manifest_text: str) -> None:
    if not manifest_text.strip() or not manifest_text.lstrip().startswith("<"):
        profile.notes.append("AndroidManifest.xml no se pudo decodificar como XML de texto. Instala apktool para mayor precisión.")
        return
    try:
        root = ET.fromstring(manifest_text)
    except ET.ParseError as exc:
        profile.notes.append(f"AndroidManifest.xml no parseable: {exc}")
        return
    profile.package_name = root.attrib.get("package", "")
    profile.version_name = xml_attr(root, "versionName")
    profile.version_code = xml_attr(root, "versionCode")
    for uses_permission in root.findall(".//uses-permission"):
        name = xml_attr(uses_permission, "name")
        if name:
            profile.permissions.append(name)
    profile.permissions = sorted(set(profile.permissions))
    profile.dangerous_permissions = sorted(set(profile.permissions) & DANGEROUS_ANDROID_PERMISSIONS)
    for uses_sdk in root.findall(".//uses-sdk"):
        profile.min_sdk = xml_attr(uses_sdk, "minSdkVersion") or profile.min_sdk
        profile.target_sdk = xml_attr(uses_sdk, "targetSdkVersion") or profile.target_sdk
    app = root.find("application")
    if app is not None:
        if xml_attr(app, "debuggable").lower() == "true":
            add_finding(
                profile,
                "AND-001",
                "Debuggable Android build",
                "Critical",
                "Android Manifest",
                "android:debuggable=true",
                "AndroidManifest.xml",
                "Disable debuggable for release builds.",
                "OWASP MASVS-RESILIENCE",
            )
        if xml_attr(app, "allowBackup").lower() == "true":
            add_finding(
                profile,
                "AND-002",
                "Android backup enabled",
                "Medium",
                "Android Manifest",
                "android:allowBackup=true",
                "AndroidManifest.xml",
                "Disable backup for sensitive applications or define strict backup rules.",
                "OWASP MASVS-STORAGE",
            )
        if xml_attr(app, "usesCleartextTraffic").lower() == "true":
            add_finding(
                profile,
                "AND-003",
                "Cleartext traffic explicitly allowed",
                "High",
                "Android Network",
                "android:usesCleartextTraffic=true",
                "AndroidManifest.xml",
                "Disallow cleartext traffic in release builds and enforce HTTPS.",
                "OWASP MASVS-NETWORK",
            )
        for component_type in ("activity", "activity-alias", "service", "receiver", "provider"):
            for component in app.findall(component_type):
                exported = xml_attr(component, "exported").lower()
                name = xml_attr(component, "name") or component_type
                permission = xml_attr(component, "permission")
                if exported == "true":
                    profile.exported_components.append(f"{component_type}:{name}")
                    severity = "High" if not permission else "Medium"
                    add_finding(
                        profile,
                        "AND-005",
                        "Exported Android component",
                        severity,
                        "Android Manifest",
                        f"{component_type} {name} exported=true",
                        "AndroidManifest.xml",
                        "Confirm the component is intentionally exported and protected by permissions, auth checks or strict input validation.",
                        "OWASP MASVS-PLATFORM / CWE-926",
                    )


def analyze_android(path: Path) -> MobileProfile:
    profile = MobileProfile(
        artifact=str(path),
        platform="android",
        sha256=sha256_file(path),
        size_bytes=path.stat().st_size,
        generated_at=utc_now(),
    )
    manifest_text = decode_android_manifest_with_apktool(path)
    texts, notes = safe_zip_texts(path)
    profile.notes.extend(notes)
    if not manifest_text:
        manifest_text = next((text for name, text in texts if name.endswith("AndroidManifest.xml")), "")
    parse_android_manifest(profile, manifest_text)
    collect_urls_and_domains(profile, texts + ([("AndroidManifest.xml", manifest_text)] if manifest_text else []))
    detect_generic_package_findings(profile, texts)
    profile.libraries = sorted({Path(name).name for name, _ in texts if name.endswith((".jar", ".aar", ".so"))})
    return profile


def plist_from_ipa(path: Path) -> tuple[dict, str, list[str]]:
    notes: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            candidates = [
                name
                for name in archive.namelist()
                if name.startswith("Payload/") and name.endswith(".app/Info.plist")
            ]
            if not candidates:
                return {}, "", ["No se encontró Payload/*.app/Info.plist en el IPA."]
            info_name = sorted(candidates, key=len)[0]
            return plistlib.loads(archive.read(info_name)), info_name, notes
    except (zipfile.BadZipFile, plistlib.InvalidFileException, KeyError) as exc:
        return {}, "", [f"No se pudo leer Info.plist: {exc}"]


def analyze_ios(path: Path) -> MobileProfile:
    profile = MobileProfile(
        artifact=str(path),
        platform="ios",
        sha256=sha256_file(path),
        size_bytes=path.stat().st_size,
        generated_at=utc_now(),
    )
    info, info_location, notes = plist_from_ipa(path)
    profile.notes.extend(notes)
    texts, zip_notes = safe_zip_texts(path)
    profile.notes.extend(zip_notes)
    if info:
        profile.bundle_id = str(info.get("CFBundleIdentifier", ""))
        profile.version_name = str(info.get("CFBundleShortVersionString", ""))
        profile.build_number = str(info.get("CFBundleVersion", ""))
        profile.display_name = str(info.get("CFBundleDisplayName") or info.get("CFBundleName") or "")
        schemes: set[str] = set()
        for url_type in info.get("CFBundleURLTypes", []) or []:
            for scheme in url_type.get("CFBundleURLSchemes", []) or []:
                schemes.add(str(scheme))
        profile.url_schemes = sorted(schemes)
        sensitive_keys = sorted(key for key in IOS_SENSITIVE_USAGE_KEYS if key in info)
        profile.permissions = sensitive_keys
        ats = info.get("NSAppTransportSecurity", {}) or {}
        if ats.get("NSAllowsArbitraryLoads") is True:
            add_finding(
                profile,
                "IOS-001",
                "App Transport Security allows arbitrary loads",
                "High",
                "iOS Network",
                "NSAllowsArbitraryLoads=true",
                info_location,
                "Avoid broad ATS exceptions and define narrowly scoped exceptions only when justified.",
                "OWASP MASVS-NETWORK",
            )
        if info.get("get-task-allow") is True:
            add_finding(
                profile,
                "IOS-002",
                "Debug entitlement enabled",
                "High",
                "iOS Entitlements",
                "get-task-allow=true",
                info_location,
                "Ensure production builds are signed without debug entitlements.",
                "OWASP MASVS-RESILIENCE",
            )
    collect_urls_and_domains(profile, texts)
    detect_generic_package_findings(profile, texts)
    profile.libraries = sorted(
        {
            Path(name).name
            for name, _ in texts
            if ".framework/" in name or ".app/Frameworks/" in name or name.endswith(".dylib")
        }
    )
    return profile


def analyze_artifact(path: Path, forced_platform: str = "auto") -> MobileProfile:
    if not path.exists() or not path.is_file():
        raise ValueError(f"Artefacto no encontrado: {path}")
    platform = artifact_platform(path, forced_platform)
    if platform == "android":
        return analyze_android(path)
    if platform == "ios":
        return analyze_ios(path)
    raise ValueError(f"Plataforma no soportada: {platform}")


def key_set(profile: MobileProfile, key: str) -> set[str]:
    return set(getattr(profile, key))


def compare_profiles(previous: MobileProfile | None, current: MobileProfile) -> dict:
    if not previous:
        return {
            "available": False,
            "summary": "No previous artifact provided.",
            "new_findings": len(current.findings),
            "fixed_findings": 0,
            "persistent_findings": 0,
            "added_permissions": current.permissions,
            "removed_permissions": [],
            "added_dangerous_permissions": current.dangerous_permissions,
            "removed_dangerous_permissions": [],
            "added_exported_components": current.exported_components,
            "removed_exported_components": [],
            "added_domains": current.domains,
            "removed_domains": [],
            "added_url_schemes": current.url_schemes,
            "removed_url_schemes": [],
            "added_libraries": current.libraries,
            "removed_libraries": [],
        }
    current_findings = {(f.rule_id, f.location, f.evidence) for f in current.findings}
    previous_findings = {(f.rule_id, f.location, f.evidence) for f in previous.findings}
    diff = {
        "available": True,
        "summary": "Compared with previous artifact.",
        "new_findings": len(current_findings - previous_findings),
        "fixed_findings": len(previous_findings - current_findings),
        "persistent_findings": len(current_findings & previous_findings),
    }
    for field_name in ("permissions", "dangerous_permissions", "exported_components", "domains", "url_schemes", "libraries"):
        added = sorted(key_set(current, field_name) - key_set(previous, field_name))
        removed = sorted(key_set(previous, field_name) - key_set(current, field_name))
        diff[f"added_{field_name}"] = added
        diff[f"removed_{field_name}"] = removed
    return diff


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    return {severity: sum(1 for finding in findings if finding.severity == severity) for severity in ("Critical", "High", "Medium", "Low")}


def release_score(profile: MobileProfile, comparison: dict) -> tuple[int, str, list[str]]:
    score = 100
    reasons: list[str] = []
    counts = severity_counts(profile.findings)
    penalties = {"Critical": 35, "High": 18, "Medium": 8, "Low": 3}
    for severity, count in counts.items():
        if count:
            score -= min(70, penalties[severity] * count)
            reasons.append(f"{count} {severity.lower()} finding(s)")
    has_previous = bool(comparison.get("available"))
    added_dangerous = comparison.get("added_dangerous_permissions", [])
    if has_previous and added_dangerous:
        score -= min(25, len(added_dangerous) * 8)
        reasons.append(f"{len(added_dangerous)} new dangerous permission(s)")
    added_components = comparison.get("added_exported_components", [])
    if has_previous and added_components:
        score -= min(25, len(added_components) * 10)
        reasons.append(f"{len(added_components)} new exported component(s)")
    if comparison.get("available") and comparison.get("new_findings", 0):
        score -= min(25, comparison["new_findings"] * 8)
        reasons.append(f"{comparison['new_findings']} new risk finding(s)")
    score = max(0, score)
    if counts["Critical"] or (comparison.get("available") and comparison.get("new_findings", 0) >= 3):
        decision = "blocked"
    elif counts["High"] or added_dangerous or added_components or comparison.get("new_findings", 0):
        decision = "needs_review"
    else:
        decision = "approved"
    return score, decision, reasons or ["No blocking risk indicators detected."]


def public_profile(profile: MobileProfile) -> dict:
    payload = asdict(profile)
    payload["findings"] = [asdict(finding) for finding in profile.findings]
    return payload


def result_payload(current: MobileProfile, previous: MobileProfile | None) -> dict:
    comparison = compare_profiles(previous, current)
    score, decision, reasons = release_score(current, comparison)
    return {
        "schema_version": "1.0",
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "generated_at": utc_now(),
        "release_score": score,
        "decision": decision,
        "decision_reasons": reasons,
        "current": public_profile(current),
        "previous": public_profile(previous) if previous else None,
        "comparison": comparison,
    }


def render_markdown(payload: dict) -> str:
    current = payload["current"]
    comparison = payload["comparison"]
    counts = severity_counts([Finding(**finding) for finding in current["findings"]])
    lines = [
        f"# {TOOL_NAME} Report",
        "",
        f"**Decision:** {payload['decision'].upper()}",
        f"**Release score:** {payload['release_score']}/100",
        f"**Platform:** {current['platform']}",
        f"**Artifact:** `{current['artifact']}`",
        f"**SHA256:** `{current['sha256']}`",
        f"**Generated at:** {payload['generated_at']}",
        "",
        "> This automated release check does not replace expert mobile security review. Findings and release decisions should be validated by the responsible team.",
        "",
        "## Executive Summary",
        "",
        f"- Critical findings: {counts['Critical']}",
        f"- High findings: {counts['High']}",
        f"- Medium findings: {counts['Medium']}",
        f"- Low findings: {counts['Low']}",
        f"- New findings vs previous: {comparison['new_findings']}",
        f"- Fixed findings vs previous: {comparison['fixed_findings']}",
        f"- Persistent findings vs previous: {comparison['persistent_findings']}",
        "",
        "## Release Delta",
        "",
        f"- Added permissions: {len(comparison.get('added_permissions', []))}",
        f"- Added dangerous permissions: {len(comparison.get('added_dangerous_permissions', []))}",
        f"- Added exported components: {len(comparison.get('added_exported_components', []))}",
        f"- Added domains: {len(comparison.get('added_domains', []))}",
        f"- Added URL schemes: {len(comparison.get('added_url_schemes', []))}",
        f"- Added libraries: {len(comparison.get('added_libraries', []))}",
        "",
    ]
    for label, key in (
        ("New dangerous permissions", "added_dangerous_permissions"),
        ("New exported components", "added_exported_components"),
        ("New domains", "added_domains"),
        ("New URL schemes", "added_url_schemes"),
        ("New libraries", "added_libraries"),
    ):
        values = comparison.get(key, [])
        if values:
            lines.extend([f"### {label}", ""])
            lines.extend(f"- `{value}`" for value in values[:50])
            lines.append("")
    lines.extend(["## Findings", ""])
    if current["findings"]:
        for finding in current["findings"]:
            lines.extend(
                [
                    f"### {finding['rule_id']} - {finding['title']}",
                    "",
                    f"- Severity: {finding['severity']}",
                    f"- Category: {finding['category']}",
                    f"- Location: `{finding['location']}`",
                    f"- Evidence: `{finding['evidence']}`",
                    f"- Recommendation: {finding['recommendation']}",
                    f"- Standard: {finding['standard']}",
                    "",
                ]
            )
    else:
        lines.append("No findings detected.")
        lines.append("")
    if current["notes"]:
        lines.extend(["## Analyzer Notes", ""])
        lines.extend(f"- {note}" for note in current["notes"])
        lines.append("")
    return "\n".join(lines)


def render_html(markdown: str, payload: dict) -> str:
    body_lines = []
    for line in markdown.splitlines():
        escaped = html.escape(line)
        if line.startswith("# "):
            body_lines.append(f"<h1>{escaped[2:]}</h1>")
        elif line.startswith("## "):
            body_lines.append(f"<h2>{escaped[3:]}</h2>")
        elif line.startswith("### "):
            body_lines.append(f"<h3>{escaped[4:]}</h3>")
        elif line.startswith("- "):
            body_lines.append(f"<li>{escaped[2:]}</li>")
        elif line.startswith("> "):
            body_lines.append(f"<blockquote>{escaped[2:]}</blockquote>")
        elif not line:
            body_lines.append("")
        else:
            body_lines.append(f"<p>{escaped}</p>")
    decision = payload["decision"]
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(TOOL_NAME)}</title>
  <style>
    body {{ margin:0; font-family:Arial, sans-serif; color:#172033; background:#eef3f8; }}
    main {{ max-width:1080px; margin:0 auto; padding:28px; }}
    h1,h2,h3 {{ color:#111827; }}
    h1 {{ font-size:32px; }}
    h2 {{ margin-top:28px; border-top:1px solid #d8dee8; padding-top:18px; }}
    p,li,blockquote {{ color:#4b5563; line-height:1.5; }}
    code {{ background:#eef2f7; padding:2px 5px; border-radius:4px; }}
    blockquote {{ border-left:4px solid #0f766e; margin:18px 0; padding:10px 14px; background:#f8fafc; }}
    .hero {{ background:white; border:1px solid #d8dee8; border-radius:8px; padding:18px; margin-bottom:18px; }}
    .decision {{ display:inline-block; border-radius:999px; padding:7px 12px; color:white; font-weight:700; background:#0f766e; }}
    .decision.blocked {{ background:#a31925; }}
    .decision.needs_review {{ background:#c2410c; }}
  </style>
</head>
<body>
  <main>
    <div class="hero">
      <span class="decision {html.escape(decision)}">{html.escape(decision.upper())}</span>
      <p><strong>Release score:</strong> {payload['release_score']}/100</p>
    </div>
    {''.join(body_lines)}
  </main>
</body>
</html>
"""


def write_outputs(payload: dict, out: Path | None, html_out: Path | None, json_out: Path | None) -> None:
    markdown = render_markdown(payload)
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown, encoding="utf-8")
    if html_out:
        html_out.parent.mkdir(parents=True, exist_ok=True)
        html_out.write_text(render_html(markdown, payload), encoding="utf-8")
    if json_out:
        json_out.parent.mkdir(parents=True, exist_ok=True)
        json_out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare Android APK/AAB and iOS IPA artifacts before release.")
    parser.add_argument("artifact", help="Current APK, AAB or IPA artifact.")
    parser.add_argument("--previous", help="Previous APK, AAB or IPA artifact to compare against.")
    parser.add_argument("--platform", choices=["auto", "android", "ios"], default="auto")
    parser.add_argument("--out", help="Markdown report output path.")
    parser.add_argument("--html", help="HTML report output path.")
    parser.add_argument("--json", help="JSON output path.")
    parser.add_argument("--fail-on", choices=["blocked", "needs_review", "never"], default="never")
    return parser.parse_args()


def exit_code_for(decision: str, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    if fail_on == "blocked":
        return 2 if decision == "blocked" else 0
    if fail_on == "needs_review":
        return 2 if decision in {"blocked", "needs_review"} else 0
    return 0


def main() -> int:
    args = parse_args()
    current = analyze_artifact(Path(args.artifact).expanduser().resolve(), args.platform)
    previous = analyze_artifact(Path(args.previous).expanduser().resolve(), args.platform) if args.previous else None
    payload = result_payload(current, previous)
    write_outputs(
        payload,
        Path(args.out).expanduser().resolve() if args.out else None,
        Path(args.html).expanduser().resolve() if args.html else None,
        Path(args.json).expanduser().resolve() if args.json else None,
    )
    print(f"{TOOL_NAME}: {payload['decision'].upper()} ({payload['release_score']}/100)")
    print(f"Platform: {current.platform}")
    print(f"Findings: {len(current.findings)}")
    print(f"New findings: {payload['comparison']['new_findings']}")
    print(f"Fixed findings: {payload['comparison']['fixed_findings']}")
    print(f"Persistent findings: {payload['comparison']['persistent_findings']}")
    if args.out:
        print(f"Report: {Path(args.out).expanduser().resolve()}")
    if args.html:
        print(f"HTML: {Path(args.html).expanduser().resolve()}")
    if args.json:
        print(f"JSON: {Path(args.json).expanduser().resolve()}")
    return exit_code_for(payload["decision"], args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
