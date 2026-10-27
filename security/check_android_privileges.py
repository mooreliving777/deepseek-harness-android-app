#!/usr/bin/env python3
"""Read-only source inventory of privileged Android agent configuration.

Does not run or install an APK, execute tools on a device, or read secrets.
This is a *review inventory*, not a vulnerability/exploit detection engine.
"""
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ANDROID = "{http://schemas.android.com/apk/res/android}"


def android_attr(node, name):
    return node.get(ANDROID + name)


def main():
    config = (ROOT / "config" / "cordis.patch.yml").read_text(encoding="utf-8")
    root = ET.parse(ROOT / "android-app" / "AndroidManifest.xml").getroot()

    default_match = re.search(r"(?m)^    defaultPreset:\s*([a-z-]+)\s*$", config)
    privileged_block = re.search(
        r"(?m)^      danger-full-access:\s*\n((?:        [^\n]*\n)*)", config
    )
    if default_match is None or privileged_block is None:
        raise SystemExit("Cannot reliably locate permission configuration; manual review required.")
    approval_match = re.search(
        r"(?m)^        approval:\s*([a-z-]+)\s*$", privileged_block.group(1)
    )
    if approval_match is None:
        raise SystemExit("Cannot identify approval mode; manual review required.")

    application = root.find("application")
    sdk = root.find("uses-sdk")
    if application is None or sdk is None:
        raise SystemExit("Cannot find Android application or SDK declaration.")

    permissions = {
        android_attr(node, "name")
        for node in root.findall("uses-permission")
    }
    services = root.findall("application/service")
    accessibility_service = any(
        android_attr(s, "permission") == "android.permission.BIND_ACCESSIBILITY_SERVICE"
        for s in services
    )

    rows = [
        ("Default AI tool preset", default_match.group(1), "Review / confirm an explicit user opt-in for privileged actions"),
        ("Full-access approval setting", approval_match.group(1), "Review / verify per-action authorization"),
        ("Target Android SDK", android_attr(sdk, "targetSdkVersion") or "unspecified", "Review current OS hardening and compatibility"),
        ("Cleartext traffic allowed", android_attr(application, "usesCleartextTraffic") or "default", "Review transport security and endpoint allowlists"),
        ("Android backups allowed", android_attr(application, "allowBackup") or "default", "Review backup exposure of credentials and sessions"),
        ("All-files storage permission", str("android.permission.MANAGE_EXTERNAL_STORAGE" in permissions).lower(), "Justify breadth; prefer scoped storage where compatible"),
        ("App installation permission", str("android.permission.REQUEST_INSTALL_PACKAGES" in permissions).lower(), "Require clear consent for installations"),
        ("Shizuku integration", str("moe.shizuku.manager.permission.API_V23" in permissions).lower(), "Review capability boundaries and user grants"),
        ("Accessibility service", str(accessibility_service).lower(), "Review screen data access and approval for input automation"),
    ]

    print("# Android AI-agent permission inventory")
    print()
    print("Static evidence from repository sources only. No phone, installed APK, server, or account was inspected.")
    print()
    print("| Setting | Source value | What needs verification |")
    print("| --- | --- | --- |")
    for title, value, action in rows:
        print(f"| {title} | \`{value}\` | {action} |")
    print()
    if default_match.group(1) == "danger-full-access" and approval_match.group(1) == "never":
        print("**Priority:** The checked-in default is unrestricted agent access without approval. "
              "Do not assume read-only works on Android without a compatibility test; see SECURITY_REVIEW.md.")
    print()
    print("This inventory is advisory, not a penetration test and not proof that device permissions are granted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
