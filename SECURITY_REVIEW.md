# Android AI-agent security review

Status: **source-based review; no Android runtime change and no device verification**.

## Observed in the checked-in source

- \`config/cordis.patch.yml\` sets \`defaultPreset: danger-full-access\` and the corresponding approval mode to \`never\`. An untrusted instruction reaching an enabled privileged tool could therefore have substantial consequences if the runtime honors those settings.
- \`android-app/AndroidManifest.xml\` permits cleartext traffic and Android backup, targets SDK 28, and declares broad storage, package installation, Shizuku and accessibility-related capabilities.
- **Declared** permissions and services do not prove that any user has granted them, that they can be exploited, or that this app is installed or running on a device.
- The app's own compatibility notes say that \`sandbox\` must remain registered so the runtime can start, but actual confinement may be unusable on Android. Blindly changing \`defaultPreset\` to \`read-only\` could therefore make sessions unusable. Do not interpret the labels as proof of working isolation.

## Priority actions before granting sensitive phone access

1. Review how tool calls are authorized in the actual installed version. Require explicit confirmation before shell commands, filesystem changes, package installations, Shizuku actions, accessibility input, settings changes, or browser-driven transactions. Untrusted web pages, prompts and project files must not be allowed to override user authorization.
2. Test a safe-by-default user-selectable profile on a disposable device or emulator using **synthetic data**. Confirm that it starts, handles read-only actions, blocks unauthorized writes, and fails closed without elevated services. Test each supported provider/preset separately.
3. Keep root/Shizuku, accessibility, overlay, storage and package-install permissions disabled until a particular feature genuinely requires them. Verify user-grant and revocation flows and provide visible reporting of every privileged action.
4. Investigate network security: \`usesCleartextTraffic="true"\`, local server/token handling, loopback access, external endpoints, and browser interactions. Prefer TLS and explicit host restrictions without breaking documented local-device services.
5. Review Android backup exposure, session exports, secret storage, clipboard and log redaction; test restore on clean devices.
6. Upgrade legacy Android API targeting and replace broad storage access where possible, but only with reproducible build, emulator/device integration and regression tests.
7. Review code signing, upstream third-party packages, distribution provenance and release integrity before installing on a personal/business device.

## Acceptance criteria for a future code-changing fix

- Default privileged execution is demonstrably consent-gated and not triggered by untrusted content.
- Nonprivileged startup succeeds on the supported Android versions.
- A sandbox-disabled/nonfunctional environment cannot silently fall back to unrestricted execution.
- Regression tests cover denied tool invocations, approval prompts, revocations, package installs, Shizuku and accessibility.
- No secrets, accounts, customer content, or permissions are modified during the validation run.
- Changes are reviewed in a separate PR and approved before any APK build, installation or release.

## What this PR does

Adds a no-dependency, read-only source inventory and a GitHub Actions report. The inventory **does not make the app safer by itself**, and must not be represented as an Aikido finding, an exploit or a security certification.

Do not merge permission/preset behavioral changes without device compatibility evidence.
