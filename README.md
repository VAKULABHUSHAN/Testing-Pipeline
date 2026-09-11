# Mobile Sentinel

Mobile Sentinel is a local-first automated Android security and QA auditing platform designed primarily for Flutter and Android mobile applications.

It performs deterministic, end-to-end assessments of authorized APKs across static security, attack surface exposure, secret detection, runtime stability, automated UI exploration, and accessibility.

---

## Key Features

- **Autonomous Application Exploration**: Dynamically discovers and traverses application screens using an accessibility/UI hierarchy state graph.
- **Safe Authentication Handling**: Safely handles onboarding wizards, detects login and registration flows, and supports user-supplied authorized test credentials with zero credential leakage.
- **Safety Policy Enforcement**: Automatically classifies interactive controls as `SAFE`, `CAUTION`, or `DESTRUCTIVE` (e.g., account deletion, logout, factory resets are discovered but excluded from execution by default).
- **Static Security Analysis**: Manifest configuration, exported components, intent filters, deep links, cleartext traffic, and permissions auditing.
- **High-Entropy Secret Detection**: Pattern matching and Shannon entropy scanner with automatic redaction of keys, tokens, and private material.
- **Flutter-Specific Audit**: Engine/framework verification, Dart AOT release flags, embedded asset inspection, and sensitive endpoint discovery.
- **Runtime & Stability Monitoring**: Real-time logcat inspection, ANR detection, crash deduplication, frame skip tracking, and memory monitoring.
- **UI/UX & Accessibility Auditing**: Automated detection of touch targets under 48dp, missing semantic accessibility labels, and viewport clipping.
- **Standardized Reporting**: Human-readable `report.txt` and machine-readable `report.json` organized per application, along with evidence screenshots and logs.

---

## Architecture Overview

```text
APK
 ↓
[1/10] APK Validation & Metadata Extraction
 ↓
[2/10] Android Device & Environment Detection
 ↓
[3/10] Package Installation
 ↓
[4/10] Application Launch & Foreground Verification
 ↓
[5/10] Static Security Analysis (Manifest, Secrets, Flutter, Network)
 ↓
[6/10] Authentication & Credential Inspection
 ↓
[7/10] Autonomous UI Exploration & State Graph Traversal
 ↓
[8/10] Runtime Monitoring (Crashes, ANRs, Performance, Logcat)
 ↓
[9/10] Deterministic Multi-Category Risk Scoring
 ↓
[10/10] Report & Evidence Generation (report.txt, report.json)
```

---

## Environment Requirements

- **Python**: 3.10+ (tested on Python 3.14)
- **Android SDK**: `platform-tools` (`adb`) and `build-tools` (`aapt`) available in PATH or under `ANDROID_HOME` / `ANDROID_SDK_ROOT`
- **Android Device / Emulator**: Connected and authorized (`adb devices`)
- **Java**: JRE/JDK 17+ (optional for extended static toolchains)

Verify your local environment at any time using:

```bash
sentinel doctor
```

---

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd testing_pipeline

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# or: .venv\Scripts\activate # Windows

# Install dependencies
pip install -r requirements.txt
pip install -e .
```

---

## Basic Usage

### 1. Autonomous Security & QA Test

To run the complete automated 10-step pipeline against an APK:

```bash
sentinel test "path/to/application.apk"
```

### 2. Testing with Authorized Credentials

When testing an application that requires authentication, provide an authorized test credentials YAML file:

```bash
sentinel test "path/to/application.apk" --auth-config "config/auth.yaml"
```

If no credentials configuration is provided, Mobile Sentinel will explore all accessible unauthenticated screens and transparently report authentication as `BLOCKED (No authorized test credentials supplied)`.

### 3. Authentication Configuration Template

Copy the example template to create your local config:

```bash
cp config/card-vault-auth.example.yaml config/card-vault-auth.yaml
```

Example configuration (`config/card-vault-auth.yaml`):

```yaml
auth:
  email: "authorized-test-account@example.com"
  password: "AUTHORIZED_PASSWORD"
```

> **Security Note**: Never commit files containing plaintext passwords or API tokens into version control. Local auth configs matching `*-auth.yaml` are excluded by `.gitignore`.

---

## Safety Model

Mobile Sentinel classifies UI elements into three safety tiers:

| Tier | Actions | Policy Behavior |
| :--- | :--- | :--- |
| **SAFE** | Navigation, tabs, menus, opening screens, scrolling, test field input, expanding sections, viewing details | Executed automatically |
| **CAUTION** | Save, edit, update, upload, export, share | Executed when safe and non-destructive |
| **DESTRUCTIVE** | Delete, clear data, factory reset, logout, account deletion, payment/checkout | **Excluded by default** (`DISCOVERED_NOT_EXECUTED`) |

---

## Report Output

All generated test artifacts are organized by application name under `reports/<app_name>/`:

```text
reports/
└── <app_name>/
    ├── report.txt       # Human-readable executive summary and findings
    ├── report.json      # Structured JSON data with full state graph and metrics
    ├── screenshots/     # Evidence screenshots captured per screen transition
    ├── logs/            # Complete logcat execution logs
    ├── metadata/        # Scan metadata and timing
    └── artifacts/       # Extracted APK artifacts
```

---

## Development & Testing

Run unit tests:

```bash
pytest -v
```

---

## License

Internal / Proprietary - Mobile Sentinel Security & QA Auditing Pipeline.
