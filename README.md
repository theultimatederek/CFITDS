# CFITDS — Cryptographic File Integrity & Tamper Detection System

**Desktop file-integrity monitoring with SHA-256, HMAC-SHA-256, and security audit logs.**

CFITDS is a Python/Tkinter desktop application developed for a B.Tech Cryptography and Network Security project. It helps identify unexpected modifications and missing files by comparing current file contents against a previously trusted cryptographic baseline.

## Real-world problem

Sensitive documents—such as university examination papers, student records, financial statements, and configuration files—can be changed without altering their names. CFITDS detects changes to files that an administrator has registered for monitoring.

## Features

- Native desktop interface; no localhost or browser required
- Register files from their existing locations
- SHA-256 fingerprints and keyed HMAC-SHA-256 integrity checks
- Automatic integrity checks approximately every 3 seconds
- Detects modified and missing files
- Security alerts and SQLite audit history
- Manual verification and authorized baseline updates

## Architecture

```text
Trusted File → SHA-256 + HMAC-SHA-256 → SQLite Baseline
                                            ↓
Existing File → Periodic Scanner → Recompute & Compare
                                            ↓
                              SECURE / TAMPERED / MISSING
                                            ↓
                                 GUI Alert + Audit Log
```

## Technology

Python 3.10+, Tkinter, `hashlib`, `hmac`, `sqlite3`, and threading. The desktop application uses Python standard-library modules.

## Getting started (Windows)

1. Install Python 3.10 or newer.
2. Clone this repository:

   ```cmd
   git clone https://github.com/YOUR_USERNAME/cryptographic-file-integrity-monitor.git
   cd cryptographic-file-integrity-monitor
   ```

3. Double-click `run_desktop_windows.bat`, or run:

   ```cmd
   python desktop_app.py
   ```

4. Click **Protect File**, select a trusted file, and inspect its status.

## Demonstration

1. Create a sample `Question_Paper.txt` and register it through **Protect File**.
2. Observe its **SECURE** status.
3. Edit and save the file in Notepad.
4. Wait for the next scan; the application should flag **TAMPERED**.
5. Inspect the trusted/current fingerprints and audit history.
6. After verifying an authorized change, use **Update Baseline** to approve the new contents.

## Security considerations and limitations

- CFITDS **detects** file changes; it does not prevent edits or identify who made them.
- Monitoring runs only while the desktop application is running.
- The trusted baseline, local HMAC key, and audit database must be protected from attackers with local filesystem access. This prototype does not provide hardened key storage or tamper-proof audit logging.
- Register only files whose initial contents are already trusted. Do not approve a new baseline without verifying the change.
- This repository is an educational prototype, not a replacement for enterprise endpoint monitoring.

## Privacy

Do not commit real examination papers, private records, generated cryptographic keys, or runtime databases. The `.gitignore` excludes local runtime state.

## Project context

B.Tech — Cryptography and Network Security | Academic cybersecurity project.
