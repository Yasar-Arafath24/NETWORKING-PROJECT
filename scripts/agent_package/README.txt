NETSENTRY AI — CUSTOMER WEBSITE AGENT
======================================

1. WELCOME TO NETSENTRY AI
--------------------------
This package helps you send authorized website access-log events to NetSentry AI.
Read this guide before starting. The agent reads an existing server-side log; it
does not change your website files.

YOUR PACKAGE
  Website:             @WEBSITE_NAME@
  Website ID:          @SITE_ID@
  Platform:            @PLATFORM@
  NetSentry API origin: @API_ORIGIN@
  Selected log format: @LOG_FORMAT@

IMPORTANT: @API_ORIGIN_NOTICE@

2. WHAT THIS PACKAGE DOES
-------------------------
The agent watches the access-log file you select. It starts at the end of that
file and sends new matching request records to NetSentry using your one-time
collector key. It does not create an access log, discover files automatically,
scan a website, or change website source files.

3. WHAT FILES ARE INCLUDED
--------------------------
  config.json                    Non-secret site ID, API origin, and log format.
  README.txt                     This quick-start guide.
  INSTALLATION_GUIDE.md           Detailed installation and access-log guidance.
  TROUBLESHOOTING.md              Common problems and next actions.
  netsentry_agent.py              Interactive launcher and secure key prompt.
  generic_traffic_collector.py    Reads, parses, and submits supported log lines.
  @INSTALLER_FILE@                Installer for this operating system.

Run the OS installer. Do not edit config.json or run the Python files manually
unless your administrator/support team asks you to.

4. SYSTEM REQUIREMENTS
----------------------
  - Windows or Linux.
  - Python 3.10 or newer.
  - Read permission for the website's real access-log file.
  - Network access to the API origin printed above.
  - The active, one-time collector key for Website ID @SITE_ID@.
No third-party Python packages are needed by this collector.

5. HOW THE CONNECTION WORKS
---------------------------
Your website server writes access records. The agent reads only the selected
file and sends matching records to the NetSentry API. NetSentry authenticates
each request and stores accepted events for your dashboard.

Agent running is not proof of a website connection. A heartbeat confirms only
that the agent contacted the backend. The dashboard shows Connected only after
a real access-log event is authenticated and stored.

6. WINDOWS INSTALLATION (POWERSHELL)
------------------------------------
1. In File Explorer, right-click the ZIP and choose "Extract All...".
2. Open the extracted folder. Click the address bar, type powershell, and press
   Enter. This opens PowerShell in that folder.
3. At the PowerShell prompt, type this command and press Enter:

       .\install_windows.ps1

   If script execution is blocked, follow "PowerShell script execution blocked"
   in INSTALLATION_GUIDE.md. Do not change the machine-wide policy.
4. The installer places the agent under your Windows user profile and starts it.
5. At "Full access-log path:", type or paste the complete existing log path and
   press Enter. This is a prompt, not a command; there is no file browser.
6. At "One-time NetSentry collector key (input hidden):", enter the key and
   press Enter. The key is not displayed while typing.
7. Leave the PowerShell window open. The collector prints "Watching site ..."
   when it starts.
8. Press Ctrl+C in that window to stop the collector safely.

7. LINUX INSTALLATION
---------------------
1. Extract the ZIP using your desktop archive tool or the `unzip` command.
2. Open a terminal in the extracted folder and check Python:

       python3 --version

3. Run the included installer:

       sh ./install_linux.sh

4. Type the full path to the readable access log when prompted, then enter the
   one-time key at the hidden prompt.
5. The installer creates a separate user data folder, restricts its permissions,
   and starts the agent. Leave the terminal open; press Ctrl+C to stop.

The script also supports a `PYTHON` environment variable if Python 3.10+ has a
different executable path. Full commands are in INSTALLATION_GUIDE.md.

8. HOW TO SELECT THE ACCESS-LOG FILE
------------------------------------
At "Full access-log path:", enter the complete path to the current file that
records requests for this website. Do not enter a folder, wildcard, or a path
copied from an example without checking it. Example paths are not guaranteed to
exist on your server.

The agent does not create logs or automatically find the correct one. Ask your
server administrator/hosting provider, or inspect the active IIS Logging,
Apache CustomLog, Nginx access_log, or application configuration. See
INSTALLATION_GUIDE.md for examples and the FastAPI JSONL requirements.

9. SUPPORTED ACCESS-LOG FORMATS
-------------------------------
This package is configured to use: @LOG_FORMAT@

The collector supports:
  - jsonl: one JSON object per line, including status_code, path, and method.
  - apache: common Apache access-log request/status/byte columns.
  - nginx: common Nginx access-log request/status/byte columns.
  - iis: IIS W3C records with a #Fields: header and required request columns.

The selected parser must match the real log layout. Standard FastAPI/Uvicorn
console logs are not automatically JSONL. See INSTALLATION_GUIDE.md for exact
fields and examples.

10. HOW TO ENTER THE ONE-TIME COLLECTOR TOKEN
---------------------------------------------
NetSentry AI generates the collector key when you register the website or
regenerate its key. Enter it only at the installer's hidden-key prompt. The
characters are not displayed. The key is passed to the collector while it is
running and is not written to this ZIP, config.json, or README.

11. HOW TO START AND STOP THE AGENT
-----------------------------------
The installer starts the agent after copying its files. Keep the terminal open.
You should see a "Watching site ..." message. To stop it, press Ctrl+C in that
terminal. There is no background-service installer in this package.

To start it again, follow "Start the agent again" in INSTALLATION_GUIDE.md. You
will be asked for the log path and key again; the key is not saved.

12. HOW TO GENERATE TEST WEBSITE TRAFFIC
----------------------------------------
Start the agent first. Then, from a browser that can reach the monitored
website, load a normal page served by that website. This creates a fresh request
that should be appended to the selected log. The collector does not send old
records that were already in the file when it started.

13. HOW TO VERIFY IN THE NETSENTRY DASHBOARD
--------------------------------------------
Open NetSentry AI, go to My Websites, and select Website ID @SITE_ID@. Look for
a new event and a recent event time. The dashboard may first show Installation
detected or Waiting for events after a heartbeat. It shows Connected only after
a real authenticated event has been accepted and stored.

14. TROUBLESHOOTING COMMON ERRORS
---------------------------------
  Python missing/not found: Install Python 3.10+ and check `python --version`,
  `py -3 --version` (Windows), or `python3 --version` (Linux).
  PowerShell blocks scripts: Use the process-only option in INSTALLATION_GUIDE.md
  if your organization permits it; otherwise contact IT.
  Log not found/access denied: Confirm the active full file path and read
  permissions. Do not use a folder, wildcard, or unverified example path.
  Unsupported format/no events: Match the selected parser to actual log lines.
  Token invalid: Regenerate the key for this Website ID and enter it again.
  API unavailable: Check the configured API origin and network. A 127.0.0.1
  origin only reaches the same computer.
  Heartbeat but no events: Generate a new request and confirm it is appended in
  the selected format. A heartbeat alone does not mean Connected.

See TROUBLESHOOTING.md for causes and step-by-step solutions.

15. SECURITY AND PRIVACY
------------------------
Keep the collector key private. Never commit it to GitHub, paste it into public
screenshots, or put it in website source code. If exposed, revoke/regenerate it.

The agent sends selected metadata from the chosen log, which may include request
paths, methods, status codes, IP addresses, and user-agent strings. Select only
logs you are authorized to read and share. Do not include passwords, cookies,
authorization headers, request bodies, or collector keys in access records.
The agent does not read website source files or modify the website.

16. HOW TO DISCONNECT THE WEBSITE
---------------------------------
Press Ctrl+C to stop the local agent. In the NetSentry dashboard, use Disconnect
to revoke the key. Revocation prevents future events using that key. To connect
again, generate a new key and enter it when starting the agent.

17. CUSTOMER SUPPORT
--------------------
Contact your NetSentry AI administrator or the support contact provided by your
organization. Include Website ID @SITE_ID@, operating system, selected format,
and the exact non-secret error message. Never send the collector key or a full
log containing private visitor information.
