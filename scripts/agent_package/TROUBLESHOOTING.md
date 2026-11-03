# NetSentry AI agent troubleshooting

Do not send your collector key, passwords, cookies, or private access-log
contents to support. Share the Website ID, operating system, log format, and
the exact non-secret error message instead.

## Python not installed

**Likely reason:** The installer requires Python 3.10 or newer.

**Next step:** Install Python 3.10+ using your organization's approved method.
On Windows, ensure the Python Launcher (`py`) or `python` command is available.
On Linux, install Python 3 and the `python3` command. Reopen PowerShell or the
terminal after installation, check the version, and rerun the ZIP installer.

## Python not found in PATH

**Likely reason:** Python is installed but its executable is not discoverable.

**Windows:** Try `py -3 --version`. The installer can use the `py -3` launcher.
If neither `python` nor `py` works, ask your administrator to repair the Python
installation/PATH or install Python for your account.

**Linux:** Check `python3 --version`. If it has a different executable name,
run the installer with the supported override, for example
`PYTHON=/usr/bin/python3.12 sh ./install_linux.sh`. Replace that example with
the actual path on your computer.

## PowerShell script execution blocked

**Likely reason:** The current PowerShell execution policy does not allow local
scripts to run.

**Next step:** If permitted by your organization, in the same PowerShell window
run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then run
`.\install_windows.ps1` again. This applies only to that PowerShell process.
Do not set a machine-wide policy. If organization policy blocks this, contact
your IT administrator; do not bypass managed controls.

## Access-log file not found

**Likely reason:** The path is not the active log path, the filename changes
daily (common for IIS), or the path was entered with a typo.

**Next step:** Check the active IIS Logging, Apache `CustomLog`, Nginx
`access_log`, or application log configuration. Enter the complete path to the
current existing file, not a folder or wildcard. Example paths are not
guaranteed to exist.

## Access denied

**Likely reason:** The Windows user or Linux account running the agent cannot
read the selected log.

**Next step:** Ask the server administrator to grant the least privilege needed
to read that specific log, or choose an approved readable log. Do not run as
Administrator/root unless your organization determines it is necessary. Do not
make a sensitive log world-readable.

## Unsupported log format or no matching records

**Likely reason:** The package's selected parser does not match the actual
server log layout. Common examples include custom Apache/Nginx formats,
ordinary Uvicorn console lines, and Python application logs that are not JSONL.

**Next step:** Check the selected format in `README.txt` and compare the log
with the supported format section in `INSTALLATION_GUIDE.md`. For JSONL, each
line must be a JSON object with `status_code`, `path`, and `method`. For IIS,
check that the file has a `#Fields:` header with required columns. Ask the
administrator to configure a supported format and download a new package if
the parser selection must change.

## Collector token invalid

**Likely reason:** The key was mistyped, belongs to another website, or was
revoked/rotated. A regenerated key invalidates the previous key immediately.

**Next step:** In the dashboard, verify the website ID and generate a new
collector key. Stop the old agent, start it again, and enter the new key at the
hidden prompt. Never send the key to support.

## API server unavailable

**Likely reason:** The API is stopped/unreachable, the computer has no network
route to it, a firewall/proxy blocks the connection, or the package contains a
development-only `127.0.0.1` origin.

**Next step:** Confirm the API origin in `README.txt` and `config.json`. A
loopback address works only when the API is running on the same computer as
the agent. For customer servers, ask the NetSentry administrator to configure
the deployed public HTTPS API origin and download a replacement package.
Confirm outbound network access to that API with your network administrator.
Do not edit the package to send credentials to an unapproved destination.

## Agent heartbeat missing

**Likely reason:** The agent has not started, cannot reach the API, or the key
is invalid/revoked. A heartbeat is sent periodically while the collector is
running; it is not an event.

**Next step:** Keep the terminal open and check for the `Watching ...` message.
Review any heartbeat/network error shown in that terminal. Confirm API
reachability and the key. A heartbeat alone does not make the website
Connected.

## Events received remains zero

**Likely reason:** No new request was written after the agent started, the
selected file is not the site's active log, the selected parser is wrong, or
the event was rejected due to credentials/network errors.

**Next step:**

1. Leave the agent running.
2. Visit a normal page on the monitored website after agent startup.
3. Confirm that this request appears as a new line in the selected log.
4. Confirm the line matches the package's selected format.
5. Check the terminal for token or delivery errors and check that the API origin
   is reachable.
6. Confirm the key is active and belongs to the displayed Website ID.

The agent starts reading at the end of an existing log and does not send its
older records.

## Dashboard says Installation detected, Waiting for events, or Disconnected

**Likely reason:** Installation detected usually means the backend received an
agent heartbeat but has not stored a real access-log event. Waiting for events
means no qualifying event has been recorded. Disconnected can mean the agent
stopped or its heartbeat became stale.

**Next step:** Keep the agent terminal open, then generate a fresh normal
website request. Confirm it is appended to the selected file and that the
parser recognizes its format. Check the terminal and verify the API address
and active key. The dashboard changes to Connected only after an authenticated
event is accepted and stored.

## Agent stopped or needs restarting

**Likely reason:** The terminal was closed, Ctrl+C was pressed, or the process
exited due to an error. This package does not install a Windows service or
systemd service.

**Next step:** Run the launcher again using the start command in
`INSTALLATION_GUIDE.md`, or rerun the installer. The launcher will request the
log path and key again. Keep its terminal open.

## Still need help?

Contact the NetSentry AI administrator or your organization's support contact.
Provide the Website ID, operating system, selected parser, and exact
non-secret error. Do not attach the ZIP if it contains site details unless
your support process permits it; never send the collector key or private log
records.
