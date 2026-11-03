# NetSentry AI customer agent installation

This guide covers the Windows and Linux ZIP installers and the access-log
formats supported by the collector included in this package.

## Before you begin

You need:

- The ZIP downloaded from your NetSentry AI account.
- Python 3.10 or newer.
- The one-time collector key displayed at website registration or key rotation.
- Permission to read the website's real access-log file.
- Network access from the computer running the agent to the API origin in
  `config.json`.

The ZIP is site-specific. Check `README.txt` for its website ID, selected log
format, and API origin. Do not edit `config.json`.

### Check the API origin

The API origin is where the collector sends events. It is not the website URL
or the NetSentry dashboard URL. If `config.json` shows
`http://127.0.0.1:8000`, the package is configured for local development and
only works on the same computer as that API server. `127.0.0.1` always means
"this computer". A customer server on another computer cannot use a developer's
loopback address.

For a remote customer installation, ask the NetSentry administrator to set the
canonical public API origin to the deployed HTTPS address and download a fresh
package. Do not edit the API origin yourself or enter an arbitrary destination.

## Windows installation (PowerShell)

The installer places the agent in your user profile under
`%LOCALAPPDATA%\NetSentry\site-<Website-ID>`. It does not need administrator
privileges and does not change website files.

1. In File Explorer, locate the downloaded `netsentry-<id>-windows.zip`.
2. Right-click it, choose **Extract All...**, choose a folder you can access,
   and select **Extract**.
3. Open the extracted folder. Click the File Explorer address bar, type
   `powershell`, and press Enter. A PowerShell window opens in that folder.
4. Check Python if needed by typing this at the PowerShell prompt:

       python --version

   If `python` is unavailable, try:

       py -3 --version

   Use Python 3.10 or newer. The installer accepts `python` or the Windows
   `py -3` launcher.
5. Run the installer by typing this PowerShell command:

       .\install_windows.ps1

   The installer copies only the agent, collector, and non-secret config into
   your user data folder, then starts the agent.
6. At the terminal prompt `Full access-log path:`, type or paste the complete
   path to the existing log file and press Enter. This is a prompt, not a
   command. The launcher does not open a file-selection dialog.
7. At `One-time NetSentry collector key (input hidden):`, paste/type the key
   and press Enter. The characters are not displayed as you type.
8. Keep the PowerShell window open. The agent prints a `Watching ...` message
   when it begins monitoring. Generate a new request after it starts.
9. To stop, focus that PowerShell window and press **Ctrl+C**. This sends a
   normal stop signal; the collector attempts to report that it stopped.

### If PowerShell says scripts are blocked

Use a process-scoped setting only for the current PowerShell window, if your
organization's policy permits it. At the PowerShell prompt, run:

    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\install_windows.ps1

This setting ends when that PowerShell window closes; it does not change the
machine-wide policy. If your organization manages or prohibits script
execution, do not bypass that policy—ask your IT administrator to approve or
run the installer.

### Start the agent again

After installation, run the launcher from PowerShell using the same account.
Replace `7` below with the Website ID shown in your package:

    python "$env:LOCALAPPDATA\NetSentry\site-7\netsentry_agent.py"

If only the `py` launcher is available:

    py -3 "$env:LOCALAPPDATA\NetSentry\site-7\netsentry_agent.py"

The agent asks for the log path and key again. The key is intentionally not
stored for unattended restarts.

## Linux installation

The installer creates
`$XDG_DATA_HOME/netsentry/site-<Website-ID>` if `XDG_DATA_HOME` is set;
otherwise it uses `~/.local/share/netsentry/site-<Website-ID>`. It sets the
directory permission to owner-only (`700`) and the copied `config.json`
permission to owner read/write (`600`). It does not require `sudo` or modify
website files.

1. Extract the ZIP using your desktop archive tool or the `unzip` command:

       unzip netsentry-<id>-linux.zip -d netsentry-agent

   Replace `<id>` with the number in your downloaded ZIP filename.
2. Open a terminal in the extracted `netsentry-agent` folder. In a desktop
   file manager, use **Open in Terminal** if available, or navigate to the
   folder with `cd`.
3. Check Python:

       python3 --version

4. Run the included installer from the extracted folder:

       sh ./install_linux.sh

   The script checks for Python, copies the agent files into your user data
   directory, applies the permissions described above, and starts the agent.
   It does not require the script's executable bit because it is run through
   `sh`.
5. At `Full access-log path:`, type or paste the complete path to the existing
   readable access log and press Enter.
6. At the hidden collector-key prompt, type or paste the one-time key and
   press Enter. The input will not be displayed.
7. Keep the terminal open. Confirm the `Watching ...` message and generate a
   new request after the agent starts.
8. Stop safely with **Ctrl+C** in that terminal.

If your Python 3 executable is not named `python3`, you can select it for the
installer using the supported `PYTHON` environment variable. For example:

    PYTHON=/usr/bin/python3.12 sh ./install_linux.sh

Use the actual path to Python 3.10 or newer on your system.

### Start the agent again

Replace `7` with the Website ID:

    python3 "$HOME/.local/share/netsentry/site-7/netsentry_agent.py"

If you installed with a custom `XDG_DATA_HOME`, use that directory instead.
Enter the log path and collector key again when prompted.

## Find the correct access log

The agent does not discover, create, or configure logs. It asks for a full path
and reads only that existing file. Paths below are examples, not guarantees:
hosting provider, installation method, virtual host, container, permissions,
or server configuration may change them. Confirm the active log path with your
server configuration or hosting provider.

| Environment | How to identify the log |
|---|---|
| Windows IIS | In IIS Manager, open the site's **Logging** settings and find the log directory and site ID. A common pattern is `%SystemDrive%\inetpub\logs\LogFiles\W3SVC<site-id>\u_exYYMMDD.log`. Choose the current actual `.log` file, not a wildcard or folder. IIS W3C files usually include a `#Fields:` header; the collector uses that header to map columns. |
| Apache | Check the active virtual host's `CustomLog` directive and the Apache service configuration. Examples on Linux include `/var/log/apache2/access.log` and `/var/log/httpd/access_log`; Windows bundles may use a `logs\access.log` under the Apache installation. Select the file receiving requests for the monitored site. |
| Nginx | Check the active server block's `access_log` directive, including any inherited configuration. `/var/log/nginx/access.log` is a common Linux example but may not be the site's actual log. |
| Python / FastAPI | Standard application logs and Uvicorn's ordinary console access lines are not automatically JSONL access logs. Configure application middleware or a reverse proxy to append one JSON object per request to a file, then select that file. See the example below. |
| Other Python applications | Configure the server/application to write the same one-JSON-object-per-line format shown below. The collector does not convert arbitrary Python log messages into request records. |

### JSONL format for FastAPI and other applications

JSONL means one valid JSON object on each line. Include `status_code`, `path`,
and `method`; these are the core request fields. `source_ip`, `user_agent`,
`duration_ms`, `response_bytes`, and `request_timestamp` are optional. The
collector also recognizes documented aliases in its parser, but use these
canonical names for new logs.

Example line (the file itself should contain JSON, not Markdown):

```json
{"request_timestamp":"2026-11-03T10:15:00Z","method":"GET","path":"/","status_code":200,"duration_ms":18.4,"response_bytes":2048,"source_ip":"192.0.2.10","user_agent":"Example Browser"}
```

The `source_ip` above is documentation-only example data. Do not copy it as a
real visitor address. Do not include passwords, cookies, authorization headers,
request bodies, or the NetSentry collector key in access records.

FastAPI's ordinary application logs and Uvicorn's standard console access lines
are not the JSONL format above. If the application does not already write
compatible records, an authorized developer can add server-side middleware such
as the following. This is example application code, not part of the NetSentry
agent. Test and deploy it using your normal application change process:

```python
import json
import os
import time
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware


class NetSentryAccessLog(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        started = time.perf_counter()
        response = await call_next(request)
        record = {
            "request_timestamp": datetime.now(timezone.utc).isoformat(),
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "response_bytes": int(response.headers.get("content-length", 0) or 0),
            "source_ip": request.client.host if request.client else "",
            "user_agent": request.headers.get("user-agent", ""),
        }
        with open(os.environ["NETSENTRY_ACCESS_LOG"], "a", encoding="utf-8") as log:
            log.write(json.dumps(record) + "\n")
        return response


app.add_middleware(NetSentryAccessLog)
```

Set `NETSENTRY_ACCESS_LOG` in the website application's server environment to
the desired log-file path before starting the application. This application
middleware creates/appends the file when it handles requests; the NetSentry
agent itself does not create it or install the middleware. Ensure the parent
directory exists, the application account can write there, and the collector
account can read the file. A file permission/configuration error in application
middleware may affect requests, so test it safely before production use.

Other Python applications can write the same JSON object fields from their
request handler/middleware. Keep this log limited to the metadata required;
never log request bodies, cookies, authorization headers, or secrets.

## Supported log formats

The package selects one parser from `config.json`; the launcher uses that
format automatically. The collector supports:

- **JSONL**: one JSON object per line, as described above.
- **Apache**: common access-log records beginning with client IP, followed by
  the quoted request, status, and response-byte count. An optional duration
  immediately after the byte count is interpreted as microseconds.
- **Nginx**: common access-log records with client IP, quoted request, status,
  and response-byte count. An optional duration immediately after the byte
  count is interpreted as seconds.
- **IIS W3C**: records with a `#Fields:` header containing the required
  columns, including `c-ip`, `cs-uri-stem`, `cs-method`, and `sc-status`.

Different server log formats may look similar but have different columns or
ordering. A parser that does not recognize a line will not produce an event.
Ask the NetSentry administrator to select a supported format or configure a
compatible access-log format. Do not rename a log format to make it appear
supported.

## Generate traffic and verify

1. Start the agent and leave its terminal open.
2. From a browser on any machine that can reach the monitored website, load a
   normal page once. Use a URL served by the site whose log you selected.
3. Confirm that the request has been appended to the selected log. The collector
   starts at the end of the file, so old records are not sent.
4. In the NetSentry dashboard, open **My Websites** and select the website.
   Look for a new event and a recent event time.
5. A heartbeat may first show **Installation detected** or **Waiting for
   events**. A heartbeat proves only that the agent contacted the backend; it
   does not verify website traffic.
6. The site becomes **Connected** only after a real matching log record is sent
   with the correct key and successfully stored by the backend.

## Token security

NetSentry generates the one-time collector key and shows it when you register
the website or regenerate its key. The agent prompts for the key without
echoing it. It is passed to the collector process while running and is not
written into the ZIP, `config.json`, or README. Enter it again after restarting.

Never put the key in GitHub, a website source file, command-line argument,
screenshot, support ticket, or shared chat. If it may have been exposed, revoke
or regenerate it in the dashboard. The old key stops working immediately.

The collector sends selected metadata from the chosen access log to the API
origin in `config.json`. It does not scan the website, read website source code,
or modify website files. Select only logs you are authorized to access and
share; logs may contain personal data such as IP addresses or user-agent text.

## Disconnect

- Stop the local agent with **Ctrl+C**.
- In the dashboard, use **Disconnect** to revoke the collector key. Revocation
  stops future events authenticated with that key.
- To reconnect, generate a replacement key and enter it when starting the
  agent.

For help, contact the NetSentry AI administrator or the support contact supplied
by your organization. Share the Website ID and exact error text, but never the
collector key or private log contents.
