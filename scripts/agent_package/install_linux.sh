#!/bin/sh
set -eu

python_bin="${PYTHON:-python3}"
if ! command -v "$python_bin" >/dev/null 2>&1; then
  echo "Python 3.10 or newer was not found as '$python_bin'." >&2
  echo "Install Python 3 or set PYTHON to its executable, then rerun this installer." >&2
  exit 1
fi

package_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python_version=$("$python_bin" -c 'import sys; print(".".join(map(str, sys.version_info[:3])))') || {
  echo "Python could not be started. Check the PYTHON setting and try again." >&2
  exit 1
}
if ! "$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "Python $python_version was found, but Python 3.10 or newer is required." >&2
  exit 1
fi

config_path="$package_dir/config.json"
if [ ! -f "$config_path" ]; then
  echo "config.json is missing. Extract the complete NetSentry ZIP again." >&2
  exit 2
fi
if ! site_id=$("$python_bin" -c 'import json,sys; data=json.load(open(sys.argv[1], encoding="utf-8")); site_id=int(data["site_id"]); assert site_id > 0; print(site_id)' "$config_path" 2>/dev/null); then
  echo "config.json is invalid. Download and extract a fresh package from NetSentry AI." >&2
  exit 2
fi

install_dir="${XDG_DATA_HOME:-$HOME/.local/share}/netsentry/site-$site_id"
if ! mkdir -p "$install_dir"; then
  echo "Could not create the agent folder at $install_dir. Check your user-folder permissions." >&2
  exit 1
fi
if ! chmod 700 "$install_dir"; then
  echo "Could not restrict permissions on $install_dir. Check filesystem permissions." >&2
  exit 1
fi
if ! cp "$package_dir/netsentry_agent.py" "$package_dir/generic_traffic_collector.py" "$config_path" "$install_dir/"; then
  echo "Could not copy the agent files to $install_dir. Extract the complete ZIP and check available disk space." >&2
  exit 1
fi
if ! chmod 600 "$install_dir/config.json"; then
  echo "Could not set permissions on the agent configuration. Check filesystem permissions." >&2
  exit 1
fi

echo "Python $python_version found."
echo "Installed the NetSentry Agent separately from your website at $install_dir"
echo "The collector key will be requested without echo and will not be saved."
echo "Type the full path to your existing access log when prompted."
cd "$install_dir"
exec "$python_bin" "$install_dir/netsentry_agent.py"
