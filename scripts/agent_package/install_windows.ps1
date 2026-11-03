$ErrorActionPreference = "Stop"

$pythonVersionCommand = "import sys; print('.'.join(map(str, sys.version_info[:3])))"
function Get-PythonVersion($commandPath, $commandArgs) {
    try {
        $result = & $commandPath @commandArgs -c $pythonVersionCommand
    } catch {
        return $null
    }
    if ($LASTEXITCODE -ne 0) {
        return $null
    }
    return $result.Trim()
}

$pythonCommand = $null
$pythonArgs = @()
$pythonVersion = $null
$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    $candidateVersion = Get-PythonVersion $python.Source @()
    if ($candidateVersion) {
        try {
            if ([version]$candidateVersion -ge [version]"3.10") {
                $pythonCommand = $python.Source
                $pythonVersion = $candidateVersion
            }
        } catch {
            $pythonVersion = $null
        }
    }
}

if (-not $pythonCommand) {
    $pythonLauncher = Get-Command py -ErrorAction SilentlyContinue
    if ($pythonLauncher) {
        $candidateVersion = Get-PythonVersion $pythonLauncher.Source @("-3")
        if ($candidateVersion) {
            try {
                if ([version]$candidateVersion -ge [version]"3.10") {
                    $pythonCommand = $pythonLauncher.Source
                    $pythonArgs = @("-3")
                    $pythonVersion = $candidateVersion
                }
            } catch {
                $pythonVersion = $null
            }
        }
    }
}

if (-not $pythonCommand) {
    throw "Python 3.10 or newer was not found. Install Python and reopen PowerShell. If Python 3.10+ is installed, check 'python --version' or 'py -3 --version'."
}

$configPath = Join-Path $PSScriptRoot "config.json"
if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
    throw "config.json is missing. Extract the complete NetSentry ZIP again."
}
try {
    $config = Get-Content -Raw -Path $configPath | ConvertFrom-Json
    $siteId = [int]$config.site_id
    if ($siteId -lt 1) {
        throw "Website ID is invalid."
    }
} catch {
    throw "config.json is invalid. Extract a fresh package from NetSentry AI."
}

$installDir = Join-Path $env:LOCALAPPDATA ("NetSentry\site-" + $config.site_id)
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
try {
    Copy-Item -Path (Join-Path $PSScriptRoot "netsentry_agent.py"), (Join-Path $PSScriptRoot "generic_traffic_collector.py"), $configPath -Destination $installDir -Force
} catch {
    throw "Could not install the agent into $installDir. Check that you can write to your Windows user profile."
}
if (-not (Test-Path -LiteralPath (Join-Path $installDir "netsentry_agent.py") -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $installDir "generic_traffic_collector.py") -PathType Leaf)) {
    throw "The agent files are missing. Extract a fresh package and rerun the installer."
}

Write-Host "Python $pythonVersion found."
Write-Host "Installed the NetSentry Agent separately from your website at $installDir"
Write-Host "The collector key will be requested without echo and will not be saved by this installer."
Write-Host "Type the full path to your existing access log when prompted."
& $pythonCommand @pythonArgs (Join-Path $installDir "netsentry_agent.py")
if ($LASTEXITCODE -ne 0) {
    throw "The NetSentry Agent exited with an error. Use TROUBLESHOOTING.md to review the message and retry."
}
