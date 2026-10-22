<#
.SYNOPSIS
    Start the NetSentry AI backend and frontend for local development.

.DESCRIPTION
    Launches the FastAPI backend (uvicorn on port 8000) and the Vite
    frontend (port 5173), each in its own PowerShell window, so the
    "Unable to fetch" error (which happens when the backend is not
    running) cannot occur as long as both windows stay open.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\dev.ps1
#>

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $ProjectRoot "venv\Scripts\python.exe"
$Python = if (Test-Path $VenvPython) { $VenvPython } else { "python" }
$FrontendDir = Join-Path $ProjectRoot "frontend"

Write-Host "Starting NetSentry AI backend (uvicorn) ..."
Start-Process -FilePath "powershell" -ArgumentList @(
    "-NoExit",
    "-Command",
    "Set-Location '$ProjectRoot'; Write-Host 'NetSentry backend'; & '$Python' -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload"
)

Write-Host "Starting NetSentry AI frontend (Vite) ..."
Start-Process -FilePath "powershell" -ArgumentList @(
    "-NoExit",
    "-Command",
    "Set-Location '$FrontendDir'; Write-Host 'NetSentry frontend'; npm run dev"
)

Write-Host ""
Write-Host "Backend API docs : http://127.0.0.1:8000/docs"
Write-Host "Frontend app     : http://localhost:5173"
Write-Host ""
Write-Host "Close the two spawned windows to stop the servers."
