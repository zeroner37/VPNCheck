$ErrorActionPreference = "Stop"

python -m pip install --upgrade pyinstaller
python -m PyInstaller `
  --noconfirm `
  --clean `
  --onefile `
  --windowed `
  --name VPNCheck `
  vpncheck.py

Write-Host "Built: dist\VPNCheck.exe"
