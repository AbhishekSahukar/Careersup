@echo off
cd /d %~dp0
if not exist backend\target\release\jobpilot.exe (
  echo Building JobPilot backend - first run takes a few minutes...
  pushd backend && cargo build --release && popd
)
start "" http://localhost:3100
backend\target\release\jobpilot.exe
pause
