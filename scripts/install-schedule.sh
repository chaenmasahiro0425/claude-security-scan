#!/usr/bin/env bash
# 毎週のスキャンを登録する。macOS は launchd（既定: 月曜 8:00）、Linux は crontab の行を表示する。
# 使い方: scripts/install-schedule.sh [曜日 0-6(日=0)] [時] [分]      解除: scripts/install-schedule.sh --remove
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="local.security-scan"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
PY="$(command -v python3)"
WEEKDAY="${1:-1}"; HOUR="${2:-8}"; MIN="${3:-0}"

if [ "$(uname -s)" != Darwin ]; then
  echo "Linux では次の1行を crontab -e に追加してください:"
  echo "$MIN $HOUR * * $WEEKDAY $PY $ROOT/scan.py >> $ROOT/reports/cron.log 2>&1"
  exit 0
fi

if [ "${1:-}" = "--remove" ]; then
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  rm -f "$PLIST"; echo "解除しました"; exit 0
fi

mkdir -p "$ROOT/reports" "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <!-- zsh 経由で ~/.zshenv の環境変数（CLIの認証情報など）を読ませる -->
    <string>/bin/zsh</string><string>-c</string>
    <string>exec "$PY" "$ROOT/scan.py" --notify</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict><key>Weekday</key><integer>$WEEKDAY</integer><key>Hour</key><integer>$HOUR</integer><key>Minute</key><integer>$MIN</integer></dict>
  <key>StandardOutPath</key><string>$ROOT/reports/launchd.log</string>
  <key>StandardErrorPath</key><string>$ROOT/reports/launchd.log</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>10</integer>
</dict>
</plist>
PL
plutil -lint "$PLIST" >/dev/null
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "登録しました: 毎週 曜日=$WEEKDAY $HOUR:$(printf %02d "$MIN")（$PLIST）"
echo "今すぐ1回: launchctl kickstart gui/$(id -u)/$LABEL"
