#!/usr/bin/env bash
# 毎週のスキャンを登録する。macOS は launchd（既定: 月曜 8:00）、Linux は crontab に入れる1行を表示する。
# 使い方: scripts/install-schedule.sh [曜日 0-6(日=0)] [時] [分]      解除: scripts/install-schedule.sh --remove
set -euo pipefail
umask 077   # ログには指摘の一覧が入るので本人だけが読めるようにする
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="local.security-scan"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
PY="$(command -v python3)"

if [ "${1:-}" = "--remove" ]; then
  if [ "$(uname -s)" = Darwin ]; then
    launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
    rm -f "$PLIST"; echo "解除しました"
  else
    echo "crontab -e で security-scan の行を消してください"
  fi
  exit 0
fi

WEEKDAY="${1:-1}"; HOUR="${2:-8}"; MIN="${3:-0}"
for v in "$WEEKDAY" "$HOUR" "$MIN"; do [[ "$v" =~ ^[0-9]+$ ]] || { echo "曜日・時・分は数字で指定してください" >&2; exit 1; }; done
mkdir -p "$ROOT/reports"
chmod 700 "$ROOT/reports"

if [ "$(uname -s)" != Darwin ]; then
  q() { printf "'%s'" "${1//\'/\'\\\'\'}"; }
  echo "次の1行を crontab -e に追加してください:"
  echo "$MIN $HOUR * * $WEEKDAY $(q "$PY") $(q "$ROOT/scan.py") >> $(q "$ROOT/reports/cron.log") 2>&1"
  exit 0
fi

mkdir -p "$HOME/Library/LaunchAgents"
# plist は plistlib で書く（パスに & や $ が入っていても壊れない・シェルを通さない）
"$PY" - "$PLIST" "$LABEL" "$PY" "$ROOT" "$WEEKDAY" "$HOUR" "$MIN" <<'PYEOF'
import plistlib, sys
plist, label, py, root, wd, hh, mm = sys.argv[1:]
log = f"{root}/reports/launchd.log"
with open(plist, "wb") as f:
    plistlib.dump({
        "Label": label,
        # zsh 経由にすると ~/.zshenv の環境変数（CLIの鍵束パスワード等）を読める。引数は $1 $2 で渡しシェルに展開させない
        "ProgramArguments": ["/bin/zsh", "-c", 'exec "$1" "$2" --notify', "security-scan", py, f"{root}/scan.py"],
        "StartCalendarInterval": {"Weekday": int(wd), "Hour": int(hh), "Minute": int(mm)},
        "StandardOutPath": log, "StandardErrorPath": log,
        "LowPriorityIO": True, "Nice": 10,
    }, f)
PYEOF
touch "$ROOT/reports/launchd.log"; chmod 600 "$ROOT/reports/launchd.log"
launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
printf '登録しました: 毎週 曜日=%s %s:%02d（%s）\n' "$WEEKDAY" "$HOUR" "$MIN" "$PLIST"
echo "今すぐ1回: launchctl kickstart gui/$(id -u)/$LABEL"
