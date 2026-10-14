"""--demo 用の見本データ。実在しない会社・アカウント・リポジトリだけを使う。"""
from __future__ import annotations

from .common import Result

NEW_KEYS = {"launch|/Library/LaunchDaemons/com.example.helper.plist", "leak|demo|stripe", "gh-2fa|example-inc"}


def result() -> Result:
    r = Result()
    a = r.add
    a("mac", "high", "常駐プログラム: com.example.helper", "/Library/LaunchDaemons/com.example.helper.plist",
      "root権限で動く常駐なのに、起動するプログラムがユーザー権限で書き換えられる場所にある\n起動: ~/.config/example/helper（引数は記録しない）",
      "心当たりがなければ launchctl bootout で止めてから plist を隔離する", key="launch|/Library/LaunchDaemons/com.example.helper.plist")
    a("mac", "high", "ファイアウォールがオフ", "このMac", "Firewall is disabled. (State = 0)", "システム設定 → ネットワーク → ファイアウォール をオンにする")
    a("mac", "low", "外部から接続を受け付けるポート 3000", "tcp/3000", "プロセス: node", "開発サーバーは 127.0.0.1 にバインドする")
    a("repos", "critical", "コミット履歴に秘密情報らしき文字列: stripe-access-token", "~/dev/shop-demo  (example-inc/shop-demo・公開)",
      "2箇所（値は伏せ字）\nsrc/pay.ts:12 (3f2a91c)\n.env.local:4 (8bd0e17)",
      "①そのキーを発行元で無効化・再発行 ②偽値なら .gitleaksignore に登録 ③公開リポなら履歴からの除去も検討", key="leak|demo|stripe")
    a("repos", "high", ".env ファイルがgitに登録されている", "~/dev/landing  (example-inc/landing)", ".env", "git rm --cached で追跡を外し .gitignore に追加")
    a("repos", "high", "依存パッケージに既知の脆弱性", "~/dev/admin-panel  (example-inc/admin-panel)",
      "23件（critical:2 / high:9 / medium:12）\nnext@14.1.0: GHSA-xxxx（見本）", "npm audit fix 等で更新し、動作確認してからPR")
    a("github", "high", "組織で2段階認証が必須になっていない", "example-inc", "", "Settings → Authentication security で必須化", key="gh-2fa|example-inc")
    a("github", "high", "2段階認証を設定していないメンバー", "example-inc / taro-sample", "", "本人に2FA設定を依頼する")
    a("web", "critical", "公開してはいけないファイルが見える: /.env", "lp.example.com", "https://lp.example.com/.env",
      "デプロイ対象から除外し、中のキーをすぐローテーション")
    a("web", "low", "セキュリティヘッダーが不足", "www.example.com", "不足: Content-Security-Policy", "vercel.json の headers に追加")
    a("aws", "critical", "ルートユーザーにMFAがない", "prod (000000000000)", "", "ルートでログインしMFAを登録")
    a("aws", "high", "インターネット全体に開いた管理/DBポート", "prod (000000000000) / ap-northeast-1 / sg-0example", "22(SSH)",
      "送信元を絞るか SSM Session Manager に切り替える")
    a("gmail", "high", "全メールの自動転送がオン", "you@example.com", "転送先: unknown@example.net", "覚えがなければ即オフにしてパスワード変更")
    a("gmail", "info", "このアカウントから送信できる別アドレス（Send As）", "you@example.com", "info@example.com", "")
    for m, item in [("mac", "FileVault"), ("mac", "Gatekeeper"), ("github", "example-inc Dependabot"), ("aws", "prod (000000000000)"),
                    ("gmail", "you@example.com")]:
        r.cov(m, item, "ok")
    r.cov("gmail", "Workspace管理 (example.com)", "skip", "Admin APIはドメイン全体の委任が必要")
    return r


def previous() -> list[dict]:
    """前回分の見本。NEW_KEYS 以外は前回もあった扱いにし、1件を「解消」に見せる。"""
    cur = [f.to_dict() for f in result().findings if f.key not in NEW_KEYS]
    cur.append({"module": "web", "severity": "high", "title": "SSL証明書の期限が近い", "target": "old.example.com",
                "detail": "", "fix": "", "key": "demo-resolved"})
    return cur
