# claude-security-scan

**「セキュリティチェックして」の一言で、自分の開発環境をまるごと点検する Claude Code スキル。**

Mac・手元の全gitリポジトリ・GitHub・Vercelと公開サイト・AWS・Gmail を**読み取り専用**で横断スキャンし、
重要度別のレポートと「前回から増えたもの」を出します。設定の書き換え・送信・削除は一切しません。

![見本データのレポート](docs/report-demo.png)

## なぜ作ったか

最近の情報漏えいは、高度な攻撃より「うっかり」から起きています。

- コミット履歴に残ったままのAPIキー
- 本番に一緒に上がってしまった `.env`
- MFAの無いクラウドの管理者アカウント
- 2段階認証を必須にしていない GitHub の組織
- 乗っ取られたメールに仕込まれた自動転送

どれも、見に行けば数秒で分かります。ただ、確認する場所が散らばっていて、毎週全部を見て回る人はいません。
それを Claude Code に任せるためのスキルです。

## 何を見るか

| 領域 | 主なチェック |
|---|---|
| Mac本体 | FileVault・ファイアウォール・Gatekeeper・SIP・自動ログイン・画面ロック・未適用アップデート・外から接続できるポート・~/.ssh の権限・常駐プログラム（root権限の常駐が、書き換え可能な場所や未署名のプログラムを起動していないか） |
| コード | 手元の全gitリポジトリのコミット履歴にある秘密情報（[gitleaks](https://github.com/gitleaks/gitleaks)・値は伏せ字）・`.env` のgit登録・依存パッケージの既知脆弱性（[osv-scanner](https://github.com/google/osv-scanner)） |
| GitHub | 本人と所属組織の2FA・2FA必須設定・未設定のメンバー・公開リポ作成権限・外部コラボレーター・Webhook・Dependabot / Secret scanning のアラート |
| Webサイト・Vercel | 全チームの本番ドメイン: HTTPS・証明書期限・セキュリティヘッダー・`.env` / `.git` の露出・プレビューURLの保護・ブラウザに出てしまう秘密っぽい環境変数 |
| AWS | ルートのMFA・MFAの無いIAMユーザー・放置されたアクセスキー・公開S3・CloudTrail・GuardDuty・全開放の管理/DBポート・公開RDS |
| Gmail | 自動転送・転送フィルタ・警告メールを隠すフィルタ・委任・最近のセキュリティ通知（件名だけ） |

入っているCLIだけを使います。無いものは「確認できなかった項目」に理由つきで出るだけで、止まりません。
**「確認できなかった」を「問題なし」と混同しない**のがこのツールの方針です。

## 導入

```bash
git clone https://github.com/chaenmasahiro0425/claude-security-scan ~/.claude/skills/security-scan
bash ~/.claude/skills/security-scan/scripts/install-tools.sh   # gitleaks と osv-scanner を取得（SHA256を検証）
```

あとは Claude Code で **「セキュリティチェックして」** と言うだけです。

必要なもの: Python 3.11 以上。各領域を見るには、それぞれのCLIにログインしておきます（入っているものだけでOK）。

| 領域 | 準備 |
|---|---|
| GitHub | `gh auth login` |
| Vercel | `vercel login` |
| AWS | `aws configure` または `aws sso login` |
| Gmail | [gog](https://github.com/steipete/gogcli) で `gog auth add you@example.com` |

## 使い方

Claude Code から:

> セキュリティチェックして
> 前回から新しく出たリスクだけ教えて
> 直せるところある？
> 毎週月曜にスキャンするようにして

ターミナルから:

```bash
python3 ~/.claude/skills/security-scan/scan.py                # 全部
python3 ~/.claude/skills/security-scan/scan.py --skip repos   # 重いコード検査を外す
python3 ~/.claude/skills/security-scan/scan.py --demo --open  # 見本データで見た目だけ確認
bash ~/.claude/skills/security-scan/scripts/install-schedule.sh   # 毎週月曜 8:00 に自動実行（macOS）
```

結果は `reports/<日時>/report.html`（重要度・領域・NEWだけで絞り込み）に保存されます。

## 安全のための作り

- **読み取りだけ**: gog は `--readonly`、AWS は describe / list / get、Webサイトへは GET だけ
- **秘密の値を残さない**: gitleaks は `--redact`、Vercelの環境変数は名前と種類だけ、AWSのキーIDは末尾4桁、常駐プログラムの起動引数は記録しない。エラー文も伏せ字にしてから保存
- **見えなかったものを「解消」にしない**: 取得に失敗した領域の指摘は、前回との比較で「解消」に数えない
- レポートは自分のPCにだけ保存（権限700）。弱点の一覧なので共有に注意してください

## 設定（任意）

無くても動きます。対象を絞りたいときだけ [`config.example.toml`](config.example.toml) を
`~/.config/security-scan/config.toml` にコピーして編集してください。

## 制限

- Google Workspace 全体の管理設定（社員の2段階認証の強制など）は Admin API の委任が必要なため対象外です
- 外部サイトへの攻撃的な検査（総当たり・ファジング）はしません。自分が管理するサイトだけを対象にしてください
- 検出は手がかりです。最終判断と修正は人が行ってください

## ライセンス

MIT
