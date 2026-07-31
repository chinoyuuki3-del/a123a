# Troll Engine AFT Sync API

別端末でもAFTユーザーと友達情報を同期するためのAPIです。ソースコードはGitHubへ保存し、実際のユーザーデータは公開リポジトリではなくCloudflare D1へ保存します。

## 実装済み

- AFTユーザー登録・ログイン
- ユーザー名／AFT ID検索
- 友達申請・承認・一覧
- ブロック時の友達解除と検索除外
- BAN中ユーザーの利用停止
- 端末データの保存・読込
- パスワードのPBKDF2ハッシュ化
- 30日間のランダムセッショントークン
- SQLインジェクション対策のバインド変数

メールアドレス、GitHubトークン、Troll Engineのオーナーキーは保存しません。

## 構成

- `src/index.js` — Cloudflare Worker API
- `schema.sql` — D1データベース
- `wrangler.jsonc` — Worker設定
- `package.json` — 開発・公開コマンド

## 公開前の設定

1. CloudflareでD1データベース `aft-sync-db` を作成します。
2. `wrangler.jsonc` の `REPLACE_WITH_D1_DATABASE_ID` を作成したD1 IDへ置き換えます。
3. `ALLOWED_ORIGINS` に公開するTroll EngineのURLを設定します。
4. `npm install`
5. `npm run db:remote`
6. `npm run deploy`
7. 表示された `https://...workers.dev` のURLをTroll Engineの「AFT Sync」に入力します。

ローカルHTMLファイルから試す間だけ `ALLOW_LOCAL_FILE` を `true` にします。正式公開時は `false` にして、許可したWebサイトだけから接続してください。

## API

| Method | Path | 説明 |
| --- | --- | --- |
| GET | `/health` | 稼働確認 |
| POST | `/v1/register` | 登録 |
| POST | `/v1/login` | ログイン |
| POST | `/v1/logout` | ログアウト |
| GET | `/v1/me` | ログイン中ユーザー |
| GET | `/v1/users/search?q=` | ユーザー検索 |
| POST | `/v1/friends/request` | 友達申請 |
| GET | `/v1/friends/requests` | 受信申請 |
| POST | `/v1/friends/accept` | 申請承認 |
| GET | `/v1/friends` | 友達一覧 |
| POST | `/v1/blocks` | ブロック |
| GET | `/v1/sync` | 端末データ読込 |
| PUT | `/v1/sync` | 端末データ保存 |

認証が必要なAPIでは `Authorization: Bearer <token>` を送ります。HTMLへ固定トークンを埋め込んではいけません。
