# Discord OIDC Provider for Cloudflare Workers

これは、Cloudflare Workers上で動作する、Discordアカウントを利用したOIDC (OpenID Connect) プロバイダーです。
OIDCをサポートする様々なアプリケーションに、Discordアカウントでのシングルサインオン（SSO）機能を提供します。

## 主な機能

- **OIDC準拠**: `authorization_code` フローをサポートします。
- **PKCEサポート**: RFC 7636で定義されたPKCE (Proof Key for Code Exchange) に対応しており、よりセキュアな認証が可能です。
- **Discord連携**: DiscordのOAuth2をバックエンドで利用し、ユーザー情報（ID, ユーザー名, アバター, メールアドレス）を取得します。
- **サーバーレス**: Cloudflare Workers上で動作するため、サーバーの管理が不要です。
- **簡単なデプロイ**: Wrangler CLIを使って簡単にデプロイできます。

## セットアップ手順

### 1. リポジトリのクローン

```bash
git clone https://github.com/umireon/discord-oidc-provider-cloudflare.git
cd discord-oidc-provider-cloudflare
```

### 2. 依存関係のインストール

```bash
npm install
```

### 3. Discordアプリケーションの作成

1.  [Discord Developer Portal](https://discord.com/developers/applications)にアクセスし、新しいアプリケーションを作成します。
2.  **OAuth2** タブに移動し、`CLIENT ID` と `CLIENT SECRET` を控えておきます。
3.  **Redirects** に、デプロイしたWorkerのコールバックURLを追加します。
    - 例: `https://<YOUR_WORKER_NAME>.<YOUR_CLOUDFLARE_SUBDOMAIN>.workers.dev/callback`

### 4. 環境変数の設定

`wrangler.json` を参考に、環境変数を設定します。ローカル開発用には `.dev.vars` ファイルを作成します。

```ini
# .dev.vars

# Discord Application Credentials
DISCORD_CLIENT_ID="YOUR_DISCORD_CLIENT_ID"
DISCORD_CLIENT_SECRET="YOUR_DISCORD_CLIENT_SECRET"

# OIDC Provider's Client Credentials
# This provider only supports one client.
OIDC_CLIENT_ID="YOUR_OIDC_CLIENT_ID"
OIDC_CLIENT_SECRET="YOUR_OIDC_CLIENT_SECRET"
OIDC_REDIRECT_URI="YOUR_OIDC_CLIENT_REDIRECT_URI"

# (Optional) Discord Guild ID to get user roles
# DISCORD_GUILD_ID="YOUR_DISCORD_GUILD_ID"
```

### 5. シークレットキーの生成と設定

以下のコマンドを実行して、JWTの署名やJWEの暗号化に必要なキーを生成し、CloudflareのSecretに設定します。

**本番環境 (production)**

```bash
# JWTの署名に使うES256キーペア
npm run setup:jwt_private_key

# 認可コードの暗号化に使うJWEキー
npm run setup:code_private_key

# stateの署名に使うシークレット
npm run setup:state_secret
```

ローカル開発の場合は、`--env=development` をつけて実行するか、手動で `.dev.vars` に設定してください。

### 6. デプロイ

```bash
npm run deploy
```

## 使い方

OIDCをサポートするアプリケーション（例: Grafana, GitLab, etc.）の認証設定で、以下の情報を設定します。

- **Issuer URL**: `https://<YOUR_WORKER_NAME>.<YOUR_CLOUDFLARE_SUBDOMAIN>.workers.dev`
- **Client ID**: `OIDC_CLIENT_ID` で設定した値
- **Client Secret**: `OIDC_CLIENT_SECRET` で設定した値

アプリケーションが自動的に `.well-known/openid-configuration` を検出し、設定が完了します。

## APIエンドポイント

- `/.well-known/openid-configuration`: OIDCプロバイダーの設定情報を提供します。
- `/jwks.json`: IDトークンの署名検証に使われる公開鍵を提供します。
- `/auth`: 認可エンドポイント。
- `/token`: トークンエンドポイント。
- `/userinfo`: ユーザー情報エンドポイント。
- `/callback`: Discordからのリダイレクトを受け取る内部エンドポイント。
