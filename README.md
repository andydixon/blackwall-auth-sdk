# BlackWall Auth SDK (PHP)

A distributable PHP SDK for integrating applications with BlackWall OAuth 2.1 and OpenID Connect.

This package provides:
- OAuth authorisation URL generation with PKCE (`S256`)
- Code-for-token exchange
- Refresh token exchange
- UserInfo retrieval
- UserInfo normalisation (`email`, `privilege_level`, `role`)
- Unified callback handling helper (`handleCallback`)
- Session helpers for `state` and `code_verifier`
- Typed API (`AuthClient`, `TokenSet`) and specific exception classes

## Requirements

- PHP 8.1+
- cURL extension (`ext-curl`)

## Installation

### 1. Install as a Composer package

If this repository is published and tagged:

```bash
composer require andydixon/blackwall-auth-sdk
```

### 2. Install from local path (during development)

In the consuming application's `composer.json`:

```json
{
  "repositories": [
    {
      "type": "path",
      "url": "../test.dixon.cx"
    }
  ],
  "require": {
    "andydixon/blackwall-auth-sdk": "*"
  }
}
```

Then run:

```bash
composer update andydixon/blackwall-auth-sdk
```

## Quick start

```php
<?php

declare(strict_types=1);

session_start();

require __DIR__ . '/vendor/autoload.php';

use BlackWall\Auth\AuthClient;
use BlackWall\Auth\Config;

$config = Config::fromArray([
    'clientId' => 'your-client-id',
    'authorizeUrl' => 'https://blackwall.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.cx/oauth/userinfo',
    'redirectUri' => 'https://your-app.example/callback.php',
    'scope' => 'openid profile email offline_access',
]);

$client = new AuthClient($config);

// Step 1: redirect user to provider
$auth = $client->buildAuthorisationUrl([
    'extra' => [
        // Some providers require nonce for OIDC requests.
        'nonce' => rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='),
    ],
]);
header('Location: ' . $auth['url']);
exit;
```

For callback handling, see `docs/INTEGRATION_GUIDE.md`.
For provider-side threat/invariant assumptions, see `docs/SECURITY_MODEL.md`.

Minimal callback example:

```php
$result = $client->handleCallback($_GET);

$_SESSION['user'] = [
    'email' => $result->user->email,
    'privilege_level' => $result->user->privilegeLevel,
    'role' => $result->user->role,
];
$_SESSION['access_token'] = $result->tokens->accessToken;
```

## Backwards compatibility

A wrapper class is retained for older integrations:

```php
use BlackWallSDK\BlackWallAuth;
```

This wrapper now delegates to `BlackWall\Auth\AuthClient`.

## Public API

- `BlackWall\Auth\Config`
- `BlackWall\Auth\AuthClient`
- `BlackWall\Auth\TokenSet`
- `BlackWall\Auth\AuthResult`
- `BlackWall\Auth\CallbackResult`
- `BlackWall\Auth\UserInfo`
- `BlackWall\Auth\UserInfoNormalizer`
- `BlackWall\Auth\Http\HttpClientInterface`
- `BlackWall\Auth\Http\CurlHttpClient`
- `BlackWall\Auth\Exception\*`

## Security notes

- Always validate OAuth `state` in callback handlers.
- Handle provider callback errors (`error`, `error_description`) explicitly; treat `access_denied` as an expected user/authorisation outcome rather than a transport failure.
- Treat `invalid_scope` as a client-configuration mismatch: requested scopes must be a subset of scopes allowed on the provider client.
- Expect `access_denied` even after the consent page is displayed if provider-side project membership or tenant scope changes before consent submission.
- Expect provider token introspection to return `active=false` when user/project/client state is no longer active.
- Expect revoked JWT access tokens to be rejected by provider `userinfo` even before token expiry.
- Register only HTTPS redirect URIs in provider client settings (HTTP should be used only for localhost loopback during development).
- Use OAuth/portal authentication endpoints for end users; provider admin login endpoints enforce separate admin scope checks.
- For provider admin enrolment URL export operations, use `POST` with CSRF protection; do not automate them via unauthenticated `GET` links.
- Handle provider CSV exports with formula-injection safety in mind if opening them in spreadsheet applications.
- Treat generated enrolment URLs as secrets and keep them out of URL query strings and request logs.
- For reverse-proxy deployments, harden trusted proxy/IP forwarding configuration to prevent spoofed client IP headers.
- Prefer narrowly scoped trusted-proxy entries (explicit IPs/CIDR ranges) instead of broad network trust.
- Keep client-side admin mutation retries idempotent; approval workflows can be lock-serialised and should not be assumed to execute twice.
- Do not submit parallel approve/reject/cancel decisions for the same approval request ID.
- Apply bounded CSV import sizes and row counts for admin bulk-user operations.
- Never place client secrets, refresh tokens, or access tokens in URL query strings.
- For OIDC providers, include a per-request `nonce` in authorisation requests.
- Ensure requested `scope` values in SDK config/examples (for example `offline_access`) are enabled on the provider-side client before rollout.
- Expect refresh-token exchange to fail (`invalid_grant`) if provider-side client scopes were tightened and the refresh token now carries disallowed scopes.
- For direct Cryptbin API usage, send `key_b64url` on unwrap calls; provider rejects key-mismatch unwrap attempts with `403 Forbidden`.
- For newly created Cryptbin items, continue using the creating WebAuthn credential for unwrap/update/delete flows.
- Always use HTTPS in production.
- Store refresh tokens securely.
- Keep access tokens out of logs and browser-visible output.
- Use short session lifetimes where possible.
- `Config::fromArray()` enforces HTTPS URLs by default.
- For localhost-only development over HTTP, set `allowInsecureHttp => true`.

## Repository layout

- `src/Auth/` - main SDK classes
- `src/Auth/Http/` - HTTP transport abstraction
- `src/Auth/Exception/` - typed exceptions
- `src/BlackWallAuth.php` - legacy compatibility wrapper
- `src/legacy_autoload.php` - fallback non-Composer loader
- `public_html/` - demonstration application
- `docs/` - integration documentation

## Licence

Proprietary (internal distribution by default).
