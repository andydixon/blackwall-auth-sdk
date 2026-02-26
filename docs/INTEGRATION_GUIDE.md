# Integration Guide (British English)

This guide shows a complete OAuth/OIDC login flow using `BlackWall\Auth\AuthClient`.

## 1. Start login

```php
<?php

declare(strict_types=1);

session_start();
require __DIR__ . '/vendor/autoload.php';

use BlackWall\Auth\AuthClient;
use BlackWall\Auth\Config;

$client = new AuthClient(Config::fromArray([
    'clientId' => 'your-client-id',
    'authorizeUrl' => 'https://blackwall.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.cx/oauth/userinfo',
    'redirectUri' => 'https://your-app.example/callback.php',
    'scope' => 'openid profile email offline_access',
]));

if (!isset($_SESSION['user'])) {
    $auth = $client->buildAuthorisationUrl([
        'extra' => [
            // Some providers require nonce for OIDC requests.
            'nonce' => rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '='),
        ],
    ]);
    // Prevent stale redirects from being reused from cache.
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Location: ' . $auth['url']);
    exit;
}

echo 'Already signed in.';
```

## 2. Handle callback

```php
<?php

declare(strict_types=1);

session_start();
require __DIR__ . '/vendor/autoload.php';

use BlackWall\Auth\AuthClient;
use BlackWall\Auth\Config;

$client = new AuthClient(Config::fromArray([
    'clientId' => 'your-client-id',
    'authorizeUrl' => 'https://blackwall.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.cx/oauth/userinfo',
    'redirectUri' => 'https://your-app.example/callback.php',
]));

if (isset($_GET['error'])) {
    $error = (string) $_GET['error'];
    $description = isset($_GET['error_description']) ? (string) $_GET['error_description'] : 'Unknown provider error';
    // access_denied is a normal authorisation outcome (for example, membership
    // revoked, privilege changed, or user denied consent between request and submit).
    http_response_code($error === 'access_denied' ? 403 : 400);
    exit('Authorization failed: ' . $description);
}

$result = $client->handleCallback($_GET);

$_SESSION['user'] = [
    'email' => $result->user->email,
    'privilege_level' => $result->user->privilegeLevel,
    'role' => $result->user->role,
];
$_SESSION['access_token'] = $result->tokens->accessToken;
$_SESSION['refresh_token'] = $result->tokens->refreshToken;

header('Location: /');
exit;
```

## 3. Single callback for multiple app roles

Using one OAuth client and one callback URL is recommended.

Map users in your application by:

1. `email` claim to local account record
2. `privilege_level` (or `role`) to application role

Typical mapping example:

- `privilege_level = 1` => admin/superadmin
- `privilege_level = 2` => user/tutor

If `privilege_level` is absent, the SDK also resolves common role strings (`admin`, `superadmin`, `user`, `tutor`).

## 4. Refresh token (optional)

```php
<?php

$tokens = $client->refreshAccessToken($_SESSION['refresh_token']);
$_SESSION['access_token'] = $tokens->accessToken;
if ($tokens->refreshToken !== null) {
    $_SESSION['refresh_token'] = $tokens->refreshToken;
}
```

## Exceptions

Catch specific exceptions for clearer handling:

- `BlackWall\Auth\Exception\StateMismatchException`
- `BlackWall\Auth\Exception\TokenExchangeException`
- `BlackWall\Auth\Exception\UserInfoException`
- `BlackWall\Auth\Exception\TransportException`

Example:

```php
try {
    $tokens = $client->exchangeCodeForTokens($code);
} catch (\BlackWall\Auth\Exception\TokenExchangeException $e) {
    error_log('Token exchange failed: ' . $e->getMessage());
    error_log('Auth code: ' . ($e->authCode() ?? 'none'));
    http_response_code(502);
}
```

`UserInfoException` with `invalid_token` can occur when provider-side subject scope is no longer active (for example user/project disabled) between token issuance and userinfo retrieval.
`TokenExchangeException` with `invalid_grant` can also occur when provider-side client/user/project state is inactive at exchange time.
Provider login/authorization steps can also fail with `access_denied` when account status is disabled before completion.
WebAuthn-based login verification can return credential-style failures for disabled accounts even when authenticator assertions are otherwise valid.
Existing authenticated sessions may also be invalidated when account status changes to disabled.
OAuth authorization consent submission can return `access_denied` if the account becomes inactive between session establishment and consent completion.

## Operational guidance

- Keep provider URLs in environment variables, not hard-coded.
- Avoid printing tokens in production pages.
- Expect `429 Too Many Requests` from provider control endpoints under abuse protection; implement backoff/retry instead of tight loops.
- Apply the same backoff strategy for provider `userinfo` calls that return `429 Too Many Requests`.
- For token exchange and refresh, apply bounded retry/backoff on transient provider failures instead of immediate repeated retries.
- Use exactly one client authentication method per token/control request (do not send both HTTP Basic and `client_secret` form fields together).
- If you call provider WebAuthn login challenge/verify endpoints directly, use `POST` only.
- Configure OAuth client redirect URIs as HTTPS in production; reserve HTTP for localhost loopback testing only.
- Assume provider rate limits are enforced per source identity (for example IP) and shared across related auth endpoints.
- Rotate client secrets for confidential clients.
- Do not transport secrets or tokens in URL query parameters; keep them in server-side session or secure storage only.
- Add a unique `nonce` to each OIDC authorisation request.
- Keep `state`, `nonce`, and PKCE values within standard URL-safe formats/lengths; malformed values can be rejected by provider validation.
- Validate `state` on every callback request.
- Use secure session cookies (`Secure`, `HttpOnly`, `SameSite=Lax` or stricter).
- HTTPS URLs are enforced by default in `Config::fromArray()`.
- For localhost-only HTTP testing, explicitly set `allowInsecureHttp => true`.
