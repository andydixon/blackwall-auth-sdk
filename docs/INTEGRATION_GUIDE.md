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
    $auth = $client->buildAuthorisationUrl();
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

## Operational guidance

- Keep provider URLs in environment variables, not hard-coded.
- Avoid printing tokens in production pages.
- Rotate client secrets for confidential clients.
- Validate `state` on every callback request.
- Use secure session cookies (`Secure`, `HttpOnly`, `SameSite=Lax` or stricter).
- HTTPS URLs are enforced by default in `Config::fromArray()`.
- For localhost-only HTTP testing, explicitly set `allowInsecureHttp => true`.
