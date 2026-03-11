<?php

declare(strict_types=1);

session_start();

$autoloadCandidates = [
    __DIR__ . '/../vendor/autoload.php',
    __DIR__ . '/../src/legacy_autoload.php',
];

foreach ($autoloadCandidates as $file) {
    if (is_file($file)) {
        require_once $file;
    }
}

use BlackWallSDK\BlackWallAuth;
use BlackWall\Auth\AuthClient;

$auth = new BlackWallAuth([
    'clientId' => '94d228c4-d4c6-4479-9b02-793e6a73e3f2',
    'authorizeUrl' => 'https://blackwall.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.cx/oauth/userinfo',
    'redirectUri' => 'https://test.dixon.cx/callback.php',
    'scope' => 'openid profile email offline_access',
]);

if (isset($_GET['logout'])) {
    unset(
        $_SESSION['access_token'],
        $_SESSION['refresh_token'],
        $_SESSION['user'],
        $_SESSION[AuthClient::STATE_SESSION_KEY],
        $_SESSION[AuthClient::CODE_VERIFIER_SESSION_KEY],
        $_SESSION[AuthClient::NONCE_SESSION_KEY]
    );
    header('Location: /');
    exit;
}

if (!isset($_SESSION['user'])) {
    $authData = $auth->getAuthorizationUrl();
    header('Location: ' . $authData['url']);
    exit;
}

header('Content-Type: text/plain; charset=utf-8');
echo "Authenticated (session)\n\n";
echo "User:\n";
echo json_encode($_SESSION['user'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n\n";
echo "Tokens (truncated):\n";
echo json_encode([
    'access_token' => isset($_SESSION['access_token']) ? substr((string) $_SESSION['access_token'], 0, 16) . '...' : null,
    'refresh_token' => isset($_SESSION['refresh_token']) ? substr((string) $_SESSION['refresh_token'], 0, 8) . '...' : null,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n\n";
echo "Logout: /?logout=1\n";
