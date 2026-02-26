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

$auth = new BlackWallAuth([
    'clientId' => '94d228c4-d4c6-4479-9b02-793e6a73e3f2',
    'authorizeUrl' => 'https://blackwall.cx/oauth/authorize',
    'tokenUrl' => 'https://blackwall.cx/oauth/token',
    'userInfoUrl' => 'https://blackwall.cx/oauth/userinfo',
    'redirectUri' => 'https://test.dixon.cx/callback.php',
]);

try {
    $result = $auth->handleCallback($_GET);
    $_SESSION['access_token'] = $result['tokens']['access_token'] ?? null;
    $_SESSION['refresh_token'] = $result['tokens']['refresh_token'] ?? null;
    $_SESSION['user'] = $result['raw_user'] ?? null;

    header('Location: /');
    exit;
} catch (Throwable $e) {
    http_response_code(500);
    echo 'Auth failed: ' . htmlspecialchars($e->getMessage(), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}
