<?php

declare(strict_types=1);

namespace BlackWall\Auth\Tests;

use BlackWall\Auth\Config;
use PHPUnit\Framework\TestCase;

final class ConfigSecurityTest extends TestCase
{
    public function testRejectsInsecureHttpForNonLocalhostByDefault(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::fromArray([
            'clientId' => 'client-123',
            'authorizeUrl' => 'http://provider.example/oauth/authorize',
            'tokenUrl' => 'https://provider.example/oauth/token',
            'userInfoUrl' => 'https://provider.example/oauth/userinfo',
            'redirectUri' => 'https://app.example/callback.php',
        ]);
    }

    public function testAllowsInsecureHttpForLocalhostWhenExplicitlyEnabled(): void
    {
        $config = Config::fromArray([
            'clientId' => 'client-123',
            'authorizeUrl' => 'http://localhost/oauth/authorize',
            'tokenUrl' => 'http://127.0.0.1/oauth/token',
            'userInfoUrl' => 'http://localhost/oauth/userinfo',
            'redirectUri' => 'http://localhost/callback.php',
            'allowInsecureHttp' => true,
        ]);

        self::assertTrue($config->allowInsecureHttp);
        self::assertSame('http://localhost/oauth/authorize', $config->authorizeUrl);
    }
}

