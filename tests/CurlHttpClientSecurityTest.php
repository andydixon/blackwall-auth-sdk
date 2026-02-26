<?php

declare(strict_types=1);

namespace BlackWall\Auth\Tests;

use BlackWall\Auth\Exception\TransportException;
use BlackWall\Auth\Http\CurlHttpClient;
use PHPUnit\Framework\TestCase;

final class CurlHttpClientSecurityTest extends TestCase
{
    public function testRejectsUnsupportedUrlScheme(): void
    {
        $client = new CurlHttpClient();

        $this->expectException(TransportException::class);
        $client->get('file:///etc/passwd');
    }

    public function testRejectsHeaderInjectionAttempt(): void
    {
        $client = new CurlHttpClient();

        $this->expectException(TransportException::class);
        $client->get('https://example.com', [
            'X-Test' => "ok\r\nInjected: yes",
        ]);
    }
}

