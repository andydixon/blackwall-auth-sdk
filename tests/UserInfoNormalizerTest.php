<?php

declare(strict_types=1);

namespace BlackWall\Auth\Tests;

use BlackWall\Auth\UserInfoNormalizer;
use BlackWall\Auth\Exception\UserInfoException;
use PHPUnit\Framework\TestCase;

final class UserInfoNormalizerTest extends TestCase
{
    public function testNormalizesNestedClaimsAndRoleString(): void
    {
        $normalized = UserInfoNormalizer::normalize([
            'email' => 'User@Example.com',
            'claims' => [
                'role' => 'admin',
            ],
        ]);

        self::assertSame('user@example.com', $normalized->email);
        self::assertSame(1, $normalized->privilegeLevel);
        self::assertSame('admin', $normalized->role);
    }

    public function testThrowsWhenEmailMissing(): void
    {
        $this->expectException(UserInfoException::class);
        UserInfoNormalizer::normalize(['sub' => '123']);
    }
}

