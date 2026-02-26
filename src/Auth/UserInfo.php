<?php

declare(strict_types=1);

namespace BlackWall\Auth;

final class UserInfo
{
    /**
     * @param array<string, mixed> $raw
     */
    public function __construct(
        public readonly string $email,
        public readonly ?int $privilegeLevel,
        public readonly ?string $role,
        public readonly array $raw
    ) {
    }
}

