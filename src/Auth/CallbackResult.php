<?php

declare(strict_types=1);

namespace BlackWall\Auth;

final class CallbackResult
{
    /**
     * @param array<string, mixed> $rawUser
     */
    public function __construct(
        public readonly TokenSet $tokens,
        public readonly UserInfo $user,
        public readonly array $rawUser
    ) {
    }
}

