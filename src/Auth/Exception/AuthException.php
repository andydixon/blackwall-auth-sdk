<?php

declare(strict_types=1);

namespace BlackWall\Auth\Exception;

class AuthException extends \RuntimeException
{
    public function __construct(
        string $message = '',
        private readonly ?string $authCode = null,
        int $code = 0,
        ?\Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }

    public function authCode(): ?string
    {
        return $this->authCode;
    }
}
