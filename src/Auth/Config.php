<?php

declare(strict_types=1);

namespace BlackWall\Auth;

final class Config
{
    public function __construct(
        public readonly string $clientId,
        public readonly string $authorizeUrl,
        public readonly string $tokenUrl,
        public readonly string $redirectUri,
        public readonly ?string $userInfoUrl = null,
        public readonly ?string $clientSecret = null,
        public readonly string $defaultScope = 'openid profile email',
        public readonly bool $allowInsecureHttp = false
    ) {
    }

    /**
     * @param array<string, mixed> $config
     */
    public static function fromArray(array $config): self
    {
        foreach (['clientId', 'authorizeUrl', 'tokenUrl', 'redirectUri'] as $required) {
            if (empty($config[$required]) || !is_string($config[$required])) {
                throw new \InvalidArgumentException("{$required} is required");
            }
        }

        $allowInsecureHttp = isset($config['allowInsecureHttp']) && (bool) $config['allowInsecureHttp'];
        $authorizeUrl = rtrim(trim((string) $config['authorizeUrl']), '/');
        $tokenUrl = rtrim(trim((string) $config['tokenUrl']), '/');
        $redirectUri = trim((string) $config['redirectUri']);
        $userInfoUrl = isset($config['userInfoUrl']) ? rtrim(trim((string) $config['userInfoUrl']), '/') : null;

        self::assertSecureUrl($authorizeUrl, 'authorizeUrl', $allowInsecureHttp);
        self::assertSecureUrl($tokenUrl, 'tokenUrl', $allowInsecureHttp);
        self::assertSecureUrl($redirectUri, 'redirectUri', $allowInsecureHttp);
        if ($userInfoUrl !== null && $userInfoUrl !== '') {
            self::assertSecureUrl($userInfoUrl, 'userInfoUrl', $allowInsecureHttp);
        }

        return new self(
            clientId: $config['clientId'],
            authorizeUrl: $authorizeUrl,
            tokenUrl: $tokenUrl,
            redirectUri: $redirectUri,
            userInfoUrl: $userInfoUrl,
            clientSecret: isset($config['clientSecret']) ? (string) $config['clientSecret'] : null,
            defaultScope: isset($config['scope']) ? (string) $config['scope'] : 'openid profile email',
            allowInsecureHttp: $allowInsecureHttp
        );
    }

    private static function assertSecureUrl(string $url, string $field, bool $allowInsecureHttp): void
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'])) {
            throw new \InvalidArgumentException("{$field} must be a valid absolute URL");
        }

        $scheme = strtolower((string) $parts['scheme']);
        if (!in_array($scheme, ['https', 'http'], true)) {
            throw new \InvalidArgumentException("{$field} must use http or https");
        }

        if ($scheme === 'https') {
            return;
        }

        if ($allowInsecureHttp && self::isLocalHost((string) ($parts['host'] ?? ''))) {
            return;
        }

        throw new \InvalidArgumentException("{$field} must use https (set allowInsecureHttp=true for localhost development)");
    }

    private static function isLocalHost(string $host): bool
    {
        $normalized = strtolower(trim($host));
        return in_array($normalized, ['localhost', '127.0.0.1', '::1'], true);
    }
}
