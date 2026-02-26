<?php

declare(strict_types=1);

namespace BlackWall\Auth\Http;

use BlackWall\Auth\Exception\TransportException;

final class CurlHttpClient implements HttpClientInterface
{
    public function __construct(
        private readonly int $timeoutSeconds = 20,
        private readonly int $connectTimeoutSeconds = 10
    )
    {
    }

    public function postForm(string $url, array $fields, array $headers = []): array
    {
        $this->assertValidUrl($url);
        $ch = curl_init($url);
        if ($ch === false) {
            throw new TransportException('Unable to initialise cURL for POST request', 'curl_init_failed');
        }

        $headerLines = $this->normaliseHeaders(array_merge([
            'Content-Type' => 'application/x-www-form-urlencoded',
            'Accept' => 'application/json',
        ], $headers));

        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($fields, '', '&', PHP_QUERY_RFC3986),
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeoutSeconds,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
        ]);
        if (defined('CURLOPT_PROTOCOLS')) {
            curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        }
        if (defined('CURLOPT_REDIR_PROTOCOLS')) {
            curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        }

        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($body === false) {
            throw new TransportException(
                $error !== '' ? $error : 'Unknown cURL POST error',
                $errno > 0 ? ('curl_errno_' . $errno) : 'curl_post_failed'
            );
        }

        return ['status' => $status, 'body' => $body];
    }

    public function get(string $url, array $headers = []): array
    {
        $this->assertValidUrl($url);
        $ch = curl_init($url);
        if ($ch === false) {
            throw new TransportException('Unable to initialise cURL for GET request', 'curl_init_failed');
        }

        $headerLines = $this->normaliseHeaders(array_merge([
            'Accept' => 'application/json',
        ], $headers));

        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => $this->connectTimeoutSeconds,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
        ]);
        if (defined('CURLOPT_PROTOCOLS')) {
            curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        }
        if (defined('CURLOPT_REDIR_PROTOCOLS')) {
            curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        }

        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($body === false) {
            throw new TransportException(
                $error !== '' ? $error : 'Unknown cURL GET error',
                $errno > 0 ? ('curl_errno_' . $errno) : 'curl_get_failed'
            );
        }

        return ['status' => $status, 'body' => $body];
    }

    /**
     * @param array<string, string> $headers
     * @return string[]
     */
    private function normaliseHeaders(array $headers): array
    {
        $result = [];
        foreach ($headers as $name => $value) {
            if (
                str_contains((string) $name, "\r")
                || str_contains((string) $name, "\n")
                || str_contains((string) $value, "\r")
                || str_contains((string) $value, "\n")
            ) {
                throw new TransportException('Header names/values must not contain CR/LF characters', 'invalid_header');
            }
            $result[] = sprintf('%s: %s', $name, $value);
        }

        return $result;
    }

    private function assertValidUrl(string $url): void
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'])) {
            throw new TransportException('Request URL must be an absolute URL', 'invalid_url');
        }

        $scheme = strtolower((string) $parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new TransportException('Only http/https URLs are supported', 'invalid_url_scheme');
        }
    }
}
