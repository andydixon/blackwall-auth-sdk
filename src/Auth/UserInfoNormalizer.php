<?php

declare(strict_types=1);

namespace BlackWall\Auth;

use BlackWall\Auth\Exception\UserInfoException;

final class UserInfoNormalizer
{
    /**
     * @param array<string, mixed> $raw
     */
    public static function normalize(array $raw): UserInfo
    {
        $email = self::extractEmail($raw);
        if ($email === null || $email === '') {
            throw new UserInfoException('UserInfo payload did not include a valid email.', 'missing_email');
        }

        $privilegeLevel = self::resolvePrivilegeLevel($raw);
        $role = self::resolveRole($raw);

        return new UserInfo(
            email: strtolower(trim($email)),
            privilegeLevel: $privilegeLevel,
            role: $role,
            raw: $raw
        );
    }

    /**
     * @param array<string, mixed> $raw
     */
    public static function resolvePrivilegeLevel(array $raw): ?int
    {
        $candidates = [
            $raw['privilege_level'] ?? null,
            $raw['privilegeLevel'] ?? null,
            $raw['privilege'] ?? null,
            $raw['level'] ?? null,
            $raw['role_level'] ?? null,
            $raw['roleLevel'] ?? null,
            $raw['role'] ?? null,
        ];

        if (isset($raw['claims']) && is_array($raw['claims'])) {
            $candidates[] = $raw['claims']['privilege_level'] ?? null;
            $candidates[] = $raw['claims']['role_level'] ?? null;
            $candidates[] = $raw['claims']['role'] ?? null;
        }

        foreach ($candidates as $value) {
            if (is_int($value)) {
                return $value;
            }
            if (is_string($value) && ctype_digit($value)) {
                return (int) $value;
            }
            if (is_string($value)) {
                $role = strtolower(trim($value));
                if (in_array($role, ['admin', 'superadmin', 'super_admin', 'owner'], true)) {
                    return 1;
                }
                if (in_array($role, ['user', 'tutor', 'member'], true)) {
                    return 2;
                }
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $raw
     */
    public static function resolveRole(array $raw): ?string
    {
        $candidates = [
            $raw['role'] ?? null,
            $raw['role_name'] ?? null,
            $raw['roleName'] ?? null,
        ];

        if (isset($raw['claims']) && is_array($raw['claims'])) {
            $candidates[] = $raw['claims']['role'] ?? null;
            $candidates[] = $raw['claims']['role_name'] ?? null;
        }

        foreach ($candidates as $value) {
            if (is_string($value) && trim($value) !== '') {
                return strtolower(trim($value));
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $raw
     */
    private static function extractEmail(array $raw): ?string
    {
        $email = $raw['email'] ?? $raw['upn'] ?? null;
        if (is_string($email) && trim($email) !== '') {
            return $email;
        }

        if (isset($raw['claims']) && is_array($raw['claims'])) {
            $claimEmail = $raw['claims']['email'] ?? $raw['claims']['upn'] ?? null;
            if (is_string($claimEmail) && trim($claimEmail) !== '') {
                return $claimEmail;
            }
        }

        return null;
    }
}

