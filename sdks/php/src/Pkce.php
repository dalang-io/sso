<?php

declare(strict_types=1);

namespace Dalang\Sso;

/** A PKCE verifier/challenge pair (RFC 7636, S256). */
final class Pkce
{
    public function __construct(
        public readonly string $verifier,
        public readonly string $challenge,
    ) {
    }

    /** Generate a random verifier and derive its S256 challenge. */
    public static function generate(): self
    {
        $verifier = self::b64url(random_bytes(32));
        // challenge = base64url(sha256(verifier)) with no padding.
        $challenge = self::b64url(hash('sha256', $verifier, true));

        return new self($verifier, $challenge);
    }

    /** base64url-encode without padding. */
    private static function b64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
