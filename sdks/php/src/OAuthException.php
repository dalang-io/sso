<?php

declare(strict_types=1);

namespace Dalang\Sso;

use RuntimeException;

/** Thrown when the token endpoint returns a 4xx {error, error_description}. */
final class OAuthException extends RuntimeException
{
    public function __construct(
        public readonly string $error,
        public readonly string $errorDescription = '',
    ) {
        parent::__construct("oauth error: $error — $errorDescription");
    }
}
