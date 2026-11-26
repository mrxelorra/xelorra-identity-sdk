<?php

declare(strict_types=1);

namespace Xelorra\Identity\Exceptions;

class InsufficientScopeException extends XelorraException
{
    /** @var list<string> */
    public readonly array $requiredScopes;

    /**
     * @param list<string> $requiredScopes
     * @param array<string, mixed>|null $details
     */
    public function __construct(
        string $message = 'The access token does not include the required scope for this endpoint.',
        array $requiredScopes = [],
        ?array $details = null
    ) {
        parent::__construct('insufficient_scope', $message, 403, $details);
        $this->requiredScopes = $requiredScopes;
    }
}
