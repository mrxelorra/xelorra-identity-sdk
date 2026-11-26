<?php

declare(strict_types=1);

namespace Xelorra\Identity\Exceptions;

class AccessRevokedException extends XelorraException
{
    public readonly ?string $reason;

    /**
     * @param array<string, mixed>|null $details
     */
    public function __construct(
        string $message = 'The user has revoked this application access on Xelorra One.',
        ?string $reason = null,
        ?array $details = null
    ) {
        parent::__construct('access_revoked', $message, 401, $details);
        $this->reason = $reason;
    }
}
