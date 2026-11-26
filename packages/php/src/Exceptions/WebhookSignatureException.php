<?php

declare(strict_types=1);

namespace Xelorra\Identity\Exceptions;

class WebhookSignatureException extends XelorraException
{
    public function __construct(string $errorCode, string $message)
    {
        parent::__construct($errorCode, $message, 401);
    }
}
