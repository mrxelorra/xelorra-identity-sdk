<?php

declare(strict_types=1);

namespace Xelorra\Identity\Exceptions;

use RuntimeException;
use Throwable;

class XelorraException extends RuntimeException
{
    public readonly string $errorCode;
    public readonly ?int $httpStatus;

    /** @var array<string, mixed>|null */
    public readonly ?array $details;

    /**
     * @param array<string, mixed>|null $details
     */
    public function __construct(
        string $errorCode,
        string $message,
        ?int $httpStatus = null,
        ?array $details = null,
        ?Throwable $previous = null
    ) {
        parent::__construct($message, $httpStatus ?? 0, $previous);
        $this->errorCode = $errorCode;
        $this->httpStatus = $httpStatus;
        $this->details = $details;
    }
}
