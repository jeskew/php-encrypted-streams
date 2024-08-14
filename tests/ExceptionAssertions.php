<?php

declare(strict_types=1);

namespace Jsq\EncryptionStreams;

use Exception;

trait ExceptionAssertions
{
    public function assertException(callable $act, Exception $exception): void
    {
        $this->expectExceptionObject($exception);
        $act();
    }
}