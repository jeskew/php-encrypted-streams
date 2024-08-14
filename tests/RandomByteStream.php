<?php

namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\PumpStream;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

class RandomByteStream implements StreamInterface
{
    use StreamDecoratorTrait;

    /**
     * @var PumpStream
     */
    private $stream;

    /**
     * @param int $maxLength
     */
    public function __construct(private $maxLength)
    {
        $this->stream = new PumpStream(function ($length) {
            $length = min($length, $this->maxLength);
            $this->maxLength -= $length;
            return $length > 0 ? random_bytes($length) : false;
        });
    }

    public function getSize(): ?int
    {
        return $this->maxLength;
    }
}
