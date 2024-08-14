<?php

namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

class HexDecodingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private string $buffer = '';

    public function __construct(private readonly StreamInterface $stream)
    {
    }

    public function getSize(): ?int
    {
        $unencodedSize = $this->stream->getSize();
        return $unencodedSize === null
            ? null
            : intval($unencodedSize / 2);
    }

    public function read($length): string
    {
        $this->buffer .= hex2bin($this->stream->read($length * 2));

        $toReturn = substr($this->buffer, 0, $length);
        $this->buffer = substr($this->buffer, $length);
        return $toReturn;
    }
}