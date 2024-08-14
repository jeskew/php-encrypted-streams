<?php

namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

class Base64EncodingStream implements StreamInterface
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
            : (int)ceil($unencodedSize / 3) * 4;
    }

    public function read($length): string
    {
        $toRead = (int)ceil($length / 4) * 3;
        $this->buffer .= base64_encode($this->stream->read($toRead));

        $toReturn = substr($this->buffer, 0, $length);
        $this->buffer = substr($this->buffer, $length);
        return $toReturn;
    }
}