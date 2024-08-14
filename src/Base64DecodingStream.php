<?php

namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

class Base64DecodingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private string $buffer = '';

    public function __construct(private readonly StreamInterface $stream)
    {
    }

    public function getSize(): ?int
    {
        return null;
    }

    public function read(int $length): string
    {
        $toRead = (int)ceil($length / 3) * 4;
        $this->buffer .= base64_decode($this->stream->read($toRead));

        $toReturn = substr($this->buffer, 0, $length);
        $this->buffer = substr($this->buffer, $length);
        return $toReturn;
    }
}