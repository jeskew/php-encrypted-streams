<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

class HexEncodingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    /**
     * @var string
     */
    private $buffer = '';

    /**
     * @var StreamInterface
     */
    private $stream;

    public function __construct(StreamInterface $stream)
    {
        $this->stream = $stream;
    }

    public function getSize(): ?int
    {
        $unencodedSize = $this->stream->getSize();
        return $unencodedSize === null
            ? null
            : $unencodedSize * 2;
    }

    public function read($length): string
    {
        $this->buffer .= bin2hex($this->stream->read(ceil($length / 2)));

        $toReturn = substr($this->buffer, 0, $length);
        $this->buffer = substr($this->buffer, $length);
        return $toReturn;
    }
}