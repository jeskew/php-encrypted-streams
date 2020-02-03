<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\PumpStream;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

class RandomByteStream implements StreamInterface
{
    use StreamDecoratorTrait;

    /**
     * @var int
     */
    private $maxLength;

    /**
     * @var PumpStream
     */
    private $stream;

    /**
     * @param int $maxLength
     */
    public function __construct($maxLength)
    {
        $this->maxLength = $maxLength;
        $this->stream = new PumpStream(function ($length) use (&$maxLength) {
            $length = min($length, $maxLength);
            $maxLength -= $length;
            return $length > 0 ? random_bytes($length) : false;
        });
    }

    public function getSize()
    {
        return $this->maxLength;
    }
}
