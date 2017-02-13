<?php
namespace Jsq\EncryptionStreams;

use BadMethodCallException;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

class HashingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    /**
     * @var string
     */
    private $hash;

    /**
     * @var resource
     */
    private $hashResource;

    /**
     * @var callable
     */
    private $onComplete;

    public function __construct(
        StreamInterface $stream,
        $key = null,
        callable $onComplete = null,
        $algo = 'sha256'
    ){
        $this->stream = $stream;
        $this->hashResource
            = hash_init($algo, $key !== null ? HASH_HMAC : 0, $key);
        $this->onComplete = $onComplete;
    }

    /**
     * Returns the raw binary hash of the wrapped stream if it has been read.
     * Returns null otherwise.
     *
     * @return string|null
     */
    public function getHash()
    {
        return $this->hash;
    }

    public function isSeekable()
    {
        return false;
    }

    public function read($length)
    {
        $read = $this->stream->read($length);
        hash_update($this->hashResource, $read);
        if ($this->stream->eof()) {
            $this->hash = hash_final($this->hashResource, true);
            if ($this->onComplete) {
                call_user_func($this->onComplete, $this->hash);
            }
        }

        return $read;
    }

    public function seek($offset, $whence = SEEK_SET)
    {
        throw new BadMethodCallException('Hashing streams are not seekable');
    }
}