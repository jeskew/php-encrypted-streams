<?php
namespace Jsq\EncryptionStreams;

use BadMethodCallException;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use LogicException;
use Psr\Http\Message\StreamInterface;

class HashingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    /**
     * @var StreamInterface
     */
    private $stream;

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

    private $key;

    private $algorithm;

    public function __construct(
        StreamInterface $stream,
        ?string $key = null,
        ?callable $onComplete = null,
        string $algorithm = 'sha256'
    ){
        $this->stream = $stream;
        $this->key = $key;
        $this->onComplete = $onComplete;
        $this->algorithm = $algorithm;

        $this->initializeHash();
    }

    /**
     * Returns the raw binary hash of the wrapped stream if it has been read.
     * Returns null otherwise.
     */
    public function getHash(): ?string
    {
        return $this->hash;
    }

    public function read($length): string
    {
        $read = $this->stream->read($length);
        if (strlen($read) > 0) {
            hash_update($this->hashResource, $read);
        }
        if ($this->stream->eof()) {
            $this->hash = hash_final($this->hashResource, true);
            if ($this->onComplete) {
                call_user_func($this->onComplete, $this->hash);
            }
        }

        return $read;
    }

    public function seek($offset, $whence = SEEK_SET): void
    {
        if ($offset === 0 && $whence === SEEK_SET) {
            $this->stream->seek($offset, $whence);
            $this->initializeHash();
        } else {
            throw new LogicException('AES encryption streams only support being'
                . ' rewound, not arbitrary seeking.');
        }
    }

    private function initializeHash(): void
    {
        $this->hash = null;
        $this->hashResource = hash_init(
            $this->algorithm,
            $this->key !== null ? HASH_HMAC : 0,
            $this->key
        );
    }
}