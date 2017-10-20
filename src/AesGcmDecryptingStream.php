<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

class AesGcmDecryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private $aad;

    private $initializationVector;

    private $key;

    private $keySize;

    private $cipherText;

    private $tag;

    private $tagLength;

    public function __construct(
        StreamInterface $cipherText,
        string $key,
        string $initializationVector,
        string $tag,
        string $aad = '',
        int $tagLength = 16,
        int $keySize = 256
    ) {
        $this->cipherText = $cipherText;
        $this->key = $key;
        $this->initializationVector = $initializationVector;
        $this->tag = $tag;
        $this->aad = $aad;
        $this->tagLength = $tagLength;
        $this->keySize = $keySize;
    }

    public function createStream(): StreamInterface
    {
        return Psr7\stream_for(openssl_decrypt(
            (string) $this->cipherText,
            "aes-{$this->keySize}-gcm",
            $this->key,
            OPENSSL_RAW_DATA,
            $this->initializationVector,
            $this->tag,
            $this->aad
        ));
    }

    public function isWritable(): bool
    {
        return false;
    }
}