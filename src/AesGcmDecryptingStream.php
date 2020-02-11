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
        $plaintext = openssl_decrypt(
            (string) $this->cipherText,
            "aes-{$this->keySize}-gcm",
            $this->key,
            OPENSSL_RAW_DATA,
            $this->initializationVector,
            $this->tag,
            $this->aad
        );

        if ($plaintext === false) {
            throw new DecryptionFailedException("Unable to decrypt data with an initialization vector"
                . " of {$this->initializationVector} using the aes-{$this->keySize}-gcm algorithm. Please"
                . " ensure you have provided a valid key size, initialization vector, and key.");
        }

        return Psr7\stream_for($plaintext);
    }

    public function isWritable(): bool
    {
        return false;
    }
}
