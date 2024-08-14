<?php

namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;

#[\AllowDynamicProperties]
class AesGcmEncryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    private string $tag = '';

    public function __construct(
        private readonly StreamInterface $plaintext,
        private readonly string $key,
        private readonly string $initializationVector,
        private readonly string $aad = '',
        private readonly int $tagLength = 16,
        private readonly int $keySize = 256
    ) {
    }

    public function createStream(): StreamInterface
    {
        $cipherText = openssl_encrypt(
            (string)$this->plaintext,
            sprintf('aes-%d-gcm', $this->keySize),
            $this->key,
            OPENSSL_RAW_DATA,
            $this->initializationVector,
            $this->tag,
            $this->aad,
            $this->tagLength
        );

        if ($cipherText === false) {
            throw new EncryptionFailedException(
                "Unable to encrypt data with an initialization vector"
                . sprintf(' of %s using the aes-%d-gcm algorithm. Please', $this->initializationVector, $this->keySize)
                . " ensure you have provided a valid key size and initialization vector."
            );
        }

        return Utils::streamFor($cipherText);
    }

    public function getTag(): string
    {
        return $this->tag;
    }

    public function isWritable(): bool
    {
        return false;
    }
}
