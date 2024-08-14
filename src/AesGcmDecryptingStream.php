<?php

namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\StreamInterface;

#[\AllowDynamicProperties]
class AesGcmDecryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    public function __construct(
        private readonly StreamInterface $cipherText,
        private readonly string $key,
        private readonly string $initializationVector,
        private readonly string $tag,
        private readonly string $aad = '',
        private readonly int $tagLength = 16,
        private readonly int $keySize = 256
    ) {
    }

    public function createStream(): StreamInterface
    {
        $plaintext = openssl_decrypt(
            (string)$this->cipherText,
            sprintf('aes-%d-gcm', $this->keySize),
            $this->key,
            OPENSSL_RAW_DATA,
            $this->initializationVector,
            $this->tag,
            $this->aad
        );

        if ($plaintext === false) {
            throw new DecryptionFailedException(
                "Unable to decrypt data with an initialization vector"
                . sprintf(' of %s using the aes-%d-gcm algorithm. Please', $this->initializationVector, $this->keySize)
                . " ensure you have provided a valid key size, initialization vector, and key."
            );
        }

        return Utils::streamFor($plaintext);
    }

    public function isWritable(): bool
    {
        return false;
    }
}
