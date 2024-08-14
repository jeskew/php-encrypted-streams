<?php

namespace Jsq\EncryptionStreams;

use PHPUnit\Framework\Attributes\DataProvider;
use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class AesGcmEncryptingStreamTest extends TestCase
{
    use AesEncryptionStreamTestTrait;
    use ExceptionAssertions;
    public const KEY = 'foo';

    #[DataProvider('cartesianJoinInputKeySizeProvider')]
    public function testStreamOutputSameAsOpenSSL(StreamInterface $plainTextStream, string $plainText, int $keySize): void
    {
        $iv = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $additionalData = json_encode(['foo' => 'bar']);
        $tag = null;
        $encryptingStream = new AesGcmEncryptingStream(
            $plainTextStream,
            self::KEY,
            $iv,
            $additionalData,
            16,
            $keySize
        );

        $this->assertSame(
            (string)$encryptingStream,
            openssl_encrypt(
                $plainText,
                sprintf('aes-%d-gcm', $keySize),
                self::KEY,
                OPENSSL_RAW_DATA,
                $iv,
                $tag,
                $additionalData,
                16
            )
        );

        $this->assertSame($tag, $encryptingStream->getTag());
    }

    public function testIsNotWritable(): void
    {
        $decryptingStream = new AesGcmEncryptingStream(
            Utils::streamFor(''),
            self::KEY,
            random_bytes(openssl_cipher_iv_length('aes-256-gcm'))
        );

        $this->assertFalse($decryptingStream->isWritable());
    }

    public function testEmitsErrorWhenEncryptionFails(): void
    {
        $initializationVector = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $keySize = 157;
        $expectedException = new EncryptionFailedException(
            "Unable to encrypt data with an initialization vector"
            . sprintf(' of %s using the aes-%d-gcm algorithm. Please', $initializationVector, $keySize)
            . " ensure you have provided a valid key size and initialization vector."
        );

        // Trigger a decryption failure by attempting to decrypt gibberish
        $act = fn(): string => @(string)new AesGcmEncryptingStream(
            new RandomByteStream(1024 * 1024),
            self::KEY,
            $initializationVector,
            'tag',
            16,
            $keySize
        );

        $this->assertException($act, $expectedException);
    }
}
