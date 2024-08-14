<?php

namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class AesGcmDecryptingStreamTest extends TestCase
{
    use AesEncryptionStreamTestTrait;
    use ExceptionAssertions;

    public const KEY = 'key';


    #[DataProvider('cartesianJoinInputKeySizeProvider')]
    public function testStreamOutputSameAsOpenSSL(
        StreamInterface $plainTextStream,
        string $plainText,
        int $keySize
    ): void {
        $iv = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $additionalData = json_encode(['foo' => 'bar']);
        $tag = null;
        $cipherText = openssl_encrypt(
            $plainText,
            sprintf('aes-%d-gcm', $keySize),
            self::KEY,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $additionalData,
            16
        );
        $decryptingStream = new AesGcmDecryptingStream(
            Utils::streamFor($cipherText),
            self::KEY,
            $iv,
            $tag,
            $additionalData,
            16,
            $keySize
        );

        $this->assertSame((string)$decryptingStream, $plainText);
    }

    public function testIsNotWritable(): void
    {
        $iv = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $tag = null;
        $decryptingStream = new AesGcmDecryptingStream(
            Utils::streamFor(
                openssl_encrypt(
                    '1234',
                    'aes-256-gcm',
                    self::KEY,
                    OPENSSL_RAW_DATA,
                    $iv,
                    $tag
                )
            ),
            self::KEY,
            $iv,
            $tag
        );

        $this->assertFalse($decryptingStream->isWritable());
    }

    public function testEmitsErrorWhenDecryptionFails(): void
    {
        $initializationVector = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $keySize = 256;
        $expectedException = new DecryptionFailedException(
            "Unable to decrypt data with an initialization vector"
            . sprintf(' of %s using the aes-%d-gcm algorithm. Please', $initializationVector, $keySize)
            . " ensure you have provided a valid key size, initialization vector, and key."
        );

        $act = fn(): string => (string)new AesGcmDecryptingStream(
            new RandomByteStream(1024 * 1024),
            self::KEY,
            $initializationVector,
            'tag',
            keySize: $keySize
        );

        $this->assertException($act, $expectedException);
    }
}
