<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class AesGcmDecryptingStreamTest extends TestCase
{
    use AesEncryptionStreamTestTrait;

    const KEY = 'key';

    /**
     * @dataProvider cartesianJoinInputKeySizeProvider
     *
     * @param StreamInterface $plainTextStream
     * @param string $plainText
     * @param int $keySize
     */
    public function testStreamOutputSameAsOpenSSL(StreamInterface $plainTextStream, string $plainText, $keySize) {
        $iv = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $additionalData = json_encode(['foo' => 'bar']);
        $tag = null;
        $cipherText = openssl_encrypt(
            $plainText,
            "aes-{$keySize}-gcm",
            self::KEY,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $additionalData,
            16
        );

        $decryptingStream = new AesGcmDecryptingStream(
            Psr7\stream_for($cipherText),
            self::KEY,
            $iv,
            $tag,
            $additionalData,
            16,
            $keySize
        );

        $this->assertSame((string) $decryptingStream, $plainText);
    }

    public function testIsNotWritable()
    {
        $decryptingStream = new AesGcmDecryptingStream(
            Psr7\stream_for(''),
            self::KEY,
            random_bytes(openssl_cipher_iv_length('aes-256-gcm')),
            'tag'
        );

        $this->assertFalse($decryptingStream->isWritable());
    }

    public function testEmitsErrorWhenDecryptionFails()
    {
        // Capture the error in a custom handler to avoid PHPUnit's error trap
        set_error_handler(function ($_, $message) use (&$error) {
            $error = $message;
        });

        // Trigger a decryption failure by attempting to decrypt gibberish
        $_ = (string) new AesGcmDecryptingStream(
            new RandomByteStream(1024 * 1024),
            self::KEY,
            random_bytes(openssl_cipher_iv_length('aes-256-gcm')),
            'tag'
        );

        $this->assertRegExp("/DecryptionFailedException: Unable to decrypt/", $error);
    }
}
