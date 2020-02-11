<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class AesGcmEncryptingStreamTest extends TestCase
{
    use AesEncryptionStreamTestTrait;

    const KEY = 'foo';

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
        $encryptingStream = new AesGcmEncryptingStream(
            $plainTextStream,
            self::KEY,
            $iv,
            $additionalData,
            16,
            $keySize
        );

        $this->assertSame(
            (string) $encryptingStream,
            openssl_encrypt(
                $plainText,
                "aes-{$keySize}-gcm",
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

    public function testIsNotWritable()
    {
        $decryptingStream = new AesGcmEncryptingStream(
            Psr7\stream_for(''),
            self::KEY,
            random_bytes(openssl_cipher_iv_length('aes-256-gcm'))
        );

        $this->assertFalse($decryptingStream->isWritable());
    }

    public function testEmitsErrorWhenEncryptionFails()
    {
        // Capture the error in a custom handler to avoid PHPUnit's error trap
        set_error_handler(function ($_, $message) use (&$error) {
            $error = $message;
        });

        // Trigger a decryption failure by attempting to decrypt gibberish
        $_ = (string) new AesGcmEncryptingStream(
            new RandomByteStream(1024 * 1024),
            self::KEY,
            random_bytes(openssl_cipher_iv_length('aes-256-gcm')),
            'tag',
            16,
            157
        );

        $this->assertRegExp("/EncryptionFailedException: Unable to encrypt/", $error);
    }
}
