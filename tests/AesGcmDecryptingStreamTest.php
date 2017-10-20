<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class AesGcmDecryptingStreamTest extends TestCase
{
    use AesEncryptionStreamTestTrait;

    /**
     * @dataProvider cartesianJoinInputKeySizeProvider
     *
     * @param StreamInterface $plainText
     * @param int $keySize
     */
    public function testStreamOutputSameAsOpenSSL(
        StreamInterface $plainText,
        $keySize
    ) {
        $plainText->rewind();
        $plainText = (string) $plainText;
        $key = 'foo';
        $iv = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $additionalData = json_encode(['foo' => 'bar']);
        $tag = null;
        $cipherText = openssl_encrypt(
            $plainText,
            "aes-{$keySize}-gcm",
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $additionalData,
            16
        );

        $decryptingStream = new AesGcmDecryptingStream(
            Psr7\stream_for($cipherText),
            $key,
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
            'key',
            random_bytes(openssl_cipher_iv_length('aes-256-gcm')),
            'tag'
        );

        $this->assertFalse($decryptingStream->isWritable());
    }
}
