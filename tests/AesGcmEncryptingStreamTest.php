<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class AesGcmEncryptingStreamTest extends TestCase
{
    use AesEncryptionStreamTestTrait;

    /**
     * @dataProvider cartesianJoinInputKeySizeProvider
     *
     * @param StreamInterface $plainTextStream
     * @param string $plainText
     * @param int $keySize
     */
    public function testStreamOutputSameAsOpenSSL(StreamInterface $plainTextStream, string $plainText, $keySize) {
        $key = 'foo';
        $iv = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $additionalData = json_encode(['foo' => 'bar']);
        $tag = null;
        $encryptingStream = new AesGcmEncryptingStream(
            $plainTextStream,
            $key,
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
                $key,
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
            'key',
            random_bytes(openssl_cipher_iv_length('aes-256-gcm'))
        );

        $this->assertFalse($decryptingStream->isWritable());
    }
}
