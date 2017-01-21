<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;

abstract class DecryptingStreamTest extends EncryptionStreamTest
{
    /**
     * @dataProvider plainTextProvider
     *
     * @param StreamInterface $plainText
     */
    public function testStreamOutputSameAsOpenSSL(StreamInterface $plainText) {
        $key = 'foo';
        $iv = $this->generateIv();
        $cipherText = openssl_encrypt(
            (string) $plainText,
            $this->getCipherMethod(),
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        $this->assertSame(
            (string) $this->getStreamInstance(Psr7\stream_for($cipherText), $key, $iv, 256),
            (string) $plainText
        );
    }
}