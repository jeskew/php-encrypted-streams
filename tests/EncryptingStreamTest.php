<?php
namespace Jsq\EncryptionStreams;

use Psr\Http\Message\StreamInterface;

abstract class EncryptingStreamTest extends EncryptionStreamTest
{
    /**
     * @dataProvider plainTextProvider
     *
     * @param StreamInterface $plainText
     */
    public function testStreamOutputSameAsOpenSSL(StreamInterface $plainText) {
        $key = 'foo';
        $iv = $this->generateIv();

        $this->assertSame(
            (string) $this->getStreamInstance($plainText, $key, $iv, 256),
            openssl_encrypt(
                (string) $plainText,
                $this->getCipherMethod(),
                $key,
                OPENSSL_RAW_DATA,
                $iv
            )
        );
    }
}