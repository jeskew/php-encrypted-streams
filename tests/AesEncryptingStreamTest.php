<?php
namespace Jsq\EncryptionStreams;

use Psr\Http\Message\StreamInterface;

class AesEncryptingStreamTest extends \PHPUnit_Framework_TestCase
{

    const KB = 1024;
    const MB = 1048576;

    use AesEncryptionStreamTestTrait;

    /**
     * @dataProvider cartesianJoinInputIvKeySizeProvider
     *
     * @param StreamInterface $plainText
     * @param InitializationVector $iv
     * @param int $keySize
     */
    public function testStreamOutputSameAsOpenSSL(
        StreamInterface $plainText,
        InitializationVector $iv,
        $keySize
    ) {
        $plainText->rewind();
        $key = 'foo';

        $this->assertSame(
            (string) new AesEncryptingStream($plainText, $key, $iv, $keySize),
            openssl_encrypt(
                (string) $plainText,
                "AES-{$keySize}-{$iv->getCipherMethod()}",
                $key,
                OPENSSL_RAW_DATA,
                $iv->getCurrentIv()
            )
        );
    }

    /**
     * @dataProvider cartesianJoinInputIvKeySizeProvider
     *
     * @param StreamInterface $plainText
     * @param InitializationVector $iv
     * @param int $keySize
     */
    public function testSupportsRewinding(
        StreamInterface $plainText,
        InitializationVector $iv,
        $keySize
    ) {
        $plainText->rewind();
        $cipherText = new AesEncryptingStream($plainText, 'foo', $iv, $keySize);
        $firstBytes = $cipherText->read($keySize * 2 + 3);
        $cipherText->rewind();
        $this->assertSame($firstBytes, $cipherText->read($keySize * 2 + 3));
    }

    /**
     * @dataProvider cartesianJoinInputIvKeySizeProvider
     *
     * @param StreamInterface $plainText
     * @param InitializationVector $iv
     * @param int $keySize
     */
    public function testAccuratelyReportsSizeOfCipherText(
        StreamInterface $plainText,
        InitializationVector $iv,
        $keySize
    ) {
        $plainText->rewind();
        $cipherText = new AesEncryptingStream($plainText, 'foo', $iv, $keySize);
        $this->assertSame($cipherText->getSize(), strlen((string) $cipherText));
    }

    /**
     * @dataProvider cartesianJoinIvKeySizeProvider
     *
     * @param InitializationVector $iv
     * @param int $keySize
     */
    public function testMemoryUsageRemainsConstant(
        InitializationVector $iv,
        $keySize
    ) {
        $memory = memory_get_usage();

        $stream = new AesDecryptingStream(
            new RandomByteStream(124 * self::MB),
            'foo',
            $iv,
            $keySize
        );

        while (!$stream->eof()) {
            $stream->read(self::MB);
        }

        $this->assertLessThanOrEqual($memory + self::MB, memory_get_usage());
    }
}
