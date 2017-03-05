<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use Psr\Http\Message\StreamInterface;

class AesEncryptingStreamTest extends \PHPUnit_Framework_TestCase
{

    const KB = 1024;
    const MB = 1048576;

    use AesEncryptionStreamTestTrait;

    /**
     * @dataProvider cartesianJoinInputCipherMethodKeySizeProvider
     *
     * @param StreamInterface $plainText
     * @param CipherMethod $iv
     * @param int $keySize
     */
    public function testStreamOutputSameAsOpenSSL(
        StreamInterface $plainText,
        CipherMethod $iv,
        $keySize
    ) {
        $plainText->rewind();
        $key = 'foo';

        $this->assertSame(
            (string) new AesEncryptingStream($plainText, $key, $iv, $keySize),
            openssl_encrypt(
                (string) $plainText,
                "AES-{$keySize}-{$iv->getName()}",
                $key,
                OPENSSL_RAW_DATA,
                $iv->getCurrentIv()
            )
        );
    }

    /**
     * @dataProvider cartesianJoinInputCipherMethodKeySizeProvider
     *
     * @param StreamInterface $plainText
     * @param CipherMethod $iv
     * @param int $keySize
     */
    public function testSupportsRewinding(
        StreamInterface $plainText,
        CipherMethod $iv,
        $keySize
    ) {
        $plainText->rewind();
        $cipherText = new AesEncryptingStream($plainText, 'foo', $iv, $keySize);
        $firstBytes = $cipherText->read($keySize * 2 + 3);
        $cipherText->rewind();
        $this->assertSame($firstBytes, $cipherText->read($keySize * 2 + 3));
    }

    /**
     * @dataProvider cartesianJoinInputCipherMethodKeySizeProvider
     *
     * @param StreamInterface $plainText
     * @param CipherMethod $iv
     * @param int $keySize
     */
    public function testAccuratelyReportsSizeOfCipherText(
        StreamInterface $plainText,
        CipherMethod $iv,
        $keySize
    ) {
        $plainText->rewind();
        $cipherText = new AesEncryptingStream($plainText, 'foo', $iv, $keySize);
        $this->assertSame($cipherText->getSize(), strlen((string) $cipherText));
    }

    /**
     * @dataProvider cartesianJoinIvKeySizeProvider
     *
     * @param CipherMethod $iv
     * @param int $keySize
     */
    public function testMemoryUsageRemainsConstant(
        CipherMethod $iv,
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

    public function testIsNotWritable()
    {
        $stream = new AesEncryptingStream(
            new RandomByteStream(124 * self::MB),
            'foo',
            new Cbc(random_bytes(openssl_cipher_iv_length('aes-256-cbc')))
        );

        $this->assertFalse($stream->isWritable());
    }

    /**
     * @dataProvider cipherMethodProvider
     *
     * @param CipherMethod $cipherMethod
     */
    public function testReturnsPaddedOrEmptyStringWhenSourceStreamEmpty(
        CipherMethod $cipherMethod
    ){
        $stream = new AesEncryptingStream(
            Psr7\stream_for(''),
            'foo',
            $cipherMethod
        );

        $paddingLength = $cipherMethod->requiresPadding() ? 16 : 0;

        $this->assertSame($paddingLength, strlen($stream->read(self::MB)));
        $this->assertSame($stream->read(self::MB), '');
    }

    /**
     * @dataProvider cipherMethodProvider
     *
     * @param CipherMethod $cipherMethod
     *
     * @expectedException \LogicException
     */
    public function testDoesNotSupportSeekingFromEnd(CipherMethod $cipherMethod)
    {
        $stream = new AesEncryptingStream(Psr7\stream_for('foo'), 'foo', $cipherMethod);

        $stream->seek(1, SEEK_END);
    }

    /**
     * @dataProvider seekableCipherMethodProvider
     *
     * @param CipherMethod $cipherMethod
     */
    public function testSupportsSeekingFromCurrentPosition(
        CipherMethod $cipherMethod
    ){
        $stream = new AesEncryptingStream(
            Psr7\stream_for(random_bytes(2 * self::MB)),
            'foo',
            $cipherMethod
        );

        $lastFiveBytes = substr($stream->read(self::MB), self::MB - 5);
        $stream->seek(-5, SEEK_CUR);
        $this->assertSame($lastFiveBytes, $stream->read(5));
    }
}
