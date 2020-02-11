<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class AesDecryptingStreamTest extends TestCase
{
    const KB = 1024;
    const MB = 1048576;
    const KEY = 'foo';

    use AesEncryptionStreamTestTrait;

    /**
     * @dataProvider cartesianJoinInputCipherMethodProvider
     *
     * @param StreamInterface $plainTextStream
     * @param string $plainText
     * @param CipherMethod $iv
     */
    public function testStreamOutputSameAsOpenSSL(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ) {
        $cipherText = openssl_encrypt(
            $plainText,
            $iv->getOpenSslName(),
            self::KEY,
            OPENSSL_RAW_DATA,
            $iv->getCurrentIv()
        );

        $this->assertSame(
            (string) new AesDecryptingStream(Psr7\stream_for($cipherText), self::KEY, $iv),
            $plainText
        );
    }

    /**
     * @dataProvider cartesianJoinInputCipherMethodProvider
     *
     * @param StreamInterface $plainTextStream
     * @param string $plainText
     * @param CipherMethod $iv
     */
    public function testReportsSizeOfPlaintextWherePossible(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ) {
        $cipherText = openssl_encrypt(
            $plainText,
            $iv->getOpenSslName(),
            self::KEY,
            OPENSSL_RAW_DATA,
            $iv->getCurrentIv()
        );
        $deciphered = new AesDecryptingStream(
            Psr7\stream_for($cipherText),
            self::KEY,
            $iv
        );

        if ($iv->requiresPadding()) {
            $this->assertNull($deciphered->getSize());
        } else {
            $this->assertSame(strlen($plainText), $deciphered->getSize());
        }
    }

    /**
     * @dataProvider cartesianJoinInputCipherMethodProvider
     *
     * @param StreamInterface $plainTextStream
     * @param string $plainText
     * @param CipherMethod $iv
     */
    public function testSupportsReadingBeyondTheEndOfTheStream(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ) {
        $cipherText = openssl_encrypt(
            $plainText,
            $iv->getOpenSslName(),
            self::KEY,
            OPENSSL_RAW_DATA,
            $iv->getCurrentIv()
        );
        $deciphered = new AesDecryptingStream(Psr7\stream_for($cipherText), self::KEY, $iv);
        $read = $deciphered->read(strlen($plainText) + AesDecryptingStream::BLOCK_SIZE);
        $this->assertSame($plainText, $read);
    }

    /**
     * @dataProvider cartesianJoinInputCipherMethodProvider
     *
     * @param StreamInterface $plainTextStream
     * @param string $plainText
     * @param CipherMethod $iv
     */
    public function testSupportsRewinding(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ) {
        $cipherText = openssl_encrypt(
            $plainText,
            $iv->getOpenSslName(),
            self::KEY,
            OPENSSL_RAW_DATA,
            $iv->getCurrentIv()
        );
        $deciphered = new AesDecryptingStream(Psr7\stream_for($cipherText), self::KEY, $iv);
        $firstBytes = $deciphered->read(256 * 2 + 3);
        $deciphered->rewind();
        $this->assertSame($firstBytes, $deciphered->read(256 * 2 + 3));
    }

    /**
     * @dataProvider cipherMethodProvider
     *
     * @param CipherMethod $iv
     */
    public function testMemoryUsageRemainsConstant(CipherMethod $iv)
    {
        $memory = memory_get_usage();

        $cipherStream = new AesEncryptingStream(new RandomByteStream(124 * self::MB), self::KEY, clone $iv);
        $stream = new AesDecryptingStream($cipherStream, self::KEY, clone $iv);

        while (!$stream->eof()) {
            $stream->read(self::MB);
        }

        // Reading 1MB chunks should take 2MB
        $this->assertLessThanOrEqual($memory + 2 * self::MB, memory_get_usage());
    }

    public function testIsNotWritable()
    {
        $stream = new AesDecryptingStream(
            new RandomByteStream(124 * self::MB),
            'foo',
            new Cbc(random_bytes(openssl_cipher_iv_length('aes-256-cbc')))
        );

        $this->assertFalse($stream->isWritable());
    }

    /**
     * @expectedException \LogicException
     */
    public function testDoesNotSupportArbitrarySeeking()
    {
        $stream = new AesDecryptingStream(
            new RandomByteStream(124 * self::MB),
            'foo',
            new Cbc(random_bytes(openssl_cipher_iv_length('aes-256-cbc')))
        );

        $stream->seek(1);
    }

    /**
     * @dataProvider cipherMethodProvider
     *
     * @param CipherMethod $cipherMethod
     */
    public function testReturnsEmptyStringWhenSourceStreamEmpty(
        CipherMethod $cipherMethod
    ) {
        $stream = new AesDecryptingStream(
            new AesEncryptingStream(Psr7\stream_for(''), self::KEY, clone $cipherMethod),
            self::KEY,
            $cipherMethod
        );

        $this->assertEmpty($stream->read(self::MB));
        $this->assertSame($stream->read(self::MB), '');
    }

    public function testEmitsErrorWhenDecryptionFails()
    {
        // Capture the error in a custom handler to avoid PHPUnit's error trap
        set_error_handler(function ($_, $message) use (&$error) {
            $error = $message;
        });

        // Trigger a decryption failure by attempting to decrypt gibberish
        // Not all cipher methods will balk (CTR, for example, will simply
        // decrypt gibberish into gibberish), so CBC is used.
        $_ = (string) new AesDecryptingStream(new RandomByteStream(self::MB), self::KEY,
            new Cbc(random_bytes(openssl_cipher_iv_length('aes-256-cbc'))));

        $this->assertRegExp("/DecryptionFailedException: Unable to decrypt/", $error);
    }
}
