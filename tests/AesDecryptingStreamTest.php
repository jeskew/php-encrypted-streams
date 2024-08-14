<?php

namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\Utils;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class AesDecryptingStreamTest extends TestCase
{
    use ExceptionAssertions;

    public const KB = 1024;

    public const MB = 1048576;

    public const KEY = 'foo';

    use AesEncryptionStreamTestTrait;


    #[DataProvider('cartesianJoinInputCipherMethodProvider')]
    public function testStreamOutputSameAsOpenSSL(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ): void {
        $cipherText = openssl_encrypt(
            $plainText,
            $iv->getOpenSslName(),
            self::KEY,
            OPENSSL_RAW_DATA,
            $iv->getCurrentIv()
        );

        $this->assertSame(
            (string)new AesDecryptingStream(Utils::streamFor($cipherText), self::KEY, $iv),
            $plainText
        );
    }


    #[DataProvider('cartesianJoinInputCipherMethodProvider')]
    public function testReportsSizeOfPlaintextWherePossible(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ): void {
        $cipherText = openssl_encrypt(
            $plainText,
            $iv->getOpenSslName(),
            self::KEY,
            OPENSSL_RAW_DATA,
            $iv->getCurrentIv()
        );
        $deciphered = new AesDecryptingStream(
            Utils::streamFor($cipherText),
            self::KEY,
            $iv
        );

        if ($iv->requiresPadding()) {
            $this->assertNull($deciphered->getSize());
        } else {
            $this->assertSame(strlen($plainText), $deciphered->getSize());
        }
    }


    #[DataProvider('cartesianJoinInputCipherMethodProvider')]
    public function testSupportsReadingBeyondTheEndOfTheStream(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ): void {
        $cipherText = openssl_encrypt(
            $plainText,
            $iv->getOpenSslName(),
            self::KEY,
            OPENSSL_RAW_DATA,
            $iv->getCurrentIv()
        );
        $deciphered = new AesDecryptingStream(Utils::streamFor($cipherText), self::KEY, $iv);
        $read = $deciphered->read(strlen($plainText) + AesDecryptingStream::BLOCK_SIZE);
        $this->assertSame($plainText, $read);
    }


    #[DataProvider('cartesianJoinInputCipherMethodProvider')]
    public function testSupportsRewinding(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ): void {
        $cipherText = openssl_encrypt(
            $plainText,
            $iv->getOpenSslName(),
            self::KEY,
            OPENSSL_RAW_DATA,
            $iv->getCurrentIv()
        );
        $deciphered = new AesDecryptingStream(Utils::streamFor($cipherText), self::KEY, $iv);
        $firstBytes = $deciphered->read(256 * 2 + 3);
        $deciphered->rewind();
        $this->assertSame($firstBytes, $deciphered->read(256 * 2 + 3));
    }

    #[DataProvider('cipherMethodProvider')]
    public function testMemoryUsageRemainsConstant(CipherMethod $iv): void
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

    public function testIsNotWritable(): void
    {
        $stream = new AesDecryptingStream(
            new RandomByteStream(124 * self::MB),
            'foo',
            new Cbc(random_bytes(openssl_cipher_iv_length('aes-256-cbc')))
        );

        $this->assertFalse($stream->isWritable());
    }

    public function testDoesNotSupportArbitrarySeeking(): void
    {
        $this->expectException(LogicException::class);
        $stream = new AesDecryptingStream(
            new RandomByteStream(124 * self::MB),
            'foo',
            new Cbc(random_bytes(openssl_cipher_iv_length('aes-256-cbc')))
        );

        $stream->seek(1);
    }

    #[DataProvider('cipherMethodProvider')]
    public function testReturnsEmptyStringWhenSourceStreamEmpty(
        CipherMethod $cipherMethod
    ): void {
        $stream = new AesDecryptingStream(
            new AesEncryptingStream(Utils::streamFor(''), self::KEY, clone $cipherMethod),
            self::KEY,
            $cipherMethod
        );

        $this->assertEmpty($stream->read(self::MB));
        $this->assertSame($stream->read(self::MB), '');
    }

    public function testEmitsErrorWhenDecryptionFails(): void
    {
        // Capture the error in a custom handler to avoid PHPUnit's error trap
        $cipherText = Utils::streamFor(random_bytes(self::MB)); // not big fan of random in test but ok...
        $cipherMethod = new Cbc(random_bytes(openssl_cipher_iv_length('aes-256-cbc')));
        $expectedException = new DecryptionFailedException(
            sprintf('Unable to decrypt %s with an initialization vector', $cipherText)
            . sprintf(' of %s using the %s', $cipherMethod->getCurrentIv(), $cipherMethod->getOpenSslName())
            . " algorithm. Please ensure you have provided the correct algorithm, initialization vector, and key."
        );

        // Trigger a decryption failure by attempting to decrypt gibberish
        // Not all cipher methods will balk (CTR, for example, will simply
        // decrypt gibberish into gibberish), so CBC is used.
        $act = fn(): string => (string)new AesDecryptingStream($cipherText, self::KEY, $cipherMethod);

        $this->assertException($act, $expectedException);
    }
}
