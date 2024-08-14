<?php

namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\Utils;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

class AesEncryptingStreamTest extends TestCase
{
    public const KB = 1024;

    public const MB = 1048576;

    public const KEY = 'foo';

    use AesEncryptionStreamTestTrait;
    use ExceptionAssertions;

    #[DataProvider('cartesianJoinInputCipherMethodProvider')]
    public function testStreamOutputSameAsOpenSSL(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ): void {
        $this->assertSame(
            openssl_encrypt(
                $plainText,
                $iv->getOpenSslName(),
                self::KEY,
                OPENSSL_RAW_DATA,
                $iv->getCurrentIv()
            ),
            (string)new AesEncryptingStream(
                $plainTextStream,
                self::KEY,
                $iv
            )
        );
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
        $cipherStream = new AesEncryptingStream($plainTextStream, self::KEY, $iv);
        $this->assertSame($cipherText, $cipherStream->read(strlen($plainText) + self::MB));
        $this->assertSame('', $cipherStream->read(self::MB));
    }

    #[DataProvider('cartesianJoinInputCipherMethodProvider')]
    public function testSupportsRewinding(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ): void {
        if (!$plainTextStream->isSeekable()) {
            $this->markTestSkipped('Cannot rewind encryption streams whose plaintext is not seekable');
        } else {
            $cipherText = new AesEncryptingStream($plainTextStream, 'foo', $iv);
            $firstBytes = $cipherText->read(256 * 2 + 3);
            $cipherText->rewind();
            $this->assertSame($firstBytes, $cipherText->read(256 * 2 + 3));
        }
    }

    #[DataProvider('cartesianJoinInputCipherMethodProvider')]
    public function testAccuratelyReportsSizeOfCipherText(
        StreamInterface $plainTextStream,
        string $plainText,
        CipherMethod $iv
    ): void {
        if ($plainTextStream->getSize() === null) {
            $this->markTestSkipped('Cannot read size of ciphertext stream when plaintext stream size is unknown');
        } else {
            $cipherText = new AesEncryptingStream($plainTextStream, 'foo', $iv);
            $this->assertSame($cipherText->getSize(), strlen((string)$cipherText));
        }
    }

    #[DataProvider('cipherMethodProvider')]
    public function testMemoryUsageRemainsConstant(CipherMethod $cipherMethod): void
    {
        $memory = memory_get_usage();

        $stream = new AesEncryptingStream(
            new RandomByteStream(124 * self::MB),
            'foo',
            $cipherMethod
        );

        while (!$stream->eof()) {
            $stream->read(self::MB);
        }

        // Reading 1MB chunks should take 2MB
        $this->assertLessThanOrEqual($memory + 2 * self::MB, memory_get_usage());
    }

    public function testIsNotWritable(): void
    {
        $stream = new AesEncryptingStream(
            new RandomByteStream(124 * self::MB),
            'foo',
            new Cbc(random_bytes(openssl_cipher_iv_length('aes-256-cbc')))
        );

        $this->assertFalse($stream->isWritable());
    }

    #[DataProvider('cipherMethodProvider')]
    public function testReturnsPaddedOrEmptyStringWhenSourceStreamEmpty(
        CipherMethod $cipherMethod
    ): void {
        $stream = new AesEncryptingStream(
            Utils::streamFor(''),
            'foo',
            $cipherMethod
        );

        $paddingLength = $cipherMethod->requiresPadding() ? AesEncryptingStream::BLOCK_SIZE : 0;

        $this->assertSame($paddingLength, strlen($stream->read(self::MB)));
        $this->assertSame($stream->read(self::MB), '');
    }

    #[DataProvider('cipherMethodProvider')]
    public function testDoesNotSupportSeekingFromEnd(CipherMethod $cipherMethod): void
    {
        $this->expectException(LogicException::class);
        $stream = new AesEncryptingStream(Utils::streamFor('foo'), 'foo', $cipherMethod);

        $stream->seek(1, SEEK_END);
    }

    #[DataProvider('seekableCipherMethodProvider')]
    public function testSupportsSeekingFromCurrentPosition(
        CipherMethod $cipherMethod
    ): void {
        $stream = new AesEncryptingStream(
            Utils::streamFor(random_bytes(2 * self::MB)),
            'foo',
            $cipherMethod
        );

        $lastFiveBytes = substr($stream->read(self::MB), self::MB - 5);
        $stream->seek(-5, SEEK_CUR);
        $this->assertSame($lastFiveBytes, $stream->read(5));
    }

    public function testEmitsErrorWhenEncryptionFails(): void
    {
        $cipherMethod = new class implements CipherMethod {
            public function getCurrentIv(): string
            {
                return 'iv';
            }

            public function getOpenSslName(): string
            {
                return 'aes-157-cbd';
            }

            public function requiresPadding(): bool
            {
                return false;
            }

            public function update(string $cipherTextBlock): void
            {
            }

            public function seek(int $offset, int $whence = SEEK_SET): void
            {
            }
        };
        $expectedException = new EncryptionFailedException(
            "Unable to encrypt data with an initialization vector"
            . sprintf(' of %s using the %s', $cipherMethod->getCurrentIv(), $cipherMethod->getOpenSslName())
            . " algorithm. Please ensure you have provided a valid algorithm and initialization vector."
        );

        // Trigger an openssl error by supplying an invalid key size
        $act = fn(): string => @(string)new AesEncryptingStream(
            new RandomByteStream(self::MB), self::KEY,
            $cipherMethod
        );

        $this->assertException($act, $expectedException);
    }
}
