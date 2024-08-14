<?php
namespace Jsq\EncryptionStreams;

use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\TestCase;

class CbcTest extends TestCase
{
    public function testShouldReportCipherMethodOfCBC(): void
    {
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $this->assertSame('aes-256-cbc', (new Cbc($ivString))->getOpenSslName());
    }

    public function testShouldReturnInitialIvStringForCurrentIvBeforeUpdate(): void
    {
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $iv = new Cbc($ivString);

        $this->assertSame($ivString, $iv->getCurrentIv());
    }

    public function testUpdateShouldSetCurrentIvToEndOfCipherBlock(): void
    {
        $ivLength = openssl_cipher_iv_length('aes-256-cbc');
        $ivString = random_bytes($ivLength);
        $iv = new Cbc($ivString);
        $cipherTextBlock = random_bytes(1024);

        $iv->update($cipherTextBlock);
        $this->assertNotSame($ivString, $iv->getCurrentIv());
        $this->assertSame(
            substr($cipherTextBlock, $ivLength * -1),
            $iv->getCurrentIv()
        );
    }

    public function testShouldThrowWhenIvOfInvalidLengthProvided(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new Cbc(random_bytes(openssl_cipher_iv_length('aes-256-cbc') + 1));
    }

    public function testShouldSupportSeekingToBeginning(): void
    {
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $iv = new Cbc($ivString);
        $cipherTextBlock = random_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(0);
        $this->assertSame($ivString, $iv->getCurrentIv());
    }

    public function testShouldThrowWhenNonZeroOffsetProvidedToSeek(): void
    {
        $this->expectException(LogicException::class);
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $iv = new Cbc($ivString);
        $cipherTextBlock = random_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(1);
    }

    public function testShouldThrowWhenSeekCurProvidedToSeek(): void
    {
        $this->expectException(LogicException::class);
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $iv = new Cbc($ivString);
        $cipherTextBlock = random_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(0, SEEK_CUR);
    }

    public function testShouldThrowWhenSeekEndProvidedToSeek(): void
    {
        $this->expectException(LogicException::class);
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
        $iv = new Cbc($ivString);
        $cipherTextBlock = random_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(0, SEEK_END);
    }
}
