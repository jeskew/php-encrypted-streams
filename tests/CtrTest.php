<?php
namespace Jsq\EncryptionStreams;

use PHPUnit\Framework\TestCase;

class CtrTest extends TestCase
{
    public function testShouldReportCipherMethodOfCTR()
    {
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-ctr'));
        $this->assertSame('aes-256-ctr', (new Ctr($ivString))->getOpenSslName());
    }

    public function testShouldReturnInitialIvStringForCurrentIvBeforeUpdate()
    {
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-ctr'));
        $iv = new Ctr($ivString);

        $this->assertSame($ivString, $iv->getCurrentIv());
    }

    public function testUpdateShouldSetIncrementIvByNumberOfBlocksProcessed()
    {
        $ivString = $iv = hex2bin('deadbeefdeadbeefdeadbeefdeadbeee');
        $iv = new Ctr($ivString);
        $cipherTextBlock = random_bytes(Ctr::BLOCK_SIZE);

        $iv->update($cipherTextBlock);
        $this->assertNotSame($ivString, $iv->getCurrentIv());
        $this->assertSame(
            hex2bin('deadbeefdeadbeefdeadbeefdeadbeef'),
            $iv->getCurrentIv()
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testShouldThrowWhenIvOfInvalidLengthProvided()
    {
        new Ctr(random_bytes(openssl_cipher_iv_length('aes-256-ctr') + 1));
    }

    public function testShouldSupportSeekingToBeginning()
    {
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-ctr'));
        $iv = new Ctr($ivString);
        $cipherTextBlock = random_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(0);
        $this->assertSame($ivString, $iv->getCurrentIv());
    }

    public function testShouldSupportSeekingFromCurrentPosition()
    {
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-ctr'));
        $iv = new Ctr($ivString);
        $cipherTextBlock = random_bytes(1024);

        $iv->update($cipherTextBlock);
        $updatedIv = $iv->getCurrentIv();
        $iv->seek(Ctr::BLOCK_SIZE, SEEK_CUR);
        $this->assertNotSame($updatedIv, $iv->getCurrentIv());
    }

    /**
     * @expectedException \LogicException
     */
    public function testShouldThrowWhenSeekOffsetNotDivisibleByBlockSize()
    {
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-ctr'));
        $iv = new Ctr($ivString);
        $cipherTextBlock = random_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(1);
    }

    /**
     * @expectedException \LogicException
     */
    public function testShouldThrowWhenNegativeSeekCurProvidedToSeek()
    {
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-ctr'));
        $iv = new Ctr($ivString);
        $cipherTextBlock = random_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(Ctr::BLOCK_SIZE * -1, SEEK_CUR);
    }

    /**
     * @expectedException \LogicException
     */
    public function testShouldThrowWhenSeekEndProvidedToSeek()
    {
        $ivString = random_bytes(openssl_cipher_iv_length('aes-256-ctr'));
        $iv = new Ctr($ivString);
        $cipherTextBlock = random_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(0, SEEK_END);
    }
}
