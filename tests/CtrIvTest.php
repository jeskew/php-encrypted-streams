<?php
namespace Jsq\EncryptionStreams;

class CtrIvTest extends \PHPUnit_Framework_TestCase
{
    public function testShouldReportCipherMethodOfCTR()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-ctr')
        );
        $this->assertSame('CTR', (new CtrIv($ivString))->getCipherMethod());
    }

    public function testShouldReturnInitialIvStringForCurrentIvBeforeUpdate()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-ctr')
        );
        $iv = new CtrIv($ivString);

        $this->assertSame($ivString, $iv->getCurrentIv());
    }

    public function testUpdateShouldSetIncrementIvByNumberOfBlocksProcessed()
    {
        $ivString = $iv = hex2bin('deadbeefdeadbeefdeadbeefdeadbeee');
        $iv = new CtrIv($ivString);
        $cipherTextBlock = openssl_random_pseudo_bytes(CtrIv::BLOCK_SIZE);

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
        new CtrIv(openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-ctr') + 1
        ));
    }

    public function testShouldSupportSeekingToBeginning()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-ctr')
        );
        $iv = new CtrIv($ivString);
        $cipherTextBlock = openssl_random_pseudo_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(0);
        $this->assertSame($ivString, $iv->getCurrentIv());
    }

    public function testShouldSupportSeekingFromCurrentPosition()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-ctr')
        );
        $iv = new CtrIv($ivString);
        $cipherTextBlock = openssl_random_pseudo_bytes(1024);

        $iv->update($cipherTextBlock);
        $updatedIv = $iv->getCurrentIv();
        $iv->seek(CtrIv::BLOCK_SIZE, SEEK_CUR);
        $this->assertNotSame($updatedIv, $iv->getCurrentIv());
    }

    /**
     * @expectedException \LogicException
     */
    public function testShouldThrowWhenSeekOffsetNotDivisibleByBlockSize()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-ctr')
        );
        $iv = new CtrIv($ivString);
        $cipherTextBlock = openssl_random_pseudo_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(1);
    }

    /**
     * @expectedException \LogicException
     */
    public function testShouldThrowWhenNegativeSeekCurProvidedToSeek()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-ctr')
        );
        $iv = new CtrIv($ivString);
        $cipherTextBlock = openssl_random_pseudo_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(CtrIv::BLOCK_SIZE * -1, SEEK_CUR);
    }

    /**
     * @expectedException \LogicException
     */
    public function testShouldThrowWhenSeekEndProvidedToSeek()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-ctr')
        );
        $iv = new CtrIv($ivString);
        $cipherTextBlock = openssl_random_pseudo_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(0, SEEK_END);
    }
}
