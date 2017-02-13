<?php
namespace Jsq\EncryptionStreams;

class CbcIvTest extends \PHPUnit_Framework_TestCase
{
    public function testShouldReportCipherMethodOfCBC()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-cbc')
        );
        $this->assertSame('CBC', (new CbcIv($ivString))->getCipherMethod());
    }

    public function testShouldReturnInitialIvStringForCurrentIvBeforeUpdate()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-cbc')
        );
        $iv = new CbcIv($ivString);

        $this->assertSame($ivString, $iv->getCurrentIv());
    }

    public function testUpdateShouldSetCurrentIvToEndOfCipherBlock()
    {
        $ivLength = openssl_cipher_iv_length('aes-128-cbc');
        $ivString = openssl_random_pseudo_bytes($ivLength);
        $iv = new CbcIv($ivString);
        $cipherTextBlock = openssl_random_pseudo_bytes(1024);

        $iv->update($cipherTextBlock);
        $this->assertNotSame($ivString, $iv->getCurrentIv());
        $this->assertSame(
            substr($cipherTextBlock, $ivLength * -1),
            $iv->getCurrentIv()
        );
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testShouldThrowWhenIvOfInvalidLengthProvided()
    {
        new CbcIv(openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-cbc') + 1
        ));
    }

    public function testShouldSupportSeekingToBeginning()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-cbc')
        );
        $iv = new CbcIv($ivString);
        $cipherTextBlock = openssl_random_pseudo_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(0);
        $this->assertSame($ivString, $iv->getCurrentIv());
    }

    /**
     * @expectedException \LogicException
     */
    public function testShouldThrowWhenNonZeroOffsetProvidedToSeek()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-cbc')
        );
        $iv = new CbcIv($ivString);
        $cipherTextBlock = openssl_random_pseudo_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(1);
    }

    /**
     * @expectedException \LogicException
     */
    public function testShouldThrowWhenSeekCurProvidedToSeek()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-cbc')
        );
        $iv = new CbcIv($ivString);
        $cipherTextBlock = openssl_random_pseudo_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(0, SEEK_CUR);
    }

    /**
     * @expectedException \LogicException
     */
    public function testShouldThrowWhenSeekEndProvidedToSeek()
    {
        $ivString = openssl_random_pseudo_bytes(
            openssl_cipher_iv_length('aes-128-cbc')
        );
        $iv = new CbcIv($ivString);
        $cipherTextBlock = openssl_random_pseudo_bytes(1024);

        $iv->update($cipherTextBlock);
        $iv->seek(0, SEEK_END);
    }
}
