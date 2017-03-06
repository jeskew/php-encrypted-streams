<?php
namespace Jsq\EncryptionStreams;

class Ecb implements CipherMethod
{
    /**
     * @var int
     */
    private $keySize;

    /**
     * @param int $keySize
     */
    public function __construct($keySize = 256)
    {
        $this->keySize = $keySize;
    }

    public function getOpenSslName()
    {
        return "aes-{$this->keySize}-ecb";
    }

    public function getCurrentIv()
    {
        return '';
    }

    public function requiresPadding()
    {
        return true;
    }

    public function seek($offset, $whence = SEEK_SET) {}

    public function update($cipherTextBlock) {}
}