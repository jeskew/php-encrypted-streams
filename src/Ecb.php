<?php
namespace Jsq\EncryptionStreams;

class Ecb implements CipherMethod
{
    public function getName()
    {
        return 'ECB';
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