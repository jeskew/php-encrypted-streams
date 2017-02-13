<?php
namespace Jsq\EncryptionStreams;

class EcbIv implements InitializationVector
{
    public function getCipherMethod()
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

    public function supportsArbitrarySeeking()
    {
        return true;
    }

    public function update($cipherTextBlock) {}
}