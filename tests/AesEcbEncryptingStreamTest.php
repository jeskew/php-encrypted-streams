<?php
namespace Jsq\EncryptionStreams;

use Psr\Http\Message\StreamInterface;

class AesEcbEncryptingStreamTest extends EncryptingStreamTest
{
    protected function getCipherMethod()
    {
        return 'aes-256-ecb';
    }

    protected function getStreamInstance(StreamInterface $source, $key, $iv, $keySize)
    {
        return new AesEbcEncryptingStream($source, $key, $keySize);
    }
}