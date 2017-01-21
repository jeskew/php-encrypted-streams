<?php
namespace Jsq\EncryptionStreams;

use Psr\Http\Message\StreamInterface;

class AesCbcEncryptingStreamTest extends EncryptingStreamTest
{
    protected function getCipherMethod()
    {
        return 'aes-256-cbc';
    }

    protected function getStreamInstance(StreamInterface $source, $key, $iv, $keySize)
    {
        return new AesCbcEncryptingStream($source, $key, $iv, $keySize);
    }
}
