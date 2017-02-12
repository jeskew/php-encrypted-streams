<?php
namespace Jsq\EncryptionStreams;

use Psr\Http\Message\StreamInterface;

class AesCtrEncryptingStreamTest extends DecryptingStreamTest
{
    protected function getCipherMethod()
    {
        return 'aes-256-ctr';
    }

    protected function getStreamInstance(StreamInterface $source, $key, $iv, $keySize)
    {
        return new AesEncryptingStream($source, $key, new CtrIv($iv), $keySize);
    }
}