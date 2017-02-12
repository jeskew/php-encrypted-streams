<?php
namespace Jsq\EncryptionStreams;

use Psr\Http\Message\StreamInterface;

class AesCbcDecryptingStreamTest extends DecryptingStreamTest
{
    protected function getCipherMethod()
    {
        return 'aes-256-cbc';
    }

    protected function getStreamInstance(StreamInterface $source, $key, $iv, $keySize)
    {
        return new AesDecryptingStream($source, $key, new CbcIv($iv), $keySize);
    }
}
