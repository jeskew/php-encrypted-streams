<?php
namespace Jsq\EncryptionStreams;

use Psr\Http\Message\StreamInterface;

class AesEcbDecryptingStreamTest extends DecryptingStreamTest
{
    protected function getCipherMethod()
    {
        return 'aes-256-ecb';
    }

    protected function getStreamInstance(StreamInterface $source, $key, $iv, $keySize)
    {
        return new AesDecryptingStream($source, $key, new EcbIv(), $keySize);
    }
}
