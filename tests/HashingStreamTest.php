<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;

class HashingStreamTest extends \PHPUnit_Framework_TestCase
{
    public function testHashShouldMatchThatReturnedByHashMethod()
    {
        $key = 'secret key';
        $toHash = openssl_random_pseudo_bytes(1024);
        $instance = new HashingStream(
            Psr7\stream_for($toHash),
            $key,
            function ($hash) use ($toHash, $key) {
                $this->assertSame(hash_hmac('sha256', $toHash, $key, true), $hash);
            },
            'sha256'
        );

        $instance->getContents();

        $this->assertSame(
            hash_hmac('sha256', $toHash, $key, true),
            $instance->getHash()
        );
    }
}
