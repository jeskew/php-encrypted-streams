<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;

class HashingStreamTest extends TestCase
{
    /**
     * @dataProvider hashAlgorithmProvider
     *
     * @param string $algorithm
     */
    public function testHashShouldMatchThatReturnedByHashMethod($algorithm)
    {
        $toHash = random_bytes(1025);
        $instance = new HashingStream(
            Psr7\stream_for($toHash),
            null,
            function ($hash) use ($toHash, $algorithm) {
                $this->assertSame(hash($algorithm, $toHash, true), $hash);
            },
            $algorithm
        );

        $instance->getContents();

        $this->assertSame(
            hash($algorithm, $toHash, true),
            $instance->getHash()
        );
    }

    /**
     * @dataProvider hashAlgorithmProvider
     *
     * @param string $algorithm
     */
    public function testAuthenticatedHashShouldMatchThatReturnedByHashMethod(
        $algorithm
    ) {
        $key = 'secret key';
        $toHash = random_bytes(1025);
        $instance = new HashingStream(
            Psr7\stream_for($toHash),
            $key,
            function ($hash) use ($toHash, $key, $algorithm) {
                $this->assertSame(
                    hash_hmac($algorithm, $toHash, $key, true),
                    $hash
                );
            },
            $algorithm
        );

        $instance->getContents();

        $this->assertSame(
            hash_hmac($algorithm, $toHash, $key, true),
            $instance->getHash()
        );
    }

    /**
     * @dataProvider hashAlgorithmProvider
     *
     * @param string $algorithm
     */
    public function testHashingStreamsCanBeRewound($algorithm)
    {
        $key = 'secret key';
        $toHash = random_bytes(1025);
        $callCount = 0;
        $instance = new HashingStream(
            Psr7\stream_for($toHash),
            $key,
            function ($hash) use ($toHash, $key, $algorithm, &$callCount) {
                ++$callCount;
                $this->assertSame(
                    hash_hmac($algorithm, $toHash, $key, true),
                    $hash
                );
            },
            $algorithm
        );

        $instance->getContents();
        $instance->rewind();
        $instance->getContents();

        $this->assertSame(2, $callCount);
    }

    public function hashAlgorithmProvider()
    {
        return array_map(function ($algo) { return [$algo]; }, hash_algos());
    }

    /**
     * @expectedException \LogicException
     */
    public function testDoesNotSupportArbitrarySeeking()
    {
        $instance = new HashingStream(Psr7\stream_for(random_bytes(1025)));
        $instance->seek(1);
    }
}
