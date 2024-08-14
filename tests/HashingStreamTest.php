<?php

namespace Jsq\EncryptionStreams;

use PHPUnit\Framework\Attributes\DataProvider;
use GuzzleHttp\Psr7\Utils;
use LogicException;
use PHPUnit\Framework\TestCase;
use ValueError;

class HashingStreamTest extends TestCase
{
    #[DataProvider('hashAlgorithmProvider')]
    public function testHashShouldMatchThatReturnedByHashMethod(string $algorithm): void
    {
        $toHash = random_bytes(1025);
        $instance = new HashingStream(
            Utils::streamFor($toHash),
            null,
            function ($hash) use ($toHash, $algorithm): void {
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

    #[DataProvider('hmacAlgorithmProvider')]
    public function testAuthenticatedHashShouldMatchThatReturnedByHashMethod(
        string $algorithm
    ): void {
        $key = 'secret key';
        $toHash = random_bytes(1025);
        $instance = new HashingStream(
            Utils::streamFor($toHash),
            $key,
            function ($hash) use ($toHash, $key, $algorithm): void {
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

    #[DataProvider('hmacAlgorithmProvider')]
    public function testHashingStreamsCanBeRewound(string $algorithm): void
    {
        $key = 'secret key';
        $toHash = random_bytes(1025);
        $callCount = 0;
        $instance = new HashingStream(
            Utils::streamFor($toHash),
            $key,
            function ($hash) use ($toHash, $key, $algorithm, &$callCount): void {
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

    /**
     * @return non-falsy-string[][]
     */
    public static function hmacAlgorithmProvider(): array
    {
        $cryptoHashes = [];
        foreach (hash_algos() as $algo) {
            // As of PHP 8.0, feeding a non-cryptographic hashing
            // algorithm to `hash_init` will throw ValueError exception.
            // cf https://www.php.net/manual/en/function.hash-hmac.php
            try {
                if (@hash_hmac($algo, 'data', 'secret key') !== '0') {
                    $cryptoHashes [] = [$algo];
                }
            } catch (ValueError) {
            }
        }

        return $cryptoHashes;
    }

    public static function hashAlgorithmProvider(): array
    {
        return array_map(fn($algo): array => [$algo], hash_algos());
    }

    public function testDoesNotSupportArbitrarySeeking(): void
    {
        $this->expectException(LogicException::class);
        $instance = new HashingStream(Utils::streamFor(random_bytes(1025)));
        $instance->seek(1);
    }
}
