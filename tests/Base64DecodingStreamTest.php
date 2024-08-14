<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\Utils;
use PHPUnit\Framework\TestCase;

class Base64DecodingStreamTest extends TestCase
{
    public const MB = 1048576;

    public function testEncodingShouldMatchBase64_DecodeOutput(): void
    {
        $stream = Utils::streamFor(base64_encode(random_bytes(1027)));
        $encodingStream = new Base64DecodingStream($stream);

        $this->assertSame(base64_decode($stream), (string) $encodingStream);
    }

    public function testShouldReportNullAsSize(): void
    {
        $encodingStream = new Base64DecodingStream(
            Utils::streamFor(base64_encode(random_bytes(1027)))
        );

        $this->assertNull($encodingStream->getSize());
    }

    public function testMemoryUsageRemainsConstant(): void
    {
        $memory = memory_get_usage();

        $stream = new Base64DecodingStream(
            new Base64EncodingStream(new RandomByteStream(124 * self::MB))
        );

        while (!$stream->eof()) {
            $stream->read(self::MB);
        }

        // Reading 1MB chunks should take 2MB
        $this->assertLessThanOrEqual($memory + 2 * self::MB, memory_get_usage());
    }
}
