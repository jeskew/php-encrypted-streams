<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;

class Base64DecodingStreamTest extends TestCase
{
    const MB = 1048576;

    public function testEncodingShouldMatchBase64_DecodeOutput()
    {
        $stream = Psr7\stream_for(base64_encode(random_bytes(1027)));
        $encodingStream = new Base64DecodingStream($stream);

        $this->assertSame(base64_decode($stream), (string) $encodingStream);
    }

    public function testShouldReportNullAsSize()
    {
        $encodingStream = new Base64DecodingStream(
            Psr7\stream_for(base64_encode(random_bytes(1027)))
        );

        $this->assertNull($encodingStream->getSize());
    }

    public function testMemoryUsageRemainsConstant()
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
