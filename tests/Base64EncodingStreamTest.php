<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\Utils;
use GuzzleHttp\Psr7\PumpStream;
use PHPUnit\Framework\TestCase;

class Base64EncodingStreamTest extends TestCase
{
    public const MB = 1048576;

    public function testEncodingShouldMatchBase64_EncodeOutput(): void
    {
        $bytes = random_bytes(self::MB + 3);
        $encodingStream = new Base64EncodingStream(Utils::streamFor($bytes));

        $this->assertSame(base64_encode($bytes), (string) $encodingStream);
    }

    public function testShouldReportSizeOfEncodedStream(): void
    {
        $bytes = random_bytes(self::MB + 3);
        $encodingStream = new Base64EncodingStream(Utils::streamFor($bytes));

        $this->assertSame(strlen(base64_encode($bytes)), $encodingStream->getSize());
    }

    public function testShouldReportNullIfSizeOfSourceStreamUnknown(): void
    {
        $stream = new PumpStream(fn($length): string => random_bytes($length));
        $encodingStream = new Base64EncodingStream($stream);

        $this->assertNull($encodingStream->getSize());
    }

    public function testMemoryUsageRemainsConstant(): void
    {
        $memory = memory_get_usage();

        $stream = new Base64EncodingStream(new RandomByteStream(124 * self::MB));

        while (!$stream->eof()) {
            $stream->read(self::MB);
        }

        // Reading 1MB chunks should take 2MB
        $this->assertLessThanOrEqual($memory + 2 * self::MB, memory_get_usage());
    }
}
