<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\Utils;
use GuzzleHttp\Psr7\PumpStream;
use PHPUnit\Framework\TestCase;

class HexEncodingStreamTest extends TestCase
{
    public const MB = 1048576;

    public function testEncodingShouldMatchBin2HexOutput(): void
    {
        $bytes = random_bytes(self::MB + 3);
        $encodingStream = new HexEncodingStream(Utils::streamFor($bytes));

        $this->assertSame(bin2hex($bytes), (string) $encodingStream);
    }

    public function testShouldReportSizeOfEncodedStream(): void
    {
        $bytes = random_bytes(self::MB + 3);
        $encodingStream = new HexEncodingStream(Utils::streamFor($bytes));

        $this->assertSame(strlen(bin2hex($bytes)), $encodingStream->getSize());
    }

    public function testShouldReportNullIfSizeOfSourceStreamUnknown(): void
    {
        $stream = new PumpStream(fn($length): string => random_bytes($length));
        $encodingStream = new HexEncodingStream($stream);

        $this->assertNull($encodingStream->getSize());
    }

    public function testMemoryUsageRemainsConstant(): void
    {
        $memory = memory_get_usage();

        $stream = new HexEncodingStream(new RandomByteStream(124 * self::MB));

        while (!$stream->eof()) {
            $stream->read(self::MB);
        }

        // Reading 1MB chunks should take 2MB
        $this->assertLessThanOrEqual($memory + 2 * self::MB, memory_get_usage());
    }
}
