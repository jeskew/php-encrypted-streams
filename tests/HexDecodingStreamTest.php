<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;

class HexDecodingStreamTest extends TestCase
{
    const MB = 1048576;

    public function testEncodingShouldMatchHex2BinOutput()
    {
        $stream = Psr7\stream_for(bin2hex(random_bytes(1027)));
        $encodingStream = new HexDecodingStream($stream);

        $this->assertSame(hex2bin($stream), (string) $encodingStream);
    }

    public function testShouldReportSizeOfEncodedStream()
    {
        $stream = Psr7\stream_for(bin2hex(random_bytes(1027)));
        $encodingStream = new HexDecodingStream($stream);

        $this->assertSame(strlen(hex2bin($stream)), $encodingStream->getSize());
    }

    public function testMemoryUsageRemainsConstant()
    {
        $memory = memory_get_usage();

        $stream = new HexDecodingStream(
            new HexEncodingStream(new RandomByteStream(124 * self::MB))
        );

        while (!$stream->eof()) {
            $stream->read(self::MB);
        }

        // Reading 1MB chunks should take 2MB
        $this->assertLessThanOrEqual($memory + 2 * self::MB, memory_get_usage());
    }
}
