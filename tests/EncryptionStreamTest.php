<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\CachingStream;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\StreamInterface;

abstract class EncryptionStreamTest extends TestCase
{
    const KB = 1024;
    const MB = 1048576;

    public function testMemoryUsageRemainsConstant()
    {
        $memory = memory_get_usage();

        $stream = $this->getStreamInstance(
            new RandomByteStream(124 * self::MB),
            'foo',
            $this->generateIv(),
            256
        );

        while (!$stream->eof()) {
            $stream->read(self::MB);
        }

        $this->assertLessThanOrEqual($memory + self::MB, memory_get_usage());
    }

    public function plainTextProvider() {
        return [
            [Psr7\stream_for('The rain in Spain falls mainly on the plain.')],
            [Psr7\stream_for('دست‌نوشته‌ها نمی‌سوزند')],
            [Psr7\stream_for('Рукописи не горят')],
            [new CachingStream(new RandomByteStream(1 * self::MB))]
        ];
    }

    /**
     * @return string
     */
    abstract protected function getCipherMethod();

    /**
     * @return string
     */
    protected function generateIv()
    {
        return random_bytes(openssl_cipher_iv_length($this->getCipherMethod()));
    }

    /**
     * @param StreamInterface $source
     * @param string $key
     * @param string $iv
     * @param int $keySize
     * @return StreamInterface
     */
    abstract protected function getStreamInstance(
        StreamInterface $source,
        $key,
        $iv,
        $keySize
    );
}
