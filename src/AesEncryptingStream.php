<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

abstract class AesEncryptingStream implements StreamInterface
{
    const BLOCK_SIZE = 16; // 128 bits

    use StreamDecoratorTrait;

    /**
     * @var string
     */
    private $buffer = '';

    /**
     * @var string
     */
    private $key;

    /**
     * @var StreamInterface
     */
    private $stream;

    public function __construct(StreamInterface $cipherText, $key)
    {
        $this->stream = $cipherText;
        $this->key = $key;
    }

    public function isWritable()
    {
        return false;
    }

    public function read($length)
    {
        if ($length > strlen($this->buffer)) {
            $this->buffer .= $this->encryptBlock(
                self::BLOCK_SIZE * ceil(($length - strlen($this->buffer)) / self::BLOCK_SIZE)
            );
        }

        $data = substr($this->buffer, 0, $length);
        $this->buffer = substr($this->buffer, $length);

        return $data;
    }

    protected function emptyBuffer()
    {
        $this->buffer = '';
    }

    /**
     * Returns the cipher method (as represented by ext-openssl)
     *
     * @return string
     */
    abstract protected function getCipherMethod();

    /**
     * Returns the initialization vector for the next block
     *
     * @return string
     */
    abstract protected function getIv();

    /**
     * Updates the initialization vector to take account of the last encrypted
     * ciphertext block.
     *
     * @param string $cipherTextBlock
     *
     * @return void
     */
    abstract protected function updateIv($cipherTextBlock);

    private function encryptBlock($length)
    {
        if ($this->stream->eof()) {
            return '';
        }

        $plainText = '';
        do {
            $plainText .= $this->stream->read($length - strlen($plainText));
        } while (strlen($plainText) < $length && !$this->stream->eof());

        $options = OPENSSL_RAW_DATA;
        if (!$this->stream->eof()
            || $this->stream->getSize() !== $this->stream->tell()
        ) {
            $options |= OPENSSL_ZERO_PADDING;
        }

        $cipherText = openssl_encrypt(
            $plainText,
            $this->getCipherMethod(),
            $this->key,
            $options,
            $this->getIv()
        );

        $this->updateIv(substr($cipherText, self::BLOCK_SIZE * -1));

        return $cipherText;
    }
}