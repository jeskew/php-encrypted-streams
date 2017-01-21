<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;

abstract class AesDecryptingStream implements StreamInterface
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

    /**
     * @param StreamInterface $cipherText
     * @param string $key
     */
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
            $this->buffer .= $this->decryptBlock(
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
     * Updates the initialization vector to take account of the last decrypted
     * ciphertext block.
     *
     * @param string $cipherTextBlock
     *
     * @return void
     */
    abstract protected function updateIv($cipherTextBlock);

    private function decryptBlock($length)
    {
        if ($this->stream->eof()) {
            return '';
        }

        $cipherText = '';
        do {
            $cipherText .= $this->stream->read($length - strlen($cipherText));
        } while (strlen($cipherText) < $length && !$this->stream->eof());

        $options = OPENSSL_RAW_DATA;
        if (!$this->stream->eof()
            || $this->stream->getSize() !== $this->stream->tell()
        ) {
            $options |= OPENSSL_ZERO_PADDING;
        }

        $plaintext = openssl_decrypt(
            $cipherText,
            $this->getCipherMethod(),
            $this->key,
            $options,
            $this->getIv()
        );

        $this->updateIv($cipherText);

        return $plaintext;
    }
}