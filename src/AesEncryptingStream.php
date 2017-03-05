<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use LogicException;
use Psr\Http\Message\StreamInterface;

class AesEncryptingStream implements StreamInterface
{
    const BLOCK_SIZE = 16; // 128 bits

    use StreamDecoratorTrait;

    /**
     * @var string
     */
    private $buffer = '';

    /**
     * @var CipherMethod
     */
    private $iv;

    /**
     * @var string
     */
    private $key;

    /**
     * @var int
     */
    private $keySize;

    /**
     * @var StreamInterface
     */
    private $stream;

    /**
     * @param StreamInterface $plainText
     * @param string $key
     * @param int $keySize
     * @param CipherMethod $iv
     */
    public function __construct(
        StreamInterface $plainText,
        $key,
        CipherMethod $iv,
        $keySize = 256
    ) {
        $this->stream = $plainText;
        $this->key = $key;
        $this->iv = clone $iv;
        $this->keySize = $keySize;
    }

    public function getSize()
    {
        $plainTextSize = $this->stream->getSize();

        if ($this->iv->requiresPadding() && $plainTextSize !== null) {
            // PKCS7 padding requires that between 1 and self::BLOCK_SIZE be
            // added to the plaintext to make it an even number of blocks.
            $padding = self::BLOCK_SIZE - $plainTextSize % self::BLOCK_SIZE;
            return $plainTextSize + $padding;
        }

        return $plainTextSize;
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

    public function seek($offset, $whence = SEEK_SET)
    {
        if ($whence === SEEK_CUR) {
            $offset = $this->tell() + $offset;
            $whence = SEEK_SET;
        }

        if ($whence === SEEK_SET) {
            $this->buffer = '';
            $wholeBlockOffset
                = (int) ($offset / self::BLOCK_SIZE) * self::BLOCK_SIZE;
            $this->stream->seek($wholeBlockOffset);
            $this->iv->seek($wholeBlockOffset);
            $this->read($offset - $wholeBlockOffset);
        } else {
            throw new LogicException('Unrecognized whence.');
        }
    }

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
            "AES-{$this->keySize}-{$this->iv->getName()}",
            $this->key,
            $options,
            $this->iv->getCurrentIv()
        );

        $this->iv->update($cipherText);

        return $cipherText;
    }
}