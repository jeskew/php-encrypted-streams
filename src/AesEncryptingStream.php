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
    private $cipherMethod;

    /**
     * @var string
     */
    private $key;

    /**
     * @var StreamInterface
     */
    private $stream;

    public function __construct(
        StreamInterface $plainText,
        string $key,
        CipherMethod $cipherMethod
    ) {
        $this->stream = $plainText;
        $this->key = $key;
        $this->cipherMethod = clone $cipherMethod;
    }

    public function getSize(): ?int
    {
        $plainTextSize = $this->stream->getSize();

        if ($this->cipherMethod->requiresPadding() && $plainTextSize !== null) {
            // PKCS7 padding requires that between 1 and self::BLOCK_SIZE be
            // added to the plaintext to make it an even number of blocks.
            $padding = self::BLOCK_SIZE - $plainTextSize % self::BLOCK_SIZE;
            return $plainTextSize + $padding;
        }

        return $plainTextSize;
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function read($length): string
    {
        if ($length > strlen($this->buffer)) {
            $this->buffer .= $this->encryptBlock(
                self::BLOCK_SIZE * ceil(($length - strlen($this->buffer)) / self::BLOCK_SIZE)
            );
        }

        $data = (string)substr($this->buffer, 0, $length);
        $this->buffer = (string)substr($this->buffer, $length);
        return $data;
    }

    public function seek($offset, $whence = SEEK_SET): void
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
            $this->cipherMethod->seek($wholeBlockOffset);
            $this->read($offset - $wholeBlockOffset);
        } else {
            throw new LogicException('Unrecognized whence.');
        }
    }

    private function encryptBlock(int $length): string
    {
        if ($this->stream->eof()) {
            return '';
        }

        $plainText = '';
        do {
            $plainText .= $this->stream->read($length - strlen($plainText));
        } while (strlen($plainText) < $length && !$this->stream->eof());

        $options = OPENSSL_RAW_DATA;
        if (!$this->stream->eof()) {
            $options |= OPENSSL_ZERO_PADDING;
        }

        $cipherText = openssl_encrypt(
            $plainText,
            $this->cipherMethod->getOpenSslName(),
            $this->key,
            $options,
            $this->cipherMethod->getCurrentIv()
        );

        if ($cipherText === false) {
            throw new EncryptionFailedException("Unable to encrypt data with an initialization vector"
                . " of {$this->cipherMethod->getCurrentIv()} using the {$this->cipherMethod->getOpenSslName()}"
                . " algorithm. Please ensure you have provided a valid algorithm and initialization vector.");
        }

        $this->cipherMethod->update($cipherText);

        return $cipherText;
    }
}
