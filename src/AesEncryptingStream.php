<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use LogicException;
use Psr\Http\Message\StreamInterface;
use function GuzzleHttp\Psr7\str;

class AesEncryptingStream implements StreamInterface
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
    private $plainBuffer = '';

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

    /**
     * @param StreamInterface $plainText
     * @param string $key
     * @param CipherMethod $cipherMethod
     */
    public function __construct(
        StreamInterface $plainText,
        $key,
        CipherMethod $cipherMethod
    ) {
        $this->stream = $plainText;
        $this->key = $key;
        $this->cipherMethod = clone $cipherMethod;
    }

    public function getSize()
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

        return $data ? $data : '';
    }

    public function seek($offset, $whence = SEEK_SET)
    {
        if ($whence === SEEK_CUR) {
            $offset -= strlen($this->plainBuffer);
            $offset = $this->tell() + $offset;
            $whence = SEEK_SET;
        }

        if ($whence === SEEK_SET) {
            $this->buffer = '';
            $this->plainBuffer = '';
            $wholeBlockOffset
                = (int) ($offset / self::BLOCK_SIZE) * self::BLOCK_SIZE;
            $this->stream->seek($wholeBlockOffset);
            $this->cipherMethod->seek($wholeBlockOffset);
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

        $plainText = $this->plainBuffer;
        do {
            $plainText .= $this->stream->read($length - strlen($plainText));
        } while (strlen($plainText) < $length && !$this->stream->eof());

        // Ensure eof returns the correct value. See https://www.php.net/manual/en/function.feof.php#67261
        $this->plainBuffer = $this->stream->read(1);

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

        $this->cipherMethod->update($cipherText);

        return $cipherText;
    }
}
