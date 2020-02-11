<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use LogicException;
use Psr\Http\Message\StreamInterface;

class AesDecryptingStream implements StreamInterface
{
    const BLOCK_SIZE = 16; // 128 bits

    use StreamDecoratorTrait;

    /**
     * @var string
     */
    private $plainBuffer = '';

    /**
     * @var string
     */
    private $cipherBuffer = '';

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
        StreamInterface $cipherText,
        string $key,
        CipherMethod $cipherMethod
    ) {
        $this->stream = $cipherText;
        $this->key = $key;
        $this->cipherMethod = clone $cipherMethod;
    }

    public function eof()
    {
        return $this->cipherBuffer === '' && $this->stream->eof();
    }

    public function getSize(): ?int
    {
        $plainTextSize = $this->stream->getSize();

        if ($this->cipherMethod->requiresPadding()) {
            // PKCS7 padding requires that between 1 and self::BLOCK_SIZE be
            // added to the plaintext to make it an even number of blocks. The
            // plaintext is between strlen($cipherText) - self::BLOCK_SIZE and
            // strlen($cipherText) - 1
            return null;
        }

        return $plainTextSize;
    }

    public function isWritable(): bool
    {
        return false;
    }

    public function read($length): string
    {
        if ($length > strlen($this->plainBuffer)) {
            $this->plainBuffer .= $this->decryptBlock(
                self::BLOCK_SIZE * ceil(($length - strlen($this->plainBuffer)) / self::BLOCK_SIZE)
            );
        }

        $data = substr($this->plainBuffer, 0, $length);
        $this->plainBuffer = substr($this->plainBuffer, $length);

        return $data ? $data : '';
    }

    public function seek($offset, $whence = SEEK_SET): void
    {
        if ($offset === 0 && $whence === SEEK_SET) {
            $this->plainBuffer = '';
            $this->cipherBuffer = '';
            $this->cipherMethod->seek(0, SEEK_SET);
            $this->stream->seek(0, SEEK_SET);
        } else {
            throw new LogicException('AES encryption streams only support being'
                . ' rewound, not arbitrary seeking.');
        }
    }

    private function decryptBlock(int $length): string
    {
        if ($this->cipherBuffer === '' && $this->stream->eof()) {
            return '';
        }

        $cipherText = $this->cipherBuffer;
        while (strlen($cipherText) < $length && !$this->stream->eof()) {
            $cipherText .= $this->stream->read($length - strlen($cipherText));
        }

        $options = OPENSSL_RAW_DATA;
        $this->cipherBuffer = $this->stream->read(self::BLOCK_SIZE);
        if (!($this->cipherBuffer === '' && $this->stream->eof())) {
            $options |= OPENSSL_ZERO_PADDING;
        }

        $plaintext = openssl_decrypt(
            $cipherText,
            $this->cipherMethod->getOpenSslName(),
            $this->key,
            $options,
            $this->cipherMethod->getCurrentIv()
        );

        if ($plaintext === false) {
            throw new DecryptionFailedException("Unable to decrypt $cipherText with an initialization vector"
                . " of {$this->cipherMethod->getCurrentIv()} using the {$this->cipherMethod->getOpenSslName()}"
                . " algorithm. Please ensure you have provided the correct algorithm, initialization vector, and key.");
        }

        $this->cipherMethod->update($cipherText);

        return $plaintext;
    }
}
