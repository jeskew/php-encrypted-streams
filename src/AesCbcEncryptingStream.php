<?php
namespace Jsq\EncryptionStreams;

use Psr\Http\Message\StreamInterface;

class AesCbcEncryptingStream extends AesEncryptingStream
{
    use AesTrait;

    /**
     * @var string
     */
    private $baseIv;

    /**
     * @var string
     */
    private $iv;

    /**
     * @var int
     */
    private $keySize;

    /**
     * @param StreamInterface $plainText
     * @param string $key
     * @param string $iv
     * @param int $keySize
     */
    public function __construct(
        StreamInterface $plainText,
        $key,
        $iv,
        $keySize = 256
    ) {
        parent::__construct($plainText, $key);

        $this->assertValidKeySize($keySize);
        $this->keySize = $keySize;
        $this->assertValidInitializationVector($iv, $this->getCipherMethod());
        $this->iv = $this->baseIv = $iv;
    }

    public function getSize()
    {
        $inputSize = parent::getSize();

        if (null === $inputSize) {
            return null;
        }

        // PKCS7 padding requires that between 1 and self::BLOCK_SIZE be added
        // to the plaintext to make it an even number of blocks.
        return $inputSize + (self::BLOCK_SIZE - $inputSize % self::BLOCK_SIZE);
    }

    public function seek($offset, $whence = SEEK_SET)
    {
        if ($offset === 0 && $whence === SEEK_SET) {
            $this->emptyBuffer();
            $this->iv = $this->baseIv;
            parent::seek($offset, SEEK_SET);
        }
    }

    protected function getCipherMethod()
    {
        return "aes-{$this->keySize}-cbc";
    }

    protected function getIv()
    {
        return $this->iv;
    }

    protected function updateIv($cipherTextBlock)
    {
        $this->iv = substr($cipherTextBlock, self::BLOCK_SIZE * -1);
    }
}
