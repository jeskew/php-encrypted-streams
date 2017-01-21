<?php
namespace Jsq\EncryptionStreams;

use Psr\Http\Message\StreamInterface;

class AesCbcDecryptingStream extends AesDecryptingStream
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
     * AesCbcDecryptingStream constructor.
     * @param StreamInterface $cipherText
     * @param string $key
     * @param string $iv
     * @param int $keySize
     */
    public function __construct(
        StreamInterface $cipherText,
        $key,
        $iv,
        $keySize = 256
    ) {
        parent::__construct($cipherText, $key);

        $this->assertValidKeySize($keySize);
        $this->keySize = $keySize;
        $this->assertValidInitializationVector($iv, $this->getCipherMethod());
        $this->iv = $this->baseIv = $iv;
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
