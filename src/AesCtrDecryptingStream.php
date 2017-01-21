<?php
namespace Jsq\EncryptionStreams;

use Psr\Http\Message\StreamInterface;

class AesCtrDecryptingStream extends AesDecryptingStream
{
    const CTR_BLOCK_MAX = 65536; // maximum 16-bit unsigned integer value

    use AesCtrTrait;

    /**
     * @var int
     */
    private $keySize;

    /**
     * @var int[]
     */
    private $iv;

    /**
     * @var int[]
     */
    private $ctrOffset;

    /**
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
        $this->iv = $this->extractIvParts($iv);
        $this->ctrOffset = array_fill(0, 8, 0);
    }

    public function seek($offset, $whence = SEEK_SET)
    {
        if ($whence === SEEK_SET) {
            $this->emptyBuffer();
            $this->ctrOffset = array_fill(0, 8, 0);

            $wholeBlockOffset = (int) ($offset / self::BLOCK_SIZE) * self::BLOCK_SIZE;
            $this->incrementOffset($wholeBlockOffset);
            parent::seek($wholeBlockOffset, $whence);
            $this->read($offset - $wholeBlockOffset);
        }

        return false;
    }

    protected function getCipherMethod()
    {
        return "aes-{$this->keySize}-ctr";
    }

    protected function getIv()
    {
        return $this->calculateCurrentIv($this->iv, $this->ctrOffset);
    }

    protected function updateIv($cipherTextBlock)
    {
        $this->incrementOffset(strlen($cipherTextBlock) / self::BLOCK_SIZE);
    }
}