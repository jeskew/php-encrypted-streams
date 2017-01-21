<?php
namespace Jsq\EncryptionStreams;

use Psr\Http\Message\StreamInterface;

class AesCtrEncryptingStream extends AesEncryptingStream
{
    use AesCtrTrait;

    /**
     * @var int
     */
    private $keySize;

    /**
     * The hash initialization vector, stored as eight 16-bit words
     * @var int[]
     */
    private $iv;

    /**
     * The counter offset to add to the initialization vector
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