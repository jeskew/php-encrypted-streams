<?php
namespace Jsq\EncryptionStreams;

use Psr\Http\Message\StreamInterface;

class AesEbcEncryptingStream extends AesEncryptingStream
{
    use AesTrait;

    /**
     * @var int
     */
    private $keySize;

    /**
     * @param StreamInterface $cipherText
     * @param string $key
     * @param int $keySize
     */
    public function __construct(
        StreamInterface $cipherText,
        $key,
        $keySize = 256
    ) {
        parent::__construct($cipherText, $key);

        $this->assertValidKeySize($keySize);
        $this->keySize = $keySize;
    }

    protected function getCipherMethod()
    {
        return "aes-{$this->keySize}-ecb";
    }

    protected function getIv()
    {
        return '';
    }

    protected function updateIv($cipherTextBlock) {}
}