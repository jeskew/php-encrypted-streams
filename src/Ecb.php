<?php
namespace Jsq\EncryptionStreams;

class Ecb implements CipherMethod
{
    /**
     * @var int
     */
    private $keySize;

    /**
     * @param int $keySize
     */
    public function __construct(int $keySize = 256)
    {
        $this->keySize = $keySize;
    }

    public function getOpenSslName(): string
    {
        return "aes-{$this->keySize}-ecb";
    }

    public function getCurrentIv(): string
    {
        return '';
    }

    public function requiresPadding(): bool
    {
        return true;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void {}

    public function update(string $cipherTextBlock): void {}
}