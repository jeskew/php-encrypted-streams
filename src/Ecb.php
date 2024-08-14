<?php
namespace Jsq\EncryptionStreams;

class Ecb implements CipherMethod
{
    public function __construct(private readonly int $keySize = 256)
    {
    }

    public function getOpenSslName(): string
    {
        return sprintf('aes-%d-ecb', $this->keySize);
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