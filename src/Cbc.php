<?php
namespace Jsq\EncryptionStreams;

use InvalidArgumentException as Iae;
use LogicException;

class Cbc implements CipherMethod
{
    const BLOCK_SIZE = 16;

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

    public function __construct(string $iv, int $keySize = 256)
    {
        $this->baseIv = $this->iv = $iv;
        $this->keySize = $keySize;

        if (strlen($iv) !== openssl_cipher_iv_length($this->getOpenSslName())) {
            throw new Iae('Invalid initialization vector');
        }
    }

    public function getOpenSslName(): string
    {
        return "aes-{$this->keySize}-cbc";
    }

    public function getCurrentIv(): string
    {
        return $this->iv;
    }

    public function requiresPadding(): bool
    {
        return true;
    }

    public function seek(int $offset, int $whence = SEEK_SET): void
    {
        if ($offset === 0 && $whence === SEEK_SET) {
            $this->iv = $this->baseIv;
        } else {
            throw new LogicException('CBC initialization only support being'
                . ' rewound, not arbitrary seeking.');
        }
    }

    public function update(string $cipherTextBlock): void
    {
        $this->iv = substr($cipherTextBlock, self::BLOCK_SIZE * -1);
    }
}