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

    /**
     * @param string $iv
     * @param int $keySize
     */
    public function __construct($iv, $keySize = 256)
    {
        $this->baseIv = $this->iv = $iv;
        $this->keySize = $keySize;

        if (strlen($iv) !== openssl_cipher_iv_length($this->getOpenSslName())) {
            throw new Iae('Invalid initialization vector');
        }
    }

    public function getOpenSslName()
    {
        return "aes-{$this->keySize}-cbc";
    }

    public function getCurrentIv()
    {
        return $this->iv;
    }

    public function requiresPadding()
    {
        return true;
    }

    public function seek($offset, $whence = SEEK_SET)
    {
        if ($offset === 0 && $whence === SEEK_SET) {
            $this->iv = $this->baseIv;
        } else {
            throw new LogicException('CBC initialization only support being'
                . ' rewound, not arbitrary seeking.');
        }
    }

    public function update($cipherTextBlock)
    {
        $this->iv = substr($cipherTextBlock, self::BLOCK_SIZE * -1);
    }
}