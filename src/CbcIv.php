<?php
namespace Jsq\EncryptionStreams;

use InvalidArgumentException;
use LogicException;

class CbcIv implements InitializationVector
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
     * @param string $iv
     */
    public function __construct($iv)
    {
        if (strlen($iv) !== openssl_cipher_iv_length('aes-128-cbc')) {
            throw new InvalidArgumentException('Invalid initialization veector'
                . ' provided to ' . static::class);
        }
        $this->baseIv = $this->iv = $iv;
    }

    public function getCipherMethod()
    {
        return 'CBC';
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

    public function supportsArbitrarySeeking()
    {
        return false;
    }

    public function update($cipherTextBlock)
    {
        $this->iv = substr($cipherTextBlock, self::BLOCK_SIZE * -1);
    }
}