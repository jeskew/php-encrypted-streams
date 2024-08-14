<?php
namespace Jsq\EncryptionStreams;

use LogicException;

interface CipherMethod
{
    /**
     * Returns an identifier recognizable by `openssl_*` functions, such as
     * `aes-256-cbc` or `aes-128-ctr`.
     */
    public function getOpenSslName(): string;

    /**
     * Returns the IV that should be used to encrypt or decrypt the next block.
     */
    public function getCurrentIv(): string;

    /**
     * Indicates whether the cipher method used with this IV requires padding
     * the final block to make sure the plaintext is evenly divisible by the
     * block size.
     */
    public function requiresPadding(): bool;

    /**
     * Adjust the return of this::getCurrentIv to reflect a seek performed on
     * the encryption stream using this IV object.
     *
     *
     * @throws LogicException   Thrown if the requested seek is not supported by
     *                          this IV implementation. For example, a CBC IV
     *                          only supports a full rewind ($offset === 0 &&
     *                          $whence === SEEK_SET)
     */
    public function seek(int $offset, int $whence = SEEK_SET): void;

    /**
     * Take account of the last cipher text block to adjust the return of
     * this::getCurrentIv
     */
    public function update(string $cipherTextBlock): void;
}