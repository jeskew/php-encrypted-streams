<?php
namespace Jsq\EncryptionStreams;

use LogicException;

interface CipherMethod
{
    /**
     * Returns an identifier for the cipher method supported by this IV object,
     * e.g., 'CBC' or 'CTR'
     */
    public function getName();

    /**
     * Returns the IV that should be used to encrypt or decrypt the next block.
     */
    public function getCurrentIv();

    /**
     * Indicates whether the cipher method used with this IV requires padding
     * the final block to make sure the plaintext is evenly divisible by the
     * block size.
     */
    public function requiresPadding();

    /**
     * Adjust the return of this::getCurrentIv to reflect a seek performed on
     * the encryption stream using this IV object.
     *
     * @param int $offset
     * @param int $whence
     *
     * @throws LogicException   Thrown if the requested seek is not supported by
     *                          this IV implementation. For example, a CBC IV
     *                          only supports a full rewind ($offset === 0 &&
     *                          $whence === SEEK_SET)
     */
    public function seek($offset, $whence = SEEK_SET);

    /**
     * Take account of the last cipher text block to adjust the return of
     * this::getCurrentIv
     *
     * @param string $cipherTextBlock
     */
    public function update($cipherTextBlock);
}