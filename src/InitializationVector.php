<?php
namespace Jsq\EncryptionStreams;

interface InitializationVector
{
    /**
     * @return string
     */
    public function getCipherMethod();

    /**
     * @return string
     */
    public function getCurrentIv();

    /**
     * @return bool
     */
    public function requiresPadding();

    /**
     * @param int $offset
     * @param int $whence
     * @return void
     */
    public function seek($offset, $whence = SEEK_SET);

    /**
     * @return bool
     */
    public function supportsArbitrarySeeking();

    /**
     * @param string $cipherTextBlock
     * @return void
     */
    public function update($cipherTextBlock);
}