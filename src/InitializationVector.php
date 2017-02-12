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
     * @param int $offset
     * @param int $whence
     * @return void
     */
    public function seek($offset, $whence = SEEK_SET);

    /**
     * @param string $cipherTextBlock
     * @return void
     */
    public function update($cipherTextBlock);
}