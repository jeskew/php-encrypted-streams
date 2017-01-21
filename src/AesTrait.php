<?php
namespace Jsq\EncryptionStreams;

use InvalidArgumentException as Iae;

trait AesTrait
{
    /**
     * @param string $iv
     * @param string $method
     */
    private function assertValidInitializationVector($iv, $method)
    {
        $expectedLength = openssl_cipher_iv_length($method);
        if (strlen($iv) !== $expectedLength) {
            throw new Iae("Expected an initialization vector of"
                . " {$expectedLength} bytes");
        }
    }

    /**
     * @param int $ks
     */
    private function assertValidKeySize($ks)
    {
        static $keySizes = [
            128 => true,
            192 => true,
            256 => true,
        ];

        if (empty($keySizes[$ks])) {
            throw new Iae("$ks is not a valid key size for AES encryption.");
        }
    }
}