<?php
namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7;

trait AesEncryptionStreamTestTrait
{
    public function cartesianJoinInputCipherMethodProvider()
    {
        $toReturn = [];
        $plainTexts = $this->unwrapProvider([$this, 'plainTextProvider']);

        for ($i = 0; $i < count($plainTexts); $i++) {
            for ($j = 0; $j < count($this->cipherMethodProvider()); $j++) {
                $toReturn []= [
                    // Test each string with standard temp streams
                    Psr7\stream_for($plainTexts[$i]),
                    $plainTexts[$i],
                    $this->cipherMethodProvider()[$j][0]
                ];

                $toReturn []= [
                    // Test each string with a stream that does not know its own size
                    Psr7\stream_for((function ($pt) { yield $pt; })($plainTexts[$i])),
                    $plainTexts[$i],
                    $this->cipherMethodProvider()[$j][0]
                ];
            }
        }

        return $toReturn;
    }

    public function cartesianJoinInputKeySizeProvider()
    {
        $toReturn = [];
        $plainTexts = $this->unwrapProvider([$this, 'plainTextProvider']);
        $keySizes = $this->unwrapProvider([$this, 'keySizeProvider']);

        for ($i = 0; $i < count($plainTexts); $i++) {
            for ($j = 0; $j < count($keySizes); $j++) {
                $toReturn []= [
                    // Test each string with standard temp streams
                    Psr7\stream_for($plainTexts[$i]),
                    $plainTexts[$i],
                    $keySizes[$j],
                ];

                $toReturn []= [
                    // Test each string with a stream that does not know its own size
                    Psr7\stream_for((function ($pt) { yield $pt; })($plainTexts[$i])),
                    $plainTexts[$i],
                    $keySizes[$j],
                ];
            }
        }

        return $toReturn;
    }

    public function cipherMethodProvider()
    {
        $toReturn = [];
        foreach ($this->unwrapProvider([$this, 'keySizeProvider']) as $keySize) {
            $toReturn []= [new Cbc(
                random_bytes(openssl_cipher_iv_length('aes-256-cbc')),
                $keySize
            )];
            $toReturn []= [new Ctr(
                random_bytes(openssl_cipher_iv_length('aes-256-ctr')),
                $keySize
            )];
            $toReturn []= [new Ecb($keySize)];
        }

        return $toReturn;
    }

    public function seekableCipherMethodProvider()
    {
        return array_filter($this->cipherMethodProvider(), function (array $args) {
            return !($args[0] instanceof Cbc);
        });
    }

    public function keySizeProvider()
    {
        return [
            [128],
            [192],
            [256],
        ];
    }

    public function plainTextProvider() {
        return [
            ['The rain in Spain falls mainly on the plain.'],
            ['دست‌نوشته‌ها نمی‌سوزند'],
            ['Рукописи не горят'],
            ['test'],
            [random_bytes(AesEncryptingStream::BLOCK_SIZE)],
            [random_bytes(2 * 1024 * 1024)],
            [random_bytes(2 * 1024 * 1024 + 11)],
        ];
    }

    private function unwrapProvider(callable $provider)
    {
        return array_map(function (array $wrapped) {
            return $wrapped[0];
        }, call_user_func($provider));
    }
}
