<?php

namespace Jsq\EncryptionStreams;

use GuzzleHttp\Psr7\Utils;

trait AesEncryptionStreamTestTrait
{
    public static function cartesianJoinInputCipherMethodProvider(): array
    {
        $toReturn = [];
        $plainTexts = self::unwrapProvider(self::plainTextProvider());
        $counter = count($plainTexts);

        for ($i = 0; $i < $counter; $i++) {
            for ($j = 0; $j < count(self::cipherMethodProvider()); $j++) {
                $toReturn [] = [
                    // Test each string with standard temp streams
                    Utils::streamFor($plainTexts[$i]),
                    $plainTexts[$i],
                    self::cipherMethodProvider()[$j][0]
                ];

                $toReturn [] = [
                    // Test each string with a stream that does not know its own size
                    Utils::streamFor(
                        (function ($pt) {
                            yield $pt;
                        })(
                            $plainTexts[$i]
                        )
                    ),
                    $plainTexts[$i],
                    self::cipherMethodProvider()[$j][0]
                ];
            }
        }

        return $toReturn;
    }

    public static function cartesianJoinInputKeySizeProvider(): array
    {
        $toReturn = [];
        $plainTexts = self::unwrapProvider(self::plainTextProvider());
        $keySizes = self::unwrapProvider(self::keySizeProvider());
        $counter = count($plainTexts);

        for ($i = 0; $i < $counter; $i++) {
            for ($j = 0; $j < count($keySizes); $j++) {
                $toReturn [] = [
                    // Test each string with standard temp streams
                    Utils::streamFor($plainTexts[$i]),
                    $plainTexts[$i],
                    $keySizes[$j],
                ];

                $toReturn [] = [
                    // Test each string with a stream that does not know its own size
                    Utils::streamFor(
                        (function ($pt) {
                            yield $pt;
                        })(
                            $plainTexts[$i]
                        )
                    ),
                    $plainTexts[$i],
                    $keySizes[$j],
                ];
            }
        }

        return $toReturn;
    }

    public static function cipherMethodProvider(): array
    {
        $toReturn = [];
        foreach (self::unwrapProvider(self::keySizeProvider()) as $keySize) {
            $toReturn [] = [
                new Cbc(
                    random_bytes(openssl_cipher_iv_length('aes-256-cbc')),
                    $keySize
                )
            ];
            $toReturn [] = [
                new Ctr(
                    random_bytes(openssl_cipher_iv_length('aes-256-ctr')),
                    $keySize
                )
            ];
            $toReturn [] = [new Ecb($keySize)];
        }

        return $toReturn;
    }

    public static function seekableCipherMethodProvider(): array
    {
        return array_filter(self::cipherMethodProvider(), fn(array $args): bool => !($args[0] instanceof Cbc));
    }

    public static function keySizeProvider(): array
    {
        return [
            [128],
            [192],
            [256],
        ];
    }

    public static function plainTextProvider(): array
    {
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

    private static function unwrapProvider(array $provider): array
    {
        return array_map(fn(array $wrapped) => $wrapped[0], $provider);
    }
}
