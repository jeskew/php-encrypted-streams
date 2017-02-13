# PSR-7 Stream Encryption Decorators

[![Build Status](https://travis-ci.org/jeskew/php-encrypted-streams.svg?branch=master)](https://travis-ci.org/jeskew/php-encrypted-streams)
[![Total Downloads](https://img.shields.io/packagist/dt/jsq/psr7-stream-encryption.svg?style=flat)](https://packagist.org/packages/jsq/psr7-stream-encryption)
[![Author](http://img.shields.io/badge/author-@jreskew-blue.svg?style=flat-square)](https://twitter.com/jreskew)

PHP's built-in OpenSSL bindings provide a convenient means of encrypting and
decrypting data. The interface provided by `ext-openssl`, however, only operates
on strings, so decrypting a large ciphertext would require loading the entire
ciphertext into memory and receiving a string containing the entirety of the
decoded plaintext.

This package aims to allow the encryption and decryption of streams of arbitrary
size. It supports streaming encryption and decryption using AES-CBC, AES-CTR,
and AES-ECB.

> Using AES-ECB is **NOT RECOMMENDED** for new systems. It is included to allow
interoperability with older systems. Please consult [Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_.28ECB.29)
for a discussion of the drawbacks of ECB.

## Usage

Decorate an instance of `Psr\Http\Message\StreamInterface` with an encrypting
decorator to incrementally encrypt the contents of the decorated stream as 
`read` is called on the decorating stream:

```php
$iv = new Jsq\EncryptionStreams\CbcIv(
    random_bytes(openssl_cipher_iv_length('aes-256-cbc'))
);
$key = ... // a symmetric encryption key 
// Create a PSR-7 stream for a very large file.
$plaintext = new GuzzleHttp\Psr7\LazyOpenStream('/path/to/a/massive/file', 'r+);
// Create an encrypting stream.
$ciphertext = new Jsq\EncryptionStreams\AesEncryptingStream(
    $plaintext,
    $key,
    $iv
);

$encryptedChunk = $ciphertext->read(1024 * 1024);
```

No encryption is performed until `read` is called on the encrypting stream.
