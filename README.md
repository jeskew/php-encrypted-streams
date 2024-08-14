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
$iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
$cipherMethod = new Cbc($iv);
$key = 'some-secret-password-here';

$inStream = new Stream(fopen('some-input-file', 'r')); // Any PSR-7 stream will be fine here
$cipherTextStream = new AesEncryptingStream($inStream, $key, $cipherMethod); // Wrap the stream in an EncryptingStream
$cipherTextFile = Psr7\Utils::streamFor(fopen('encrypted.file', 'w'));
Psr7\copy_to_stream($cipherTextStream, $cipherTextFile); // When you read from the encrypting stream, the data will be encrypted.

// You'll also need to store the IV somewhere, because we'll need it later to decrypt the data.
// In this case, I'll base64 encode it and stick it in a file (but we could put it anywhere where we can retrieve it later, like a database column)
file_put_contents('encrypted.iv', base64_encode($iv));
```

No encryption is performed until `read` is called on the encrypting stream.

To calculate the HMAC of a cipher text, wrap a decorated stream with an instance
of `HashingStream`:

```php
$hash = null;
$ciphertext = new Jsq\EncryptionStreams\AesEncryptingStream(
    $plaintext,
    $key,
    $cipherMethod
);
$hashingDecorator = new Jsq\EncryptionStreams\HashingStream(
    $ciphertext,
    $key,
    function ($calculatedHash) use (&$hash) {
        $hash = $calculatedHash;
    }
);

while (!$ciphertext->eof()) {
    $ciphertext->read(1024 * 1024);
}

assert('$hash === $hashingDecorator->getHash()');
```

When decrypting a cipher text, wrap the cipher text in a hasing decorator before
passing it as an argument to the decrypting stream:

```php
$key = 'secret key';
$iv = random_bytes(openssl_cipher_iv_length('aes-256-cbc'));
$plainText = 'Super secret text';
$cipherText = openssl_encrypt(
    $plainText,
    'aes-256-cbc',
    $key,
    OPENSSL_RAW_DATA
    $iv
);
$expectedHash = hash('sha256', $cipherText);

$hashingDecorator = new Jsq\EncryptingStreams\HashingStream(
    GuzzleHttp\Psr7\Utils::streamFor($cipherText),
    $key,
    function ($hash) use ($expectedHash) {
        if ($hash !== $expectedHash) {
            throw new DomainException('Cipher text mac does not match expected value!');
        }
    }
);

$decrypted = new Jsq\EncryptionStreams\AesEncryptingStream(
    $cipherText,
    $key,
    $cipherMethod
);
while (!$decrypted->eof()) {
    $decrypted->read(1024 * 1024);
}
```

As with the encrypting decorators, `HashingStream`s are lazy and will only hash
the underlying stream as it is read. In the example above, no exception would be
thrown until the entire cipher text had been read (and all but the last block
deciphered).

`HashingStream`s are not seekable, so you will need to wrap on in a
`GuzzleHttp\Psr7\CachingStream` to support random access.
