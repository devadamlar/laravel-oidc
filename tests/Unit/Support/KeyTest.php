<?php

namespace DevAdamlar\LaravelOidc\Tests\Unit\Support;

use DevAdamlar\LaravelOidc\Support\Key;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

class KeyTest extends TestCase
{
    /**
     * @dataProvider validKeysProvider
     */
    public function test_thumbprint_returns_string(OpenSSLAsymmetricKey|string $key): void
    {
        $this->assertIsString(Key::thumbprint($key));
    }

    public static function validKeysProvider(): array
    {
        $rsa = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        openssl_pkey_export($rsa, $rsaPem);

        return [
            'rsa object' => [$rsa],
            'ec object' => [$ec],
            'rsa pem string' => [$rsaPem],
        ];
    }

    /**
     * @dataProvider invalidKeysProvider
     */
    public function test_thumbprint_throws_for_invalid_keys(mixed $key, string $expectedMessage): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($expectedMessage);
        Key::thumbprint($key);
    }

    public static function invalidKeysProvider(): array
    {
        $unsupported = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_DSA]);

        return [
            'invalid pem string' => ['---invalid---', 'Invalid PEM key string provided.'],
            'unsupported key type' => [$unsupported, 'Unsupported key type.'],
        ];
    }
}
