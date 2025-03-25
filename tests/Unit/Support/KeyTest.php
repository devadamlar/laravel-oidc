<?php

namespace DevAdamlar\LaravelOidc\Tests\Unit\Support;

use DevAdamlar\LaravelOidc\Support\Alg;
use DevAdamlar\LaravelOidc\Support\Key;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;

class KeyTest extends TestCase
{
    /**
     * @dataProvider validKeysProvider
     */
    public function test_thumbprint_returns_string(string $key, string $thumbprint): void
    {
        $key = openssl_pkey_get_details(openssl_pkey_get_public($key));
        $this->assertEquals($thumbprint, Key::thumbprint($key));
    }

    public static function validKeysProvider(): array
    {
        return [
            'rsa' => [<<<'PEM'
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw/NFLBiy9HhDNFZalB94
ZK03AKF8bU8uq+vwqUAwBzA3ZJkIoYqXcL5M9bS7I5anRYZfRzPV7K0s0+JZRI8O
kPQV5xEGwvHGZDcJm7HjjSxuOTZpFw4qVeqHTeJwCW6N7vQ+OE1TuLQUn+GdugDn
xKrWEk6Ud0XsEoLsoBTPlfFzzSPvoHUHuQFqKnM3w2zcm8p3S5GRKAb+3rLeCuxY
NhrlczObZ1M3s9Xk79q+vGwO4n2Z/7p3H5kfpQXxAdkntKkKhgtG+N4yUpm45b84
XnJ4g64RyUax2IQpg9LwCHD9qx5az3p3BTLwLzZplDcBuLtZlbLMIEQ7Cy+rI+x9
TwIDAQAB
-----END PUBLIC KEY-----
PEM, 'Mz5R-sC7envGHcHzOgkSj8zxeOg42d95L6XdoMAyZ0U'],
            'ec' => [<<<'PEM'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----
PEM, 'VrUsVk0eLNVAMnejOiLLccHcixeqjj1wAHPjm3Hu6dM'],
        ];
    }

    public function test_thumbprint_throws_for_invalid_keys(): void
    {
        // Arrange
        $publicKey = openssl_pkey_get_public(<<<PEM
-----BEGIN PUBLIC KEY-----
MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9E
AMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f
6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv
8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtc
NrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwky
jMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/h
WuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBALea3ggqzC9Aagr+Lz7zqI1vze6x
p1lIKhmvxFMj3cu1HAQ9YtGZa967jHzzOhe/0tbooPc6xdg8nCd6hTHemsyPBg9p
L97laXAX6QyuVAkjd4Ye0oJM3yGxzvVs897YFhaCQUEuGeKXZH42Y2nhGFSaklKa
2D/axpjH6zphozWy
-----END PUBLIC KEY-----
PEM
);
        $publicKey = openssl_pkey_get_details($publicKey);
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported key type.');

        // Act
        Key::thumbprint($publicKey);
    }

    /**
     * @dataProvider privateKeyProvider
     */
    public function test_should_give_public_key_from_private_key(string|OpenSSLAsymmetricKey $privateKey): void
    {
        // Arrange
        $expected = openssl_pkey_get_details(
            openssl_pkey_get_public(
                openssl_pkey_get_details(openssl_pkey_get_private($privateKey))['key']
            )
        );

        // Act
        $publicKey = Key::publicKey($privateKey);

        // Assert
        $this->assertIsArray($publicKey);
        $this->assertEquals($expected, $publicKey);
    }

    public function test_should_throw_exception_if_private_key_is_invalid(): void
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Could not extract public key from private RSA key.');

        // Act
        Key::publicKey('invalid-key');
    }

    public function test_jwk_throws_for_invalid_keys(): void
    {
        // Arrange
        $publicKey = openssl_pkey_get_public(<<<PEM
-----BEGIN PUBLIC KEY-----
MIIBuDCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9E
AMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f
6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv
8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtc
NrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwky
jMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/h
WuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYUAAoGBALea3ggqzC9Aagr+Lz7zqI1vze6x
p1lIKhmvxFMj3cu1HAQ9YtGZa967jHzzOhe/0tbooPc6xdg8nCd6hTHemsyPBg9p
L97laXAX6QyuVAkjd4Ye0oJM3yGxzvVs897YFhaCQUEuGeKXZH42Y2nhGFSaklKa
2D/axpjH6zphozWy
-----END PUBLIC KEY-----
PEM
        );
        $publicKey = openssl_pkey_get_details($publicKey);
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unsupported key type.');

        // Act
        Key::jwk($publicKey['key']);
    }

    public function test_jwk_throws_for_invalid_pem(): void
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid public key PEM.');

        // Act
        Key::jwk('invalid-key');
    }

    /**
     * @dataProvider publicKeyProvider
     */
    public function test_jwk_should_give_jwk(string $publicKey, ?Alg $alg, array $expectedJwk): void
    {
        $actualJwk = Key::jwk($publicKey, $alg);
        $this->assertEquals($expectedJwk, $actualJwk);
    }

    /**
     * @dataProvider algProvider
     *
     * @return void
     */
    public function test_should_give_ec_pair(Alg $alg, string $curve)
    {
        // Act
        ['private' => $privateKey, 'public' => $publicKey] = Key::generateEcKeyPair($alg);

        // Assert
        $this->assertEquals($curve, $publicKey['ec']['curve_name']);
    }

    public static function privateKeyProvider(): array
    {
        return [
            'asymmetric key' => [openssl_pkey_new([
                'private_key_bits' => 2048,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ])],
            'pem' => [<<<'PEM'
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----
PEM],
        ];
    }

    public static function publicKeyProvider(): array
    {
        // Pre-generated 2048-bit RSA public key
        $rsaPem = <<<'PEM'
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw/NFLBiy9HhDNFZalB94
ZK03AKF8bU8uq+vwqUAwBzA3ZJkIoYqXcL5M9bS7I5anRYZfRzPV7K0s0+JZRI8O
kPQV5xEGwvHGZDcJm7HjjSxuOTZpFw4qVeqHTeJwCW6N7vQ+OE1TuLQUn+GdugDn
xKrWEk6Ud0XsEoLsoBTPlfFzzSPvoHUHuQFqKnM3w2zcm8p3S5GRKAb+3rLeCuxY
NhrlczObZ1M3s9Xk79q+vGwO4n2Z/7p3H5kfpQXxAdkntKkKhgtG+N4yUpm45b84
XnJ4g64RyUax2IQpg9LwCHD9qx5az3p3BTLwLzZplDcBuLtZlbLMIEQ7Cy+rI+x9
TwIDAQAB
-----END PUBLIC KEY-----
PEM;

        $rsaJwk = [
            'kid' => 'Mz5R-sC7envGHcHzOgkSj8zxeOg42d95L6XdoMAyZ0U',
            'use' => 'sig',
            'kty' => 'RSA',
            'n' => 'w_NFLBiy9HhDNFZalB94ZK03AKF8bU8uq-vwqUAwBzA3ZJkIoYqXcL5M9bS7I5anRYZfRzPV7K0s0-JZRI8OkPQV5xEGwvHGZDcJm7HjjSxuOTZpFw4qVeqHTeJwCW6N7vQ-OE1TuLQUn-GdugDnxKrWEk6Ud0XsEoLsoBTPlfFzzSPvoHUHuQFqKnM3w2zcm8p3S5GRKAb-3rLeCuxYNhrlczObZ1M3s9Xk79q-vGwO4n2Z_7p3H5kfpQXxAdkntKkKhgtG-N4yUpm45b84XnJ4g64RyUax2IQpg9LwCHD9qx5az3p3BTLwLzZplDcBuLtZlbLMIEQ7Cy-rI-x9Tw',
            'e' => 'AQAB',
        ];

        $rsaJwkWithAlg = $rsaJwk + ['alg' => 'RS256'];

        // Pre-generated EC key (P-256 / ES256)
        $ecPem = <<<'PEM'
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
-----END PUBLIC KEY-----
PEM;

        $ecJwk = [
            'kid' => 'VrUsVk0eLNVAMnejOiLLccHcixeqjj1wAHPjm3Hu6dM',
            'use' => 'sig',
            'kty' => 'EC',
            'crv' => 'prime256v1',
            'x' => 'EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84',
            'y' => 'kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY',
        ];

        $ecJwkWithAlg = $ecJwk + ['alg' => 'ES256'];

        return [
            'rsa without alg' => [$rsaPem, null, $rsaJwk],
            'rsa with alg' => [$rsaPem, Alg::RS256, $rsaJwkWithAlg],
            'ec without alg' => [$ecPem, null, $ecJwk],
            'ec with alg' => [$ecPem, Alg::ES256, $ecJwkWithAlg],
        ];
    }

    public static function algProvider(): array
    {
        return [
            [Alg::ES256, 'prime256v1'],
            [Alg::ES384, 'secp384r1'],
            [Alg::ES256K, 'secp256k1'],
        ];
    }
}
