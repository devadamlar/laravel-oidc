<?php

namespace DevAdamlar\LaravelOidc\Support;

use InvalidArgumentException;
use OpenSSLAsymmetricKey;

/**
 * JWK and key-related utilities for RSA and EC keys.
 */
class Key
{
    /**
     * @param  array<array{pem: string, alg?:Alg}>  $keys
     * @return array{keys: list<array<string, string>>}
     */
    public static function jwks(array $keys): array
    {
        $jwks = [];
        foreach ($keys as $key) {
            $jwks[] = self::jwk($key['pem'], $key['alg'] ?? null);
        }

        return ['keys' => $jwks];
    }

    /**
     * @return array<string, string>
     *
     * @throws InvalidArgumentException
     */
    public static function jwk(string $pem, ?Alg $alg = null): array
    {
        $parsed = openssl_pkey_get_public($pem);
        if (! $parsed) {
            throw new InvalidArgumentException('Invalid public key PEM.');
        }
        $publicKey = $parsed;

        /** @var array{type: int, key: string, rsa?: array{n: string, e: string}, ec?: array{curve_name?: string, x: string, y: string}} $details */
        $details = openssl_pkey_get_details($publicKey);

        $type = $details['type'];
        if (! in_array($type, [OPENSSL_KEYTYPE_RSA, OPENSSL_KEYTYPE_EC], true)) {
            throw new InvalidArgumentException('Unsupported key type.');
        }

        $kty = $type === OPENSSL_KEYTYPE_RSA ? 'RSA' : 'EC';

        $kid = self::thumbprint($details);

        $jwk = [
            'kid' => $kid,
            'use' => 'sig',
            'kty' => $kty,
        ];

        if ($alg !== null) {
            $jwk['alg'] = $alg->value;
        }

        if ($kty === 'RSA' && isset($details['rsa'])) {
            $jwk['n'] = self::base64url($details['rsa']['n']);
            $jwk['e'] = self::base64url($details['rsa']['e']);
        } elseif ($kty === 'EC' && isset($details['ec'])) {
            $jwk['crv'] = $details['ec']['curve_name'] ?? 'P-256';
            $jwk['x'] = self::base64url($details['ec']['x']);
            $jwk['y'] = self::base64url($details['ec']['y']);
        }

        return $jwk;
    }

    /**
     * @param  array{type: int, key: string, rsa?: array{n: string, e: string}, ec?: array{curve_name?: string, x: string, y: string}}  $publicKey
     */
    public static function thumbprint(array $publicKey): string
    {
        $type = $publicKey['type'];
        if ($type === OPENSSL_KEYTYPE_RSA && isset($publicKey['rsa'])) {
            return self::rsaThumbprint($publicKey['rsa']);
        }
        if ($type === OPENSSL_KEYTYPE_EC && isset($publicKey['ec'])) {
            return self::ecThumbprint($publicKey['ec']);
        }

        throw new InvalidArgumentException('Unsupported key type.');
    }

    /**
     * @param  array{n: string, e: string}  $rsa
     */
    private static function rsaThumbprint(array $rsa): string
    {
        $e = self::base64url($rsa['e']);
        $n = self::base64url($rsa['n']);

        $thumbprint = json_encode(['e' => $e, 'kty' => 'RSA', 'n' => $n], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (! is_string($thumbprint)) {
            throw new InvalidArgumentException('Failed to encode RSA thumbprint JSON.');
        }

        return self::base64url(hash('sha256', $thumbprint, true));
    }

    /**
     * @param  array{x: string, y: string, curve_name?: string}  $ec
     */
    private static function ecThumbprint(array $ec): string
    {
        $x = self::base64url($ec['x']);
        $y = self::base64url($ec['y']);
        $crv = $ec['curve_name'] ?? 'P-256';

        $thumbprint = json_encode(['crv' => $crv, 'kty' => 'EC', 'x' => $x, 'y' => $y], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (! is_string($thumbprint)) {
            throw new InvalidArgumentException('Failed to encode EC thumbprint JSON.');
        }

        return self::base64url(hash('sha256', $thumbprint, true));
    }

    protected static function base64url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @return array{type: int, key: string, rsa?: array{n: string, e: string}, ec?: array{curve_name?: string, x: string, y: string}}
     */
    public static function publicKey(OpenSSLAsymmetricKey|string $privateKey): array
    {
        if (is_string($privateKey)) {
            $privateKey = openssl_pkey_get_private($privateKey);
        }
        /** @var array{key: string}|false $details */
        $details = $privateKey ? openssl_pkey_get_details($privateKey) : false;

        $publicKey = $details ? openssl_pkey_get_public($details['key']) : false;

        /** @var array{type: int, key: string, rsa?: array{n: string, e: string}, ec?: array{curve_name?: string, x: string, y: string}} $details */
        $details = $publicKey ? openssl_pkey_get_details($publicKey) :
            throw new InvalidArgumentException('Could not extract public key from private RSA key.');

        return $details;
    }

    /**
     * @return array{private: OpenSSLAsymmetricKey, public: array{type: int, key: string, rsa?: array{n: string, e: string}, ec?: array{curve_name?: string, x: string, y: string}}}
     */
    public static function generateRsaKeyPair(): array
    {
        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);

        if (! $privateKey) {
            throw new InvalidArgumentException('Failed to generate RSA key pair.');
        }

        $publicKey = Key::publicKey($privateKey);

        return ['private' => $privateKey, 'public' => $publicKey];
    }

    /**
     * @return array{private: OpenSSLAsymmetricKey, public: array{type: int, key: string, rsa?: array{n: string, e: string}, ec?: array{curve_name?: string, x: string, y: string}}}
     */
    public static function generateEcKeyPair(Alg $alg): array
    {
        $curve = match ($alg) {
            Alg::ES256 => 'prime256v1',
            Alg::ES384 => 'secp384r1',
            Alg::ES256K => 'secp256k1',
        };

        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $curve,
        ]);

        if (! $privateKey) {
            throw new InvalidArgumentException('Failed to generate EC key pair.');
        }

        $publicKey = self::publicKey($privateKey);

        return ['private' => $privateKey, 'public' => $publicKey];
    }
}
