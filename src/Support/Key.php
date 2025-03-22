<?php

namespace DevAdamlar\LaravelOidc\Support;

use Illuminate\Support\Facades\Storage;
use InvalidArgumentException;
use OpenSSLAsymmetricKey;

/**
 * JWK and key-related utilities for RSA and EC keys.
 */
class Key
{
    /**
     * @return array{keys: list<array<string, string>>}
     *
     * @throws InvalidArgumentException
     */
    public static function jwks(?string $alg = null, ?string $publicKeyPem = null, ?string $kid = null): array
    {
        return ['keys' => [self::jwk($alg, $publicKeyPem, $kid)]];
    }

    /**
     * @return array<string, string>
     *
     * @throws InvalidArgumentException
     */
    public static function jwk(?string $alg = null, ?string $publicKeyPem = null, ?string $kid = null): array
    {
        /** @var string|null $disk */
        $disk = config('auth.guards.api.key_disk', config('oidc.key_disk', config('filesystems.default')));
        $pem = $publicKeyPem ?? ($alg ? null : Storage::disk($disk)->get('certs/public.pem'));

        $publicKey = null;
        if ($pem !== null) {
            $parsed = openssl_pkey_get_public($pem);
            if (! $parsed) {
                throw new InvalidArgumentException('Invalid public key PEM.');
            }
            $publicKey = $parsed;
        }

        if (! $publicKey) {
            [, $publicKey] = match (true) {
                $alg === null, str_starts_with($alg, 'RS') => self::generateKeyPair(),
                str_starts_with($alg, 'ES') => self::generateEcKeyPair($alg),
                default => throw new InvalidArgumentException("Unsupported algorithm $alg for key generation."),
            };
        }

        $details = openssl_pkey_get_details($publicKey);
        if (! is_array($details) || ! isset($details['type'])) {
            throw new InvalidArgumentException('Invalid or unsupported key.');
        }

        /** @var int $type */
        $type = $details['type'];
        if (! in_array($type, [OPENSSL_KEYTYPE_RSA, OPENSSL_KEYTYPE_EC], true)) {
            throw new InvalidArgumentException('Unsupported key type.');
        }

        $kty = $type === OPENSSL_KEYTYPE_RSA ? 'RSA' : 'EC';

        if ($alg === null) {
            $alg = $type === OPENSSL_KEYTYPE_RSA ? 'RS256' : match ($details['bits']) {
                256 => 'ES256',
                384 => 'ES384',
                521 => 'ES512',
                default => throw new InvalidArgumentException('Unsupported EC key size.'),
            };
        }

        $kid ??= self::thumbprint($publicKey);

        $jwk = [
            'kid' => $kid,
            'alg' => $alg,
            'use' => 'sig',
            'kty' => $kty,
        ];

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
     * @throws InvalidArgumentException
     */
    public static function thumbprint(OpenSSLAsymmetricKey|string $key): string
    {
        if (is_string($key)) {
            $parsed = openssl_pkey_get_private($key) ?: openssl_pkey_get_public($key);
            if (! $parsed) {
                throw new InvalidArgumentException('Invalid PEM key string provided.');
            }
            $key = $parsed;
        }

        $details = openssl_pkey_get_details($key);

        $type = $details['type'];
        if (! in_array($type, [OPENSSL_KEYTYPE_RSA, OPENSSL_KEYTYPE_EC], true)) {
            throw new InvalidArgumentException('Unsupported key type.');
        }

        return $type === OPENSSL_KEYTYPE_RSA
            ? self::rsaThumbprint($details['rsa'] ?? [])
            : self::ecThumbprint($details['ec'] ?? []);
    }

    /**
     * @param  array{n: string, e: string}  $rsa
     */
    protected static function rsaThumbprint(array $rsa): string
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
    protected static function ecThumbprint(array $ec): string
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
     * @return array{OpenSSLAsymmetricKey, OpenSSLAsymmetricKey}
     *
     * @throws InvalidArgumentException
     */
    public static function generateKeyPair(): array
    {
        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);

        if (! $privateKey) {
            throw new InvalidArgumentException('Failed to generate RSA key pair.');
        }

        $details = openssl_pkey_get_details($privateKey);
        if (! is_array($details) || ! isset($details['key'])) {
            throw new InvalidArgumentException('Could not extract public key from private RSA key.');
        }

        $publicKey = openssl_pkey_get_public($details['key']);
        if (! $publicKey) {
            throw new InvalidArgumentException('Failed to parse generated public RSA key.');
        }

        return [$privateKey, $publicKey];
    }

    /**
     * @return array{OpenSSLAsymmetricKey, OpenSSLAsymmetricKey}
     *
     * @throws InvalidArgumentException
     */
    public static function generateEcKeyPair(string $alg): array
    {
        $curve = match ($alg) {
            'ES256' => 'prime256v1',
            'ES384' => 'secp384r1',
            'ES512' => 'secp521r1',
            default => throw new InvalidArgumentException("Unsupported EC algorithm $alg."),
        };

        $privateKey = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => $curve,
        ]);

        if (! $privateKey) {
            throw new InvalidArgumentException('Failed to generate EC key pair.');
        }

        $details = openssl_pkey_get_details($privateKey);
        if (! is_array($details) || ! isset($details['key'])) {
            throw new InvalidArgumentException('Could not extract public key from private EC key.');
        }

        $publicKey = openssl_pkey_get_public($details['key']);
        if (! $publicKey) {
            throw new InvalidArgumentException('Failed to parse generated public EC key.');
        }

        return [$privateKey, $publicKey];
    }
}
