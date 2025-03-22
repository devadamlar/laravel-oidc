<?php

declare(strict_types=1);

namespace DevAdamlar\LaravelOidc\Testing;

use DevAdamlar\LaravelOidc\Support\Key;
use Firebase\JWT\JWT;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;
use OpenSSLAsymmetricKey;

trait ActingAs
{
    public function actingAs(Authenticatable $user, $guard = null)
    {
        $guard = $guard ?? Auth::getDefaultDriver();
        if (Config::get('auth.guards.'.$guard.'.driver') === 'oidc' && ! isset($this->defaultHeaders['Authorization'])) {
            $principal = Config::get('auth.guards.'.$guard.'.principal_identifier') ??
                Config::get('oidc.principal_identifier');
            $token = self::buildJwt([
                $principal => $user->getAuthIdentifier(),
            ]);
            $this->withHeader('Authorization', 'Bearer '.$token);
        }

        return $this->be($user, $guard);
    }

    public function withToken(string|array|null $token, string $type = 'Bearer'): self
    {
        if (is_array($token)) {
            $token = self::buildJwt($token);
        }

        if ($token === null) {
            return $this;
        }

        return parent::withToken($token, $type);
    }

    protected static function buildJwt(
        array $payload = [],
        ?OpenSSLAsymmetricKey $privateKey = null,
        ?OpenSSLAsymmetricKey $publicKey = null,
        string $encryptionAlgorithm = 'RS256',
    ): string {
        $baseUrl = 'http://oidc-server.test/auth';
        $payload = array_merge([
            'iss' => $baseUrl,
            'sub' => 'unique-id',
            'azp' => 'client-id',
            'aud' => 'phpunit',
            'exp' => time() + 300,
            'iat' => time(),
        ], $payload);

        if (! $privateKey && ! $publicKey) {
            $openSSLConfig = [
                'digest_alg' => 'sha256',
                'private_key_bits' => 1024,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ];
            [$privateKey] = self::generateKeyPair($openSSLConfig);
        }

        $kid = self::fakeRequestsToOidcServer($payload['iss'], array_merge(['active' => true], $payload));

        return JWT::encode($payload, $privateKey, $encryptionAlgorithm, $kid);
    }

    protected static function generateKeyPair(?array $openSSLConfig = null): array
    {
        if (! $openSSLConfig) {
            $openSSLConfig = [
                'digest_alg' => 'sha256',
                'private_key_bits' => 1024,
                'private_key_type' => OPENSSL_KEYTYPE_RSA,
            ];
        }
        $privateKey = openssl_pkey_new($openSSLConfig);
        $publicKey = openssl_pkey_get_details($privateKey)['key'];

        $disk = config('auth.guards.api.key_disk', config('oidc.key_disk', config('filesystems.default')));
        Storage::fake($disk);

        Storage::disk($disk)->put('certs/public.pem', $publicKey);

        return [$privateKey, openssl_pkey_get_public($publicKey)];
    }

    protected static function fakeRequestsToOidcServer(
        string $issuer = 'http://oidc-server.test/auth',
        array $introspectionResponse = ['active' => true],
    ): string {
        $jwks = Key::jwks();
        Http::fake([
            '*/.well-known/openid-configuration' => Http::response([
                'issuer' => $issuer,
                'authorization_endpoint' => "$issuer/protocol/openid-connect/auth",
                'jwks_uri' => "$issuer/protocol/openid-connect/certs",
                'introspection_endpoint' => "$issuer/protocol/openid-connect/token/introspect",
            ]),
            '*/protocol/openid-connect/token/introspect' => Http::response($introspectionResponse),
            '*/protocol/openid-connect/certs' => Http::response($jwks),
        ]);

        return $jwks['keys'][0]['kid'];
    }
}
