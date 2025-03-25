<?php

declare(strict_types=1);

namespace DevAdamlar\LaravelOidc\Testing;

use DevAdamlar\LaravelOidc\Support\Alg;
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

    /**
     * @internal
     */
    protected static function buildJwt(
        array $payload = [],
        ?OpenSSLAsymmetricKey $privateKey = null,
        Alg $signingAlgorithm = Alg::RS256,
    ): string {
        ['private' => $privateKey, 'public' => $publicKey] = $privateKey ?
            ['private' => $privateKey, 'public' => Key::publicKey($privateKey)] :
            ($signingAlgorithm->isRsa() ? Key::generateRsaKeyPair() : Key::generateEcKeyPair($signingAlgorithm));
        openssl_pkey_export($privateKey, $privateKeyPem);
        self::storeKeys($privateKeyPem, $publicKey['key']);

        $baseUrl = 'http://oidc-server.test/auth';
        $payload = array_merge([
            'iss' => $baseUrl,
            'sub' => 'unique-id',
            'azp' => 'client-id',
            'aud' => 'phpunit',
            'exp' => time() + 300,
            'iat' => time(),
        ], $payload);
        self::fakeRequestsToOidcServer($payload['iss'], array_merge(['active' => true], $payload), Key::jwks([['pem' => $publicKey['key']]]));
        $kid = Key::thumbprint($publicKey);

        return JWT::encode($payload, $privateKey, $signingAlgorithm->value, $kid);
    }

    /**
     * @internal
     */
    protected static function storeKeys(string $privateKeyPem, string $publicKeyPem): void
    {
        $disk = config('auth.guards.api.key_disk', config('oidc.key_disk', config('filesystems.default')));
        Storage::fake($disk);

        foreach (config('auth.guards') as $guard) {
            if ($guard['driver'] === 'oidc' && ! empty($guard['private_key'])) {
                Storage::disk($disk)->put($guard['private_key'], $privateKeyPem);
            }
            if ($guard['driver'] === 'oidc' && ! empty($guard['public_key'])) {
                Storage::disk($disk)->put($guard['public_key'], $publicKeyPem);
            }
        }

        if (! empty(config('oidc.private_key'))) {
            Storage::disk($disk)->put(config('oidc.private_key'), $privateKeyPem);
        }

        if (! empty(config('oidc.public_key'))) {
            Storage::disk($disk)->put(config('oidc.public_key'), $publicKeyPem);
        }
    }

    /**
     * @internal
     */
    protected static function fakeRequestsToOidcServer(
        string $issuer = 'http://oidc-server.test/auth',
        array $introspectionResponse = ['active' => true],
        ?array $jwks = null
    ): void {
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
    }
}
