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
        string $signingAlgorithm = 'RS256',
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

        ['private' => $privateKey, 'public' => $publicKey] = $privateKey ?
            ['private' => $privateKey, 'public' => Key::publicKey($privateKey)] :
            Key::generateRsaKeyPair();

        self::storeKey($publicKey['key']);

        self::fakeRequestsToOidcServer($payload['iss'], array_merge(['active' => true], $payload));

        $kid = Key::thumbprint($publicKey);

        return JWT::encode($payload, $privateKey, $signingAlgorithm, $kid);
    }

    protected static function storeKey(string $key, string $path = 'certs/public.pem'): void
    {
        $disk = config('auth.guards.api.key_disk', config('oidc.key_disk', config('filesystems.default')));
        Storage::fake($disk);

        Storage::disk($disk)->put($path, $key);
    }

    protected static function fakeRequestsToOidcServer(
        string $issuer = 'http://oidc-server.test/auth',
        array $introspectionResponse = ['active' => true],
    ): void {
        /** @var string|null $disk */
        $disk = config('auth.guards.api.key_disk', config('oidc.key_disk', config('filesystems.default')));
        $jwks = Key::jwks([['pem' => Storage::disk($disk)->get('certs/public.pem') ?? Key::generateRsaKeyPair()['public']['key']]]);
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
