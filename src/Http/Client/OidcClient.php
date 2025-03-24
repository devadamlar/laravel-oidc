<?php

namespace DevAdamlar\LaravelOidc\Http\Client;

use DevAdamlar\LaravelOidc\Config\ConfigLoader;
use DevAdamlar\LaravelOidc\Exceptions\OidcServerException;
use DevAdamlar\LaravelOidc\Http\Introspection\Introspector;
use DevAdamlar\LaravelOidc\Http\Issuer;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use InvalidArgumentException;
use stdClass;

class OidcClient
{
    protected ?Issuer $issuer = null;

    public function __construct(protected ConfigLoader $configLoader) {}

    public static function make(ConfigLoader $configLoader): self
    {
        return app()->has(self::class) ?
            app()->get(self::class) : app()->make(self::class, ['configLoader' => $configLoader]);
    }

    public function getIssuer(): ?Issuer
    {
        if ($this->issuer === null) {
            return $this->discover();
        }

        return $this->issuer;
    }

    public function setIssuer(Issuer $issuer): void
    {
        $this->issuer = $issuer;
    }

    /**
     * @throws InvalidArgumentException
     * @throws OidcServerException
     */
    private function discover(): ?Issuer
    {
        $url = $this->configLoader->get('issuer');
        if (empty($url)) {
            return null;
        }
        if (! Str::isUrl($url, ['http', 'https'])) {
            throw new InvalidArgumentException('Issuer '.$url.' is not a valid HTTP URL.');
        }
        $document = Cache::driver($this->configLoader->get('cache_driver'))->remember(
            'laravel-oidc:'.$url,
            $this->configLoader->get('cache_ttl'),
            function () {
                $response = Http::get($this->configLoader->get('issuer').'/.well-known/openid-configuration');
                if ($response->failed() || empty($response->json())) {
                    throw new OidcServerException('Failed to fetch OpenID Connect discovery document');
                }

                return $response->json();
            }
        );

        $this->issuer = $document !== null ? new Issuer($document) : null;

        return $this->issuer;
    }

    /**
     * @throws OidcServerException
     */
    public function downloadKeys(): array
    {
        $cache = Cache::driver($this->configLoader->get('cache_driver'));
        $ttl = $this->configLoader->get('cache_ttl');
        $issuer = $this->getIssuer();

        $response = Http::get($issuer->jwksUri);

        if ($response->failed() || empty($response->json())) {
            throw new OidcServerException('Failed to fetch public keys at '.$issuer->jwksUri.'.');
        }

        $jwks = $response->json();

        foreach ($jwks['keys'] ?? [] as $jwk) {
            if (! isset($jwk['kid'])) {
                continue;
            }

            $cacheKey = 'laravel-oidc:'.$issuer->issuer.':jwk:'.$jwk['kid'];
            $cache->put($cacheKey, $jwk, $ttl);
        }

        return $jwks;
    }

    public function introspect(string $token, ?string $endpoint = null, ?string $tokenTypeHint = 'access_token'): ?stdClass
    {
        $supportedAuthMethods = $this->getIssuer()?->introspectionEndpointAuthMethodsSupported;
        $configuredAuthMethod = $this->configLoader->get('introspection_auth_method');
        if (isset($supportedAuthMethods) && ! in_array($configuredAuthMethod, $supportedAuthMethods)) {
            throw new InvalidArgumentException('Given client auth method is not supported by the Authorization server');
        }

        $endpoint = $endpoint ?? $this->getIssuer()?->introspectionEndpoint;

        $introspector = Introspector::make($this->configLoader);

        if ($endpoint === null) {
            throw new InvalidArgumentException('No introspection endpoint found');
        }

        return $introspector->introspect($endpoint, $token, $tokenTypeHint);
    }
}
