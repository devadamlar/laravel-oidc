<?php

namespace DevAdamlar\LaravelOidc\Http\Introspection;

use DevAdamlar\LaravelOidc\Http\Client\OidcClient;
use DevAdamlar\LaravelOidc\Support\Key;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class PrivateKeyJwt extends Introspector
{
    protected function getBody(): array
    {
        $disk = $this->configLoader->get('key_disk');
        $privateKeyPath = $this->configLoader->get('private_key');
        $signingAlgorithm = $this->configLoader->get('rp_signing_algorithm') ?? $this->configLoader->get('signing_algorithm');
        $signingKey = openssl_pkey_get_private(Storage::disk($disk)->get($privateKeyPath));
        $client = OidcClient::make($this->configLoader);
        $kid = Key::thumbprint(Key::publicKey($signingKey));
        $jwt = JWT::encode([
            'iss' => $this->configLoader->get('client_id'),
            'sub' => $this->configLoader->get('client_id'),
            'aud' => $client->getIssuer()?->tokenEndpoint,
            'jti' => Str::uuid(),
            'exp' => now()->addMinute()->unix(),
            'nbf' => now()->unix(),
            'iat' => now()->unix(),
        ], $signingKey, $signingAlgorithm, $kid);

        return [
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $jwt,
        ];
    }

    protected function getRequired(): array
    {
        return ['client_id', 'private_key'];
    }
}
