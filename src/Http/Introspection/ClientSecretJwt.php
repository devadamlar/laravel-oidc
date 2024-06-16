<?php

namespace DevAdamlar\LaravelOidc\Http\Introspection;

use Firebase\JWT\JWT;
use Illuminate\Support\Str;

class ClientSecretJwt extends Introspector
{
    protected function getBody(): array
    {
        $signingKey = $this->configLoader->get('client_secret');
        $jwt = JWT::encode([
            'iss' => $this->configLoader->get('client_id'),
            'sub' => $this->configLoader->get('client_id'),
            'aud' => $this->configLoader->get('issuer'),
            'jti' => Str::uuid(),
            'exp' => now()->addMinute()->unix(),
            'nbf' => now()->unix(),
            'iat' => now()->unix(),
        ], $signingKey, 'HS256');

        return [
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion' => $jwt,
        ];
    }
}
