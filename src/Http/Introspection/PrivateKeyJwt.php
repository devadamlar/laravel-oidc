<?php

namespace DevAdamlar\LaravelOidc\Http\Introspection;

use DevAdamlar\LaravelOidc\Support\Key;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use InvalidArgumentException;

class PrivateKeyJwt extends Introspector
{
    protected function getBody(): array
    {
        /** @var string $disk */
        $disk = $this->configLoader->get('key_disk');
        /** @var string $signingAlgorithm */
        $signingAlgorithm = $this->configLoader->get('rp_signing_algorithm') ?? $this->configLoader->get('signing_algorithm');
        /** @var string $privateKeyPath */
        $privateKeyPath = $this->configLoader->get('private_key');
        $pem = Storage::disk($disk)->get($privateKeyPath);
        if ($pem === null) {
            throw new InvalidArgumentException('File `'.$privateKeyPath.'` not found in `'.$disk.'` disk.');
        }
        $signingKey = openssl_pkey_get_private($pem);
        if (! $signingKey) {
            throw new InvalidArgumentException('Given private key is not a valid PEM.');
        }
        $kid = Key::thumbprint(Key::publicKey($signingKey));
        $jwt = JWT::encode([
            'iss' => $this->configLoader->get('client_id'),
            'sub' => $this->configLoader->get('client_id'),
            'aud' => $this->endpoint,
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
