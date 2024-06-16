<?php

namespace DevAdamlar\LaravelOidc\Http;

class Issuer
{
    public readonly string $issuer;

    public readonly string $jwksUri;

    public readonly string $authorizationEndpoint;

    public readonly ?string $tokenEndpoint;

    public readonly ?string $userinfoEndpoint;

    public readonly ?string $endSessionEndpoint;

    public readonly ?string $introspectionEndpoint;

    public readonly ?string $revocationEndpoint;

    public readonly ?string $registrationEndpoint;

    public readonly ?array $scopesSupported;

    public readonly ?array $userinfoSigningAlgValuesSupported;

    public readonly ?array $userinfoEncryptionAlgValuesSupported;

    public readonly ?array $userinfoEncryptionEncValuesSupported;

    public readonly ?array $tokenEndpointAuthMethodsSupported;

    public readonly ?array $tokenEndpointAuthSigningAlgValuesSupported;

    public readonly ?array $introspectionEndpointAuthMethodsSupported;

    public readonly ?array $introspectionEndpointAuthSigningAlgValuesSupported;

    public function __construct(array $config)
    {
        $this->issuer = $config['issuer'];
        $this->jwksUri = $config['jwks_uri'];
        $this->authorizationEndpoint = $config['authorization_endpoint'];
        $this->tokenEndpoint = $config['token_endpoint'] ?? null;
        $this->userinfoEndpoint = $config['userinfo_endpoint'] ?? null;
        $this->endSessionEndpoint = $config['end_session_endpoint'] ?? null;
        $this->introspectionEndpoint = $config['introspection_endpoint'] ?? null;
        $this->revocationEndpoint = $config['revocation_endpoint'] ?? null;
        $this->registrationEndpoint = $config['registration_endpoint'] ?? null;
        $this->scopesSupported = $config['scopes_supported'] ?? null;
        $this->userinfoSigningAlgValuesSupported = $config['userinfo_signing_alg_values_supported'] ?? null;
        $this->userinfoEncryptionAlgValuesSupported = $config['userinfo_encryption_alg_values_supported'] ?? null;
        $this->userinfoEncryptionEncValuesSupported = $config['userinfo_encryption_enc_values_supported'] ?? null;
        $this->tokenEndpointAuthMethodsSupported = $config['token_endpoint_auth_methods_supported'] ?? null;
        $this->tokenEndpointAuthSigningAlgValuesSupported = $config['token_endpoint_auth_signing_alg_values_supported'] ?? null;
        $this->introspectionEndpointAuthMethodsSupported = $config['introspection_endpoint_auth_methods_supported'] ?? null;
        $this->introspectionEndpointAuthSigningAlgValuesSupported = $config['introspection_endpoint_auth_signing_alg_values_supported'] ?? null;
    }
}
