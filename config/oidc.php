<?php

declare(strict_types=1);

return [
    /*
    |--------------------------------------------------------------------------
    | OpenID Connect Provider URL
    |--------------------------------------------------------------------------
    |
    | REQUIRED IF a public key is not set OR introspection is enabled.
    | MUST be a valid HTTP URL.
    |
    | Preference is given to the public key over issuer if both are set.
    |
    | Issuer is necessary to get information contained in:
    | `<issuer>/.well-known/openid-configuration`
    |
    | `jwks_uri` from the discovery document will be used
    | to get the public key for signature verification.
    |
    | `introspection_endpoint` from the discovery document will be used
    | to introspect the token if introspection is enabled.
    |
    | All the above details are part of the OIDC specification,
    |, so this package can work with any OIDC compliant provider.
    |
    | Responses from these endpoints will be cached.
    |
    */

    'issuer' => env('OIDC_ISSUER'),

    /*
    |--------------------------------------------------------------------------
    | Public key for signature verification
    |--------------------------------------------------------------------------
    |
    | REQUIRED IF issuer is not set.
    | This can be the key extract or a path to the key file.
    |
    | Preference is given to the public key over issuer if both are set.
    |
    | Public key is necessary to verify the signature of the JWT
    | so that the authenticity of the token can be ensured.
    |
    */

    'public_key' => env('OIDC_PUBLIC_KEY'),
    'signing_algorithm' => env('OIDC_SIGNING_ALGORITHM', 'RS256'),

    /*
    |--------------------------------------------------------------------------
    | Introspection configuration
    |--------------------------------------------------------------------------
    |
    | You can choose to validate the token by sending it over to the authorization server.
    | This is useful when the token is opaque, or you want to make sure the token is not revoked.
    |
    | The following auth methods are supported:
    | - client_secret_basic
    | - client_secret_post
    | - client_secret_jwt
    | - private_key_jwt
    |
    | Information from the discovery document, if found, will also be used
    | to narrow down the supported auth methods for introspection.
    |
    | `private_key` expects the path to the private key file of the RP
    | and MUST be set IF the `introspection_auth_method` is `private_key_jwt`.
    |
    */

    'use_introspection' => env('OIDC_USE_INTROSPECTION', false),
    'introspection_auth_method' => env('OIDC_INTROSPECTION_AUTH_METHOD', 'client_secret_basic'),
    'client_id' => env('OIDC_CLIENT_ID'),
    'client_secret' => env('OIDC_CLIENT_SECRET'),
    'private_key' => env('OIDC_PRIVATE_KEY'),

    /*
    |--------------------------------------------------------------------------
    | JWT configuration
    |--------------------------------------------------------------------------
    |
    | `principal_identifier` is the claim to use as the principal identifier.
    | This will be the claim matching against the auth identifier
    | defined in the `User` model.
    |
    | `leeway` is the number of seconds to allow for clock skew.
    | This is useful when the clocks of the RP and OP are not in sync.
    |
    | `audience` is the expected audience of the token.
    | This is useful when the RP is expecting a token meant for it.
    | No validation will be done if this is not set.
    |
    */

    'principal_identifier' => env('OIDC_PRINCIPAL_IDENTIFIER', 'sub'),
    'leeway' => env('OIDC_LEEWAY', 0),
    'audience' => env('OIDC_AUDIENCE'),

    /*
    |--------------------------------------------------------------------------
    | Access token input key
    |--------------------------------------------------------------------------
    |
    | The key to look for the access token in the request body.
    | This will be used only if there is no bearer token
    | in the Authorization header.
    |
    */

    'input_key' => env('OIDC_TOKEN_INPUT_KEY', 'access_token'),

    /*
    |--------------------------------------------------------------------------
    | Disk storage for keys
    |--------------------------------------------------------------------------
    |
    | You can store the keys related to OIDC in a different disk.
    | These can be OP's public key and RP's private key.
    |
    */

    'key_disk' => env('OIDC_KEY_DISK', config('filesystems.default')),

    /*
    |--------------------------------------------------------------------------
    | Cache configuration
    |--------------------------------------------------------------------------
    |
    | Discovery document and JWKS from the issuer will be cached to reduce the
    | number of HTTP requests made to the issuer.
    |
    | You can control the store and the TTL of the cache here.
    |
    | Make sure to clear the cache when the issuer rotates its keys.
    | Cached data for a given issuer can be cleared by running
    |
    | `php artisan cache:forget <issuer>*`.
    |
    */

    'cache_driver' => env('OIDC_CACHE_DRIVER', env('CACHE_DRIVER')),
    'cache_ttl' => env('OIDC_CACHE_TTL', env('APP_ENV') === 'production' ? 86400 : 5),
];
