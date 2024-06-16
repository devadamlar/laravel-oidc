# Laravel OIDC Package

## Overview
This package allows Laravel applications to authenticate users using JWT tokens from OpenID Connect (OIDC) providers.
It integrates smoothly with Laravel's built-in authentication system
and offers flexibility for multi-tenant architectures by allowing configurations to be tailored on a per-guard basis.

## Installation
1. Install the package via Composer:
   ```bash
   composer require devadamlar/laravel-oidc
   ```
2. Publish the configuration file:
   ```bash
   php artisan vendor:publish --provider="DevAdamlar\LaravelOidc\LaravelOidcServiceProvider
   ```

## Usage
You start by defining a guard in the `config/auth.php` file.

```php
'guards' => [
    'api' => [
        'driver' => 'oidc',
        'provider' => 'users',
        'issuer' => 'https://your-auth-server.com', // must contain /.well-known/openid-configuration
    ],
],
```

Note that the guard includes the `issuer` URL, which is the base URL of your OIDC provider.
This URL is used to fetch the discovery document containing the public keys.
The package will cache the public keys from the discovery document,
ensuring no repetitive requests are made to the OIDC provider each time a token is verified.

Alternatively,
you can provide the public key directly in the configuration file avoiding the need to fetch the discovery document.
```php
'guards' => [
    'api' => [
        'driver' => 'oidc',
        'provider' => 'users',
        'public_key' => 'your-public-key', // or '/path/to/public-key.pem'
        'key_disk' => 'private-s3', // optional
    ],
],
```
Storage disk for the public key is set to the default disk defined in the `filesystems` configuration file
but can be changed by setting `key_disk` in the guard configuration or `OIDC_KEY_DISK` environment variable.

When both the issuer URL and the public key are set for a guard,
the package prioritizes the public key for verifying the tokens.
However, it will never fall back to the issuer URL if it is present.

### Authenticating Requests
You can use the `auth` middleware with the defined guard to protect your routes.
For example, the following route will return the authenticated user if the request is authenticated with the `api` guard
```php
Route::middleware('auth:api')->get('/user', function (Request $request) {
    return auth()->user(); // User model
});
```

### Model retrieval
The model defined in the provider
must implement `Illuminate\Contracts\Auth\Authenticatable` as the default `User` model does.
It has to contain the `sub` claim from the token as the auth identifier.
The attribute for auth identifier is the primary key of the model by default,
but you can change it by overriding the `getAuthIdentifierName` method in the model:

```php
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    public function getAuthIdentifierName()
    {
        return 'auth_uuid';
    }
}
```

## Global Configuration

You can set global configurations in the `.env` file for the entire application.
For example, you can set the issuer URL and the public key in the `.env` file as follows:

```env
OIDC_ISSUER=https://your-auth-server.com
OIDC_PUBLIC_KEY=/path/to/public-key.pem
```

This way, you can avoid repeating the same configurations for each guard: for each missing configuration in a guard,
the package will fall back to the global configuration.

For issuer URLs, you can also set a shared base URL in the global configuration.
The guard-level configuration can then extend this base URL with additional path segments.
For example,
you can set the base URL in the global configuration as follows:

```env
OIDC_ISSUER=https://your-auth-server.com
```

And then extend it in the guard-level configuration as follows:

```php
'guards' => [
    'api' => [
        'driver' => 'oidc',
        'provider' => 'users',
        'issuer' => 'tenant1',
    ],
],
```

In this case, the issuer URL for the `api` guard will be `https://your-auth-server.com/tenant1`.

If the guard-level issuer configuration is a full URL, it will override the base URL instead.
For example, the following configuration:
```php
'guards' => [
    'api' => [
        'driver' => 'oidc',
        'provider' => 'users',
        'issuer' => 'https://tenant1-auth-server.com',
    ],
],
```
will ignore whatever is set in the global configuration and use `https://tenant1-auth-server.com` as the issuer URL.

You can publish the configuration file and refer to the documentation there for all available options:
```bash
php artisan vendor:publish --provider="DevAdamlar\LaravelOidc\LaravelOidcServiceProvider
```

Every configuration option in the published file is also available as a guard-level configuration.

### Introspection

Introspection is a process where the validity of a token is verified by sending it to the authorization server.
This is an alternative to local validation,
where the server checks the token's signature and claims itself in real-time.

#### Benefits of Introspection
1. **Revoke Checking**: Introspection can check if a token has been revoked, which local validation cannot do.
2. **Opaque Tokens**: It allows validation of opaque tokens that cannot be validated locally because they don't contain the required information.
3. **Dynamic Information**: Introspection can provide real-time information about the token, ensuring up-to-date verification.

#### Basic Setup for Introspection
To enable introspection, configure the following in your `.env` file:
```env
OIDC_USE_INTROSPECTION=true
OIDC_INTROSPECTION_AUTH_METHOD=client_secret_basic
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
```

For a guard-level configuration, set the following:
```php
'guards' => [
    'api' => [
        'driver' => 'oidc',
        'provider' => 'users',
        'issuer' => 'https://your-auth-server.com',
        'use_introspection' => true,
        'introspection_auth_method' => 'client_secret_basic', // [, 'client_secret_post', 'client_secret_jwt', 'private_key_jwt']
        'client_id' => 'your-client-id',
        'client_secret' => 'your-client-secret',
    ],
    // Other guards...
],
```

### Caching
The package caches the public keys fetched from the discovery document
to avoid repetitive requests to the OIDC provider.
The cache duration is set to 24 hours by default for `production` environment
but can be changed in the configuration files or the `.env` file.
```env
OIDC_CACHE_TTL=1440
```

OPs don't usually change their public keys frequently, but if it happens, you can clear the cache to fetch the new keys:
```bash
php artisan cache:forget https://your-issuer-url.com
php artisan cache:forget https://your-issuer-url.com:jwks
```

## TODO

- [ ] Place coverage, build, security, maintainability badges
- [ ] Incorporate git hooks
- [ ] Implement a CI/CD pipeline with GitHub Actions
- [ ] Add a contribution guide
- [ ] Dockerize the application
- [ ] Add a command to clear the cache
- [ ] Add a hook for token validation check
- [ ] Add a hook to clear the cache when the public keys change
