<?php

declare(strict_types=1);

namespace DevAdamlar\LaravelOidc;

use DevAdamlar\LaravelOidc\Auth\OidcGuard;
use DevAdamlar\LaravelOidc\Config\ConfigLoader;
use DevAdamlar\LaravelOidc\Support\Alg;
use DevAdamlar\LaravelOidc\Support\Key;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Storage;

class LaravelOidcServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/oidc.php', 'oidc');
        Auth::extend('oidc', function ($app, $name, array $config) {
            return new OidcGuard(
                Auth::createUserProvider($config['provider'] ?? null),
                $app->request,
                $name,
                $app->make(ConfigLoader::class, ['config' => $config])
            );
        });
    }

    /**
     * Bootstrap any package services.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/oidc.php' => config_path('oidc.php'),
        ]);
        $this->registerJwksRoute();
    }

    private function registerJwksRoute(): void
    {
        /** @var string|null $jwksPath */
        $jwksPath = config('oidc.rp_jwks_path');
        /** @var string|null $privateKeyPath */
        $privateKeyPath = config('oidc.private_key');
        /** @var string|null $signingAlgorithm */
        $signingAlgorithm = config('oidc.signing_algorithm');
        /** @var array<string, array{driver: string, private_key?: string, signing_algorithm?: string, key_disk?: string}> $guards */
        $guards = config('auth.guards');
        /** @var string $disk */
        $disk = config('oidc.key_disk');
        /** @var string|null $cacheDriver */
        $cacheDriver = config('oidc.cache_driver');
        /** @var int|null $cacheTtl */
        $cacheTtl = config('oidc.cache_ttl');
        if ($jwksPath) {
            $keyData = collect();
            if ($privateKeyPath !== null) {
                $keyData->add([
                    'content' => Storage::disk($disk)->get($privateKeyPath),
                    'alg' => $signingAlgorithm,
                ]);
            }
            foreach ($guards as $guard) {
                if ($guard['driver'] !== 'oidc' ||
                    (! isset($guard['private_key']) && (! isset($guard['signing_algorithm']) || empty($privateKeyPath)))) {
                    continue;
                }
                if ($path = $guard['private_key'] ?? $privateKeyPath) {
                    $keyData->add([
                        'content' => Storage::disk($guard['key_disk'] ?? $disk)->get($path),
                        'alg' => $guard['signing_algorithm'] ?? $signingAlgorithm,
                    ]);
                }
            }
            if ($keyData->isEmpty()) {
                Log::warning('JWKS URI is set, but no private key found.');
            }

            $cacheKey = 'laravel-oidc:rp:jwks:'.md5(serialize($keyData));
            $jwks = Cache::driver($cacheDriver)->remember($cacheKey, $cacheTtl, function () use ($keyData) {
                /** @var array<array{pem: string, alg?: Alg}> $keys */
                $keys = $keyData->filter(fn ($key) => $key['content'] !== null || $key['alg'] !== null)
                    ->map(fn ($key) => [
                        'pem' => Key::publicKey($key['content'])['key'],
                        'alg' => Alg::from($key['alg']),
                    ])->toArray();

                return Key::jwks($keys);
            });
            Route::get($jwksPath, fn () => $jwks)->name('jwks');
        }
    }
}
