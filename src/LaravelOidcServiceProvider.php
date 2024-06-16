<?php

declare(strict_types=1);

namespace DevAdamlar\LaravelOidc;

use DevAdamlar\LaravelOidc\Auth\OidcGuard;
use DevAdamlar\LaravelOidc\Config\ConfigLoader;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use Illuminate\Support\Facades\Auth;

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
    }
}
