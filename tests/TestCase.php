<?php

declare(strict_types=1);

namespace DevAdamlar\LaravelOidc\Tests;

use DevAdamlar\LaravelOidc\LaravelOidcServiceProvider;
use DevAdamlar\LaravelOidc\Testing\ActingAs;
use DevAdamlar\LaravelOidc\Tests\Models\User;
use Illuminate\Support\Str;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    use ActingAs;

    protected function setUp(): void
    {
        parent::setUp();
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('auth.defaults.guard', 'api');
        $app['config']->set('auth.providers.users.model', User::class);

        $app['config']->set('auth.guards.api', [
            'driver' => 'oidc',
            'provider' => 'users',
            'issuer' => 'https://oidc-server.test/auth',
            'introspection_client_id' => fake()->word,
            'introspection_client_secret' => Str::random(64),
            'audience' => 'phpunit',
            'cache_ttl' => 0,
        ]);
        $app['config']->set('app.key', 'base64:'.base64_encode(Str::random(32)));
        $app['config']->set('app.debug', true);
    }

    protected function getPackageProviders($app): array
    {
        return [LaravelOidcServiceProvider::class];
    }
}
