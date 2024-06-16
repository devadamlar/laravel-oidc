<?php

namespace DevAdamlar\LaravelOidc\Tests\Feature\Auth;

use DevAdamlar\LaravelOidc\Tests\Models\User;
use DevAdamlar\LaravelOidc\Tests\TestCase;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

class OidcGuardTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->app['db']->connection()->getSchemaBuilder()->create('users', function (Blueprint $table) {
            $table->increments('id');
            $table->string('auth_id');
            $table->timestamps();
        });
    }

    protected function getPackageProviders($app): array
    {
        Route::get('/callback', function () {
            return 'Authenticated';
        })->middleware('auth:api');

        return parent::getPackageProviders($app);
    }

    public function test_it_can_authenticate_user_with_just_issuer()
    {
        // Arrange
        User::query()->create([
            'auth_id' => 'unique-id',
        ]);
        Config::set('auth.guards.api', [
            'public_key' => null,
            'issuer' => 'http://oidc-server.test/auth',
            'driver' => 'oidc',
            'provider' => 'users',
        ]);

        // Act
        $response = $this->withToken(self::buildJwt(['sub' => 'unique-id']))->getJson('/callback');

        // Assert
        $response->assertStatus(200);
    }

    public function test_it_can_authenticate_user_with_just_a_public_key()
    {
        // Arrange
        $token = self::buildJwt(['sub' => 'unique-id']);
        Cache::flush();
        User::query()->create([
            'auth_id' => 'unique-id',
        ]);
        Config::set('auth.guards.api', [
            'public_key' => 'certs/public.pem',
            'issuer' => null,
            'driver' => 'oidc',
            'provider' => 'users',
        ]);

        // Act
        $response = $this->withToken($token)->getJson('/callback');

        // Assert
        $response->assertStatus(200);
        Http::assertNothingSent();
    }

    public function test_it_can_authenticate_user_using_introspection()
    {
        // Arrange
        User::query()->create([
            'auth_id' => 'unique-id',
        ]);
        Config::set('auth.guards.api', [
            'use_introspection' => true,
            'issuer' => 'http://oidc-server.test/auth',
            'client_id' => 'client-id',
            'client_secret' => 'client-secret',
            'driver' => 'oidc',
            'provider' => 'users',
        ]);

        // Act
        $response = $this->withToken(self::buildJwt(['sub' => 'unique-id']))->getJson('/callback');

        // Assert
        $response->assertOk();
    }

    /**
     * @dataProvider tokenProvider
     *
     * @return void
     */
    public function test_should_not_authenticate_if_token_is_missing_or_invalid(?string $token)
    {
        // Arrange
        Config::set('auth.guards.api', [
            'use_introspection' => true,
            'issuer' => 'http://oidc-server.test/auth',
            'client_id' => 'client-id',
            'client_secret' => 'client-secret',
            'driver' => 'oidc',
            'provider' => 'users',
        ]);

        self::fakeRequestsToOidcServer(introspectionResponse: ['active' => false]);

        // Act
        $response = $this->withToken($token)->getJson('/callback');

        // Assert
        $response->assertUnauthorized();
    }

    public static function tokenProvider(): array
    {
        return [
            'no token' => [null],
            'empty token' => [''],
            'invalid token' => ['invalid-token'],
        ];
    }
}
