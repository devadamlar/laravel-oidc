<?php

namespace DevAdamlar\LaravelOidc\Tests\Feature\Testing;

use DevAdamlar\LaravelOidc\Testing\ActingAs;
use DevAdamlar\LaravelOidc\Tests\Models\User;
use DevAdamlar\LaravelOidc\Tests\TestCase;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;

class ActingAsTest extends TestCase
{
    use ActingAs;
    use RefreshDatabase;

    private function getPublicKeys(): array
    {
        return JWK::parseKeySet(Http::get('http://oidc-server.test/auth/protocol/openid-connect/certs')->json(), 'RS256');
    }

    public function test_should_set_authorization_header_and_authenticate_user()
    {
        // Arrange
        $user = User::query()->make([
            'auth_id' => 'test-id',
        ]);

        // Act
        $this->actingAs($user);

        // Assert
        $this->assertAuthenticatedAs($user);
        [$type, $token] = explode(' ', $this->defaultHeaders['Authorization']);
        $this->assertStringContainsString('Bearer', $type);
        $this->assertEquals('test-id', JWT::decode($token, $this->getPublicKeys())->sub);
    }

    public function test_should_build_token_based_on_given_claims()
    {
        // Arrange
        Carbon::setTestNow(now());
        Config::set('app.url', 'http://oidc-server.test');
        $issuer = 'http://oidc-server.test/auth';
        $user = User::query()->make();

        // Act
        $this->withToken(['sub' => 'test-id', 'name' => 'John Doe'])->actingAs($user);

        // Assert
        [$type, $token] = explode(' ', $this->defaultHeaders['Authorization']);
        $this->assertStringContainsString('Bearer', $type);
        $this->assertEquals('test-id', JWT::decode($token, $this->getPublicKeys())->sub);
        $this->assertEquals('John Doe', JWT::decode($token, $this->getPublicKeys())->name);
        $this->assertEquals(now()->unix() + 300, JWT::decode($token, $this->getPublicKeys())->exp);
        $this->assertEquals(now()->unix(), JWT::decode($token, $this->getPublicKeys())->iat);
        $this->assertEquals($issuer, JWT::decode($token, $this->getPublicKeys())->iss);
    }

    public function test_should_work_with_different_principal_identifier_config()
    {
        // Arrange
        Config::set('auth.guards.api.principal_identifier', 'email');
        $user = User::query()->make([
            'email' => 'test@test.com',
            'auth_id' => 'other-id',
        ]);

        // Act
        $this->withToken(['sub' => 'test-id', 'email' => 'test@test.com'])->actingAs($user, 'api');

        // Assert
        $this->assertAuthenticatedAs($user);
        [$type, $token] = explode(' ', $this->defaultHeaders['Authorization']);
        $this->assertStringContainsString('Bearer', $type);
        $this->assertEquals('test@test.com', JWT::decode($token, $this->getPublicKeys())->email);
    }

    public function test_should_use_given_token()
    {
        // Arrange
        $user = User::query()->make();

        // Act
        $this->withToken('random-token')->actingAs($user);

        // Assert
        $this->assertAuthenticated();
        $this->assertEquals('Bearer random-token', $this->defaultHeaders['Authorization']);
    }

    public function test_should_not_affect_other_guards()
    {
        // Arrange
        Config::set('auth.guards.web', [
            'driver' => 'session',
            'provider' => 'users',
        ]);
        Config::set('auth.defaults.guard', 'web');
        $user = User::query()->make();

        // Act
        $this->actingAs($user, 'web');
        $this->actingAs($user);

        // Assert
        $this->assertAuthenticatedAs($user);
        $this->assertArrayNotHasKey('Authorization', $this->defaultHeaders);
    }
}
