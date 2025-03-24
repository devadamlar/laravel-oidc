<?php

namespace DevAdamlar\LaravelOidc\Tests\Feature\Http\JwksRoute;

use DevAdamlar\LaravelOidc\Tests\TestCase;
use Illuminate\Support\Facades\Log;

class WithoutPrivateKeyTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        Log::shouldReceive('warning')->with('JWKS URI is set, but no private key found.')->once();
        $app['config']->set('oidc.rp_jwks_path', 'jwks');
        $app['config']->set('oidc.signing_algorithm', 'ES256');
        $app['config']->set('auth.guards', [
            'session' => ['driver' => 'session', 'name' => 'id'],
            'jwt' => ['driver' => 'jwt', 'key' => 'key'],
            'oidc4' => ['driver' => 'oidc', 'signing_algorithm' => 'ES512'],
            'oidc5' => ['driver' => 'oidc'],
        ]);
    }

    public function test_should_return_jwks_based_on_given_private_keys(): void
    {
        // Act
        $response = $this->getJson('jwks');

        // Assert
        $response
            ->assertStatus(200)
            ->assertJsonCount(0, 'keys');
    }
}
