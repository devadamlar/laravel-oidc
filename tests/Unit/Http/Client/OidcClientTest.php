<?php

namespace DevAdamlar\LaravelOidc\Tests\Unit\Http\Client;

use DevAdamlar\LaravelOidc\Config\ConfigLoader;
use DevAdamlar\LaravelOidc\Exceptions\OidcServerException;
use DevAdamlar\LaravelOidc\Http\Client\OidcClient;
use DevAdamlar\LaravelOidc\Http\Introspection\ClientSecretPost;
use DevAdamlar\LaravelOidc\Http\Issuer;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Mockery;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;

class OidcClientTest extends TestCase
{
    private ConfigLoader|MockInterface $configLoader;

    private string $issuer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->issuer = 'https://oidc-server.test/auth';
        $this->configLoader = Mockery::mock(ConfigLoader::class);
        $this->configLoader->shouldReceive('get')
            ->with('cache_ttl')
            ->andReturn(60)->byDefault();
        $this->configLoader->shouldReceive('get')
            ->with('cache_driver')
            ->andReturn('custom_driver')->byDefault();
        $this->configLoader->shouldReceive('get')
            ->with('issuer')
            ->andReturn($this->issuer)->byDefault();
        config(['cache.stores.custom_driver' => ['driver' => 'array']]);
    }

    public function test_make_should_give_instantiated_client()
    {
        // Act
        $client = OidcClient::make($this->configLoader);

        // Assert
        $this->assertInstanceOf(OidcClient::class, $client);
    }

    public function test_should_return_existing_issuer()
    {
        // Arrange
        Cache::flush();
        $client = new OidcClient($this->configLoader);
        Http::fake([
            $this->issuer.'/.well-known/openid-configuration' => Http::response([
                'issuer' => $this->issuer,
                'authorization_endpoint' => $this->issuer.'/auth',
                'token_endpoint' => $this->issuer.'/token',
                'userinfo_endpoint' => $this->issuer.'/userinfo',
                'jwks_uri' => $this->issuer.'/jwks',
            ]),
        ]);

        $client->getIssuer();

        // Act
        $issuer = $client->getIssuer();

        // Assert
        $this->assertEquals($this->issuer, $issuer->issuer);
        $this->assertEquals($this->issuer.'/jwks', $issuer->jwksUri);
        $this->assertEquals($this->issuer.'/auth', $issuer->authorizationEndpoint);
        $this->assertEquals($this->issuer.'/userinfo', $issuer->userinfoEndpoint);
        $this->assertEquals($this->issuer.'/token', $issuer->tokenEndpoint);
        $this->assertEquals($issuer, $client->getIssuer());
        Http::assertSentCount(1);
    }

    public function test_discover()
    {
        // Arrange
        Http::fake([
            $this->issuer.'/.well-known/openid-configuration' => Http::response([
                'issuer' => $this->issuer,
                'authorization_endpoint' => $this->issuer.'/auth',
                'token_endpoint' => $this->issuer.'/token',
                'userinfo_endpoint' => $this->issuer.'/userinfo',
                'jwks_uri' => $this->issuer.'/jwks',
            ]),
        ]);
        $client = new OidcClient($this->configLoader);

        // Act
        $issuer = $client->getIssuer();

        // Assert
        $this->assertEquals($this->issuer, $issuer->issuer);
        $this->assertEquals($this->issuer.'/jwks', $issuer->jwksUri);
        $this->assertEquals($this->issuer.'/auth', $issuer->authorizationEndpoint);
        $this->assertEquals($this->issuer.'/userinfo', $issuer->userinfoEndpoint);
        $this->assertEquals($this->issuer.'/token', $issuer->tokenEndpoint);
        $this->assertEquals($issuer, $client->getIssuer());

        Http::assertSentCount(1);
        $this->assertTrue(Cache::driver('custom_driver')->has('laravel-oidc:'.$this->issuer));
    }

    public function test_should_return_null_if_issuer_is_absent()
    {
        // Arrange
        $this->configLoader->shouldReceive('get')
            ->with('issuer')
            ->andReturnNull();
        $this->configLoader->shouldReceive('get')
            ->with('cache_ttl')
            ->andReturn(0);
        $client = new OidcClient($this->configLoader);

        // Act
        $issuer = $client->getIssuer();

        // Assert
        $this->assertNull($issuer);
    }

    /**
     * @dataProvider errorResponseProvider
     *
     * @return void
     */
    public function test_should_throw_exception_if_discovery_response_fails_or_incomplete(array|string|null $body, int $code)
    {
        // Arrange
        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('Failed to fetch OpenID Connect discovery document');
        Cache::forget('laravel-oidc:'.$this->issuer);
        Http::fake([
            $this->issuer.'/.well-known/openid-configuration' => Http::response($body, $code),
        ]);
        $client = new OidcClient($this->configLoader);

        // Act
        $client->getIssuer();
    }

    public function test_should_throw_exception_if_issuer_url_is_invalid()
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Issuer invalid-url is not a valid HTTP URL.');
        $this->configLoader->shouldReceive('get')
            ->with('issuer')
            ->andReturn('invalid-url');
        $this->configLoader->shouldReceive('get')
            ->with('cache_ttl')
            ->andReturn(0);
        $client = new OidcClient($this->configLoader);

        // Act
        $client->getIssuer();
    }

    public function test_download_keys()
    {
        // Arrange
        $privateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        $publicKey = openssl_pkey_get_details($privateKey)['rsa'];

        $jwt = JWT::encode(
            ['sub' => '1234567890', 'name' => 'John Doe', 'iat' => 1516239022],
            $privateKey,
            'RS256',
            'key-id'
        );

        $jwksUri = $this->issuer.'/jwks';
        Http::fake([
            $jwksUri => Http::response([
                'keys' => [
                    [
                        'kty' => 'RSA',
                        'use' => 'sig',
                        'alg' => 'RS256',
                        'kid' => 'key-id',
                        'n' => Str::toBase64($publicKey['n']),
                        'e' => Str::toBase64($publicKey['e']),
                    ],
                ],
            ]),
        ]);
        $client = new OidcClient($this->configLoader);
        $client->setIssuer(new Issuer([
            'issuer' => $this->issuer,
            'jwks_uri' => $jwksUri,
            'authorization_endpoint' => $this->issuer.'/auth',
        ]));

        // Act
        $client->downloadKeys($jwksUri);
        $client->downloadKeys($jwksUri);
        $keys = $client->downloadKeys();

        // Assert
        $this->assertIsArray($keys);
        $this->assertArrayHasKey('keys', $keys);
        $this->assertCount(1, $keys['keys']);
        $this->assertEquals('John Doe', JWT::decode($jwt, JWK::parseKeySet($keys))->name);
        Http::assertSentCount(1);
        $this->assertTrue(Cache::driver('custom_driver')->has('laravel-oidc:'.$this->issuer.':jwks'));
    }

    public function test_should_not_cache_keys_if_request_fails_or_returns_empty_body()
    {
        // Arrange
        Cache::forget('laravel-oidc:'.$this->issuer.':jwks');
        Http::fake([
            $this->issuer.'/jwks' => Http::sequence()
                ->push([], 500)
                ->push([], 404)
                ->push([]),
        ]);
        $client = new OidcClient($this->configLoader);
        $client->setIssuer(new Issuer([
            'issuer' => $this->issuer,
            'jwks_uri' => $this->issuer.'/jwks',
            'authorization_endpoint' => $this->issuer.'/auth',
        ]));

        // Act
        foreach (range(1, 3) as $ignored) {
            try {
                $client->downloadKeys();
            } catch (OidcServerException) {
            }
        }

        // Assert
        Http::assertSentCount(3);
    }

    /**
     * @dataProvider errorResponseProvider
     *
     * @return void
     */
    public function test_should_throw_exception_if_jwks_response_fails_or_incomplete(array|string|null $body, int $code)
    {
        // Arrange
        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('Failed to fetch public keys at '.$this->issuer.'/jwks.');
        Cache::forget('laravel-oidc:'.$this->issuer.'/jwks');
        Http::fake([
            $this->issuer.'/jwks' => Http::response($body, $code),
        ]);
        $client = new OidcClient($this->configLoader);
        $client->setIssuer(new Issuer([
            'issuer' => $this->issuer,
            'jwks_uri' => $this->issuer.'/jwks',
            'authorization_endpoint' => $this->issuer.'/auth',
        ]));

        // Act
        $client->downloadKeys();
    }

    public function test_introspect()
    {
        // Arrange
        $token = 'token';
        $this->partialMock(ClientSecretPost::class, function ($mock) use ($token) {
            $mock->shouldReceive('get')
                ->with('client_id')
                ->andReturn('client-id');
            $mock->shouldReceive('get')
                ->with('client_secret')
                ->andReturn('client-secret');
            $mock->shouldReceive('introspect')
                ->with($this->issuer.'/introspect', $token, 'access_token')
                ->once()
                ->andReturn((object) ['active' => true]);
        });
        $this->configLoader->shouldReceive('get')
            ->with('introspection_auth_method')
            ->andReturn('client_secret_post');
        $client = new OidcClient($this->configLoader);
        $client->setIssuer(new Issuer([
            'issuer' => $this->issuer,
            'introspection_endpoint' => $this->issuer.'/introspect',
            'authorization_endpoint' => $this->issuer.'/auth',
            'jwks_uri' => $this->issuer.'/jwks',
        ]));

        // Act
        $response = $client->introspect($token);

        // Assert
        $this->assertTrue($response->active);
    }

    public function test_should_throw_exception_if_introspection_auth_method_is_not_supported()
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Given client auth method is not supported by the Authorization server');
        $token = 'token';
        $this->configLoader->shouldReceive('get')
            ->with('introspection_auth_method')
            ->andReturn('client_secret_post');
        $client = new OidcClient($this->configLoader);
        $client->setIssuer(new Issuer([
            'issuer' => $this->issuer,
            'introspection_endpoint' => $this->issuer.'/introspect',
            'authorization_endpoint' => $this->issuer.'/auth',
            'jwks_uri' => $this->issuer.'/jwks',
            'introspection_endpoint_auth_methods_supported' => ['client_secret_basic'],
        ]));

        // Act
        $client->introspect($token);
    }

    public function test_should_throw_exception_if_endpoint_could_not_found()
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('No introspection endpoint found');
        $this->configLoader->shouldReceive('get')
            ->with('introspection_auth_method')
            ->andReturn('client_secret_basic');
        $client = new OidcClient($this->configLoader);
        $client->setIssuer(new Issuer([
            'issuer' => $this->issuer,
            'authorization_endpoint' => $this->issuer.'/auth',
            'jwks_uri' => $this->issuer.'/jwks',
        ]));

        // Act
        $client->introspect('token');
    }

    public static function errorResponseProvider(): array
    {
        return [
            [null, 500],
            [[], 404],
            [[], 200],
            [null, 200],
            ['', 200],
        ];
    }
}
