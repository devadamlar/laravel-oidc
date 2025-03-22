<?php

namespace DevAdamlar\LaravelOidc\Tests\Unit\Http\Introspection;

use DevAdamlar\LaravelOidc\Config\ConfigLoader;
use DevAdamlar\LaravelOidc\Exceptions\OidcServerException;
use DevAdamlar\LaravelOidc\Http\Client\OidcClient;
use DevAdamlar\LaravelOidc\Http\Introspection\ClientSecretBasic;
use DevAdamlar\LaravelOidc\Http\Introspection\ClientSecretJwt;
use DevAdamlar\LaravelOidc\Http\Introspection\ClientSecretPost;
use DevAdamlar\LaravelOidc\Http\Introspection\Introspector;
use DevAdamlar\LaravelOidc\Http\Introspection\PrivateKeyJwt;
use DevAdamlar\LaravelOidc\Http\Issuer;
use Firebase\JWT\JWT;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Mockery;
use OpenSSLAsymmetricKey;
use Orchestra\Testbench\TestCase;

class IntrospectorTest extends TestCase
{
    private ConfigLoader|Mockery $configLoader;

    private OpenSSLAsymmetricKey $introspectorPrivateKey;

    protected function setUp(): void
    {
        parent::setUp();
        $this->introspectorPrivateKey = openssl_pkey_new([
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        openssl_pkey_export($this->introspectorPrivateKey, $privateKey);
        $privateKeyFile = '/oidc/key.pem';
        $this->configLoader = Mockery::mock(ConfigLoader::class);
        $this->configLoader->shouldReceive('get')
            ->with('client_id')
            ->andReturn('client-id')->byDefault();
        $this->configLoader->shouldReceive('get')
            ->with('client_secret')
            ->andReturn('client-secret')->byDefault();
        $this->configLoader->shouldReceive('get')
            ->with('private_key')
            ->andReturn($privateKeyFile)->byDefault();
        $this->configLoader->shouldReceive('get')
            ->with('issuer')
            ->andReturn('https://introspecting-server.test')->byDefault();
        Storage::disk('local')->put($privateKeyFile, $privateKey);
        Http::fake(['https://introspecting-server.test/introspect' => Http::response(['active' => true])]);
    }

    /**
     * @dataProvider introspectionAuthMethodProvider
     *
     * @return void
     */
    public function test_should_instantiate_correct_introspector_based_on_given_config(string $authMethod, string $expectedClass)
    {
        // Arrange
        $this->configLoader->shouldReceive('get')
            ->with('introspection_auth_method')
            ->andReturn($authMethod);

        // Act
        $introspector = Introspector::make($this->configLoader);

        // Assert
        $this->assertInstanceOf($expectedClass, $introspector);
    }

    /**
     * @dataProvider invalidAuthMethodProvider
     *
     * @param  string|null  $authMethod
     * @return void
     */
    public function test_should_throw_exception_if_given_auth_method_config_is_invalid(mixed $authMethod)
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Valid introspection auth method is required');
        $this->configLoader->shouldReceive('get')
            ->with('introspection_auth_method')
            ->andReturn($authMethod);

        // Act
        Introspector::make($this->configLoader);
    }

    public function test_introspector_with_client_secret_basic()
    {
        // Arrange
        $endpoint = 'https://introspecting-server.test/introspect';
        $token = 'token';
        $this->configLoader->shouldReceive('get')
            ->with('introspection_auth_method')
            ->andReturn('client_secret_basic');
        $introspector = Introspector::make($this->configLoader);

        // Act
        $introspector->introspect($endpoint, $token);

        // Assert
        Http::assertSent(function (Request $request) use ($endpoint, $token) {
            return $request->url() === $endpoint
                && $request->isForm()
                && $request['token'] === $token
                && $request->hasHeader('Authorization')
                && $request->header('Authorization')[0] === 'Basic '.base64_encode('client-id:client-secret');
        });
    }

    public function test_introspector_with_client_secret_post_assert()
    {
        // Arrange
        $endpoint = 'https://introspecting-server.test/introspect';
        $token = 'token';
        $this->configLoader->shouldReceive('get')
            ->with('introspection_auth_method')
            ->andReturn('client_secret_post');
        $introspector = Introspector::make($this->configLoader);

        // Act
        $introspector->introspect($endpoint, $token);

        // Assert
        Http::assertSent(function (Request $request) use ($endpoint, $token) {
            return $request->url() === $endpoint
                && $request->isForm()
                && $request['token'] === $token
                && $request['client_id'] === 'client-id'
                && $request['client_secret'] === 'client-secret';
        });
    }

    public function test_introspector_with_client_secret_jwt()
    {
        // Arrange
        $endpoint = 'https://introspecting-server.test/introspect';
        $token = 'token';
        $kid = fake()->uuid();
        $this->configLoader->shouldReceive('get')
            ->with('introspection_auth_method')
            ->andReturn('client_secret_jwt');
        Carbon::setTestNow(now());
        Str::createUuidsUsing(function () use ($kid) {
            return $kid;
        });
        $jwt = JWT::encode([
            'iss' => 'client-id',
            'sub' => 'client-id',
            'aud' => 'https://introspecting-server.test',
            'jti' => $kid,
            'exp' => now()->addMinute()->unix(),
            'nbf' => now()->unix(),
            'iat' => now()->unix(),
        ], 'client-secret', 'HS256');
        $introspector = Introspector::make($this->configLoader);

        // Act
        $introspector->introspect($endpoint, $token);

        // Assert
        Http::assertSent(function (Request $request) use ($endpoint, $token, $jwt) {
            return $request->url() === $endpoint
                && $request->isForm()
                && $request['token'] === $token
                && $request['client_assertion_type'] === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                && $request['client_assertion'] === $jwt;
        });
    }

    public function test_introspector_with_private_key_jwt()
    {
        // Arrange
        $endpoint = 'https://introspecting-server.test/introspect';
        $token = 'token';
        $kid = fake()->uuid();
        $this->configLoader->shouldReceive('get')
            ->with('introspection_auth_method')
            ->andReturn('private_key_jwt');

        $issuer = new Issuer([
            'issuer' => 'https://introspecting-server.test',
            'jwks_uri' => 'https://introspecting-server.test/jwks',
            'authorization_endpoint' => 'https://introspecting-server.test/auth',
            'token_endpoint' => 'https://introspecting-server.test/token',
            'introspection_endpoint' => $endpoint,
        ]);

        $this->mock(OidcClient::class, function ($mock) use ($issuer) {
            $mock->shouldReceive('getIssuer')->andReturn($issuer);
        });

        Carbon::setTestNow(now());
        Str::createUuidsUsing(function () use ($kid) {
            return $kid;
        });
        $jwt = JWT::encode([
            'iss' => 'client-id',
            'sub' => 'client-id',
            'aud' => 'https://introspecting-server.test/token',
            'jti' => $kid,
            'exp' => now()->addMinute()->unix(),
            'nbf' => now()->unix(),
            'iat' => now()->unix(),
        ], $this->introspectorPrivateKey, 'RS256');

        $disk = 'custom-disk';
        Config::set('filesystems', [
            'default' => $disk,
            'disks' => [
                $disk => [
                    'driver' => 'local',
                    'root' => storage_path('app'),
                ],
            ],
        ]);
        Config::set('oidc.key_disk', $disk);
        $this->configLoader->shouldReceive('get')->with('key_disk')->andReturn($disk);

        $introspector = Introspector::make($this->configLoader);

        // Act
        $introspector->introspect($endpoint, $token);

        // Assert
        Http::assertSent(function (Request $request) use ($endpoint, $token, $jwt) {
            return $request->url() === $endpoint
                && $request->isForm()
                && $request['token'] === $token
                && $request['client_assertion_type'] === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                && $request['client_assertion'] === $jwt;
        });
    }

    /**
     * @dataProvider introspectionRequirementProvider
     *
     * @return void
     */
    public function test_should_throw_invalid_argument_exception_if_required_configs_are_missing(string $authMethod, string $missingConfig)
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($missingConfig.' is required for introspection with '.$authMethod);
        $this->configLoader->shouldReceive('get')
            ->with('introspection_auth_method')
            ->andReturn($authMethod);
        $this->configLoader->shouldReceive('get')
            ->with($missingConfig)
            ->andReturn(null);
        $introspector = Introspector::make($this->configLoader);

        // Act
        $introspector->introspect('https://introspecting-server.test/introspect', 'token');
    }

    public function test_should_throw_exception_if_introspection_request_fails()
    {
        // Arrange
        $this->expectException(OidcServerException::class);
        $this->expectExceptionMessage('Introspection request failed at https://test-server/introspect: {"error":"invalid_request","error_description":"Authentication failed."}');
        $this->configLoader->shouldReceive('get')
            ->with('introspection_auth_method')
            ->andReturn('client_secret_basic');
        $introspector = Introspector::make($this->configLoader);
        Http::fake([
            'https://test-server/introspect' => Http::response([
                'error' => 'invalid_request',
                'error_description' => 'Authentication failed.',
            ], 401),
        ]);

        // Act
        $introspector->introspect('https://test-server/introspect', 'token');
    }

    public static function introspectionAuthMethodProvider(): array
    {
        return [
            ['client_secret_basic', ClientSecretBasic::class],
            ['client_secret_post', ClientSecretPost::class],
            ['client_secret_jwt', ClientSecretJwt::class],
            ['private_key_jwt', PrivateKeyJwt::class],
        ];
    }

    public static function invalidAuthMethodProvider(): array
    {
        return [
            [null],
            [''],
            ['invalid-auth-method'],
            [1],
        ];
    }

    public static function introspectionRequirementProvider(): array
    {
        return [
            ['client_secret_basic', 'client_id'],
            ['client_secret_basic', 'client_secret'],
            ['client_secret_post', 'client_id'],
            ['client_secret_post', 'client_secret'],
            ['client_secret_jwt', 'client_id'],
            ['client_secret_jwt', 'client_secret'],
            ['private_key_jwt', 'client_id'],
            ['private_key_jwt', 'private_key'],
        ];
    }
}
