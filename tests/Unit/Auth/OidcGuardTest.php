<?php

namespace DevAdamlar\LaravelOidc\Tests\Unit\Auth;

use DevAdamlar\LaravelOidc\Auth\OidcGuard;
use DevAdamlar\LaravelOidc\Config\ConfigLoader;
use DevAdamlar\LaravelOidc\Config\PublicKeyResolver;
use DevAdamlar\LaravelOidc\Exceptions\TokenException;
use DevAdamlar\LaravelOidc\Exceptions\UserNotFoundException;
use DevAdamlar\LaravelOidc\Http\Client\OidcClient;
use DevAdamlar\LaravelOidc\Http\Issuer;
use DevAdamlar\LaravelOidc\Support\Key;
use DevAdamlar\LaravelOidc\Tests\Models\User;
use DevAdamlar\LaravelOidc\Tests\TestCase;
use Firebase\JWT\JWT;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use InvalidArgumentException;
use Mockery;
use Mockery\MockInterface;

class OidcGuardTest extends TestCase
{
    private ConfigLoader|MockInterface $config;

    private Request|MockInterface $request;

    private UserProvider|MockInterface $provider;

    protected User $user;

    private string $accessToken;

    protected function setUp(): void
    {
        parent::setUp();
        $this->user = User::query()->make([
            'auth_id' => 'unique-id',
        ]);

        $this->accessToken = $this->createToken([
            'sub' => 'unique-id',
        ]);

        $this->config = $this->partialMock(ConfigLoader::class, function (MockInterface $mock) {
            $mock->shouldReceive('get')
                ->with('public_key', Mockery::any())
                ->andReturn('certs/public.pem')->byDefault();
            $mock->shouldReceive('get')
                ->with('input_key')
                ->andReturn('custom_token')->byDefault();
        });
        $this->provider = $this->partialMock(UserProvider::class, function (MockInterface $mock) {
            $mock->shouldReceive('retrieveById')
                ->with('unique-id')->andReturn($this->user);
        })->byDefault();
    }

    protected function createToken(
        array $payload = [],
        bool $mockRequest = true
    ): string {
        [$privateKey, $publicKey] = self::generateKeyPair();

        return tap(parent::buildJwt($payload, $privateKey, $publicKey), function ($token) use ($mockRequest, $privateKey) {
            $this->partialMock(PublicKeyResolver::class, function (MockInterface $mock) use ($privateKey) {
                $mock->shouldReceive('resolve')->andReturn(new \Firebase\JWT\Key(openssl_pkey_get_details($privateKey)['key'], 'RS256'));
            })->byDefault();
            if ($mockRequest) {
                $this->request = $this->partialMock(Request::class, function (MockInterface $mock) use ($token) {
                    $mock->shouldReceive('input')->with('custom_token')->andReturn($token)->byDefault();
                    $mock->shouldReceive('bearerToken')->andReturnNull()->byDefault();
                });
            }
        });
    }

    public function test_should_return_user_directly_if_it_is_already_retrieved()
    {
        // Arrange
        $this->provider->shouldNotReceive('retrieveById');
        $this->request->shouldNotReceive('bearerToken');
        $this->request->shouldNotReceive('input');
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);
        $guard->setUser($this->user);

        // Act
        $result = $guard->user();

        // Assert
        $this->assertSame($this->user, $result);
    }

    public function test_it_should_return_false_when_token_is_not_provided()
    {
        // Arrange
        $this->request->shouldReceive('bearerToken')->andReturnNull();
        $this->request->shouldReceive('input')->andReturnNull();
        $this->config->shouldReceive('get')->with('input_key')->andReturn('api_token');
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $result = $guard->check();

        // Assert
        $this->assertFalse($result);
    }

    public function test_should_prefer_request_header_over_request_body_to_find_access_token()
    {
        // Arrange
        $tokenWithOtherAud = $this->createToken(['aud' => 'other-aud'], false);
        $this->config->shouldReceive('get')->with('audience')->andReturn('other-aud');
        $this->request->shouldReceive('bearerToken')->andReturn($tokenWithOtherAud);
        $this->request->shouldReceive('input')->with('custom_token')->andReturn($this->accessToken);
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $result = $guard->user();

        // Assert
        $this->assertSame($this->user, $result);
    }

    public function test_it_should_throw_token_exception_when_token_is_invalid()
    {
        // Arrange
        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('Wrong number of segments');
        $this->request->shouldReceive('bearerToken')->andReturn('invalid-token');
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $guard->user();

    }

    public function test_should_throw_exception_when_neither_issuer_nor_public_key_are_present()
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Issuer or public key is required to verify JWT signature.');
        $this->config->shouldReceive('get')->with('public_key', Mockery::any())->andReturnNull();
        $this->config->shouldReceive('get')->with('issuer')->andReturnNull();
        $this->request->shouldReceive('input')->with('custom_token')->andReturn($this->accessToken);
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $guard->user();

    }

    public function test_should_throw_exception_when_public_key_is_invalid()
    {
        // Arrange
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Supplied public key is invalid.');
        $this->partialMock(PublicKeyResolver::class, function (MockInterface $mock) {
            $mock->shouldReceive('resolve')->andReturn(new \Firebase\JWT\Key('some-junk', 'RS256'));
        });
        $this->config->shouldReceive('get')->with('public_key', Mockery::any())->andReturn('junk');
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $guard->user();

    }

    public function test_should_throw_exception_if_token_has_expired()
    {
        // Arrange
        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('Expired token');
        $this->config->shouldReceive('get')->with('leeway')->andReturn(0);
        $this->createToken(['exp' => time() - 10]);
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $guard->user();

    }

    public function test_should_throw_exception_if_signature_could_not_verified()
    {
        // Arrange
        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('Signature verification failed');
        $this->createToken(mockRequest: false);
        $this->config->shouldReceive('get')->with('leeway')->andReturn(0);
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $guard->user();

    }

    public function test_should_take_into_account_leeway()
    {
        // Arrange
        $this->createToken(['iat' => time() - 10]);
        $this->config->shouldReceive('get')->with('leeway')->andReturn(20);
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $result = $guard->check();

        // Assert
        $this->assertTrue($result);
    }

    /**
     * @dataProvider audienceProvider
     *
     * @return void
     *
     * @throws TokenException
     * @throws UserNotFoundException
     */
    public function test_it_should_return_true_when_token_is_valid(string|array|null $tokenAudience, ?string $rpAudience)
    {
        // Arrange
        $this->createToken(['aud' => $tokenAudience]);
        $this->config->shouldReceive('get')->with('audience')->andReturn($rpAudience);
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $result = $guard->user();

        // Assert
        $this->assertSame($this->user, $result);
    }

    public function test_should_throw_not_found_exception_if_token_user_not_found()
    {
        // Arrange
        $this->expectException(UserNotFoundException::class);
        $this->expectExceptionMessage('User not found.');
        $this->provider->shouldReceive('retrieveById')->with('unique-id')->andReturnNull();
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $guard->user();

    }

    /**
     * @dataProvider audienceProviderForFailure
     *
     * @return void
     *
     * @throws TokenException
     * @throws UserNotFoundException
     */
    public function test_should_throw_token_exception_if_aud_not_match(string|array|null $tokenAudience)
    {
        // Arrange
        $this->expectException(TokenException::class);
        $this->expectExceptionMessage('Token audience does not match the expected audience.');
        $this->createToken(['aud' => $tokenAudience]);
        $this->config->shouldReceive('get')->with('audience')->andReturn('different-audience');
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $guard->user();

    }

    public function test_should_prefer_public_key_over_issuer_for_jwt_validation()
    {
        // Arrange
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
        $this->config->shouldReceive('get')->with('key_disk')->andReturn($disk);
        $this->config->shouldReceive('get')->with('public_key', Mockery::any())->andReturn('certs/public.pem');
        $token = $this->createToken(['sub' => 'unique-id']);
        $this->request->shouldReceive('input')->with('custom_token')->andReturn($token);
        $this->request->shouldReceive('bearerToken')->andReturnNull();
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $result = $guard->check();

        // Assert
        $this->assertTrue($result);
    }

    public function test_should_validate_by_introspection_if_configured_to_do_so()
    {
        // Arrange
        $this->accessToken = $this->createToken(['sub' => 'unique-id']);
        $this->config->shouldReceive('get')->with('use_introspection')->andReturnTrue();
        $this->config->shouldReceive('get')->with('client_id')->andReturn('client-id');
        $this->config->shouldReceive('get')->with('client_secret')->andReturn('client-secret');
        $this->provider->shouldReceive('retrieveById')->with('unique-id')->andReturn($this->user);
        $this->mock(OidcClient::class, function (MockInterface $mock) {
            $mock->shouldReceive('introspect')->andReturn((object) [
                'active' => true,
                'sub' => 'unique-id',
                'scope' => 'scope1 scope2',
            ]);
        });
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $result = $guard->check();

        // Assert
        $this->assertTrue($result);
    }

    public function test_should_use_issuer_to_get_public_key_when_public_key_is_absent()
    {
        // Arrange
        $token = $this->createToken(['sub' => 'unique-id']);
        [$head64] = explode('.', $token);
        $head = JWT::jsonDecode(JWT::urlsafeB64Decode($head64));
        $this->mock(OidcClient::class, function (MockInterface $mock) use ($head) {
            $mock->shouldReceive('getIssuer')->andReturn(new Issuer([
                'issuer' => 'https://oidc-server.test/auth',
                'jwks_uri' => 'https://oidc-server.test/auth/jwks',
                'authorization_endpoint' => 'https://oidc-server.test/auth/auth',
            ]))->byDefault();
            $mock->shouldReceive('downloadKeys')
                ->andReturn(Key::jwks(kid: $head->kid))->byDefault();
            $mock->shouldReceive('introspect')->andReturn([
                'active' => true,
                'sub' => 'unique-id',
                'scope' => 'scope1 scope2',
            ])->byDefault();
        });
        $this->config->shouldReceive('get')->with('public_key', Mockery::any())->andReturnNull();
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $result = $guard->check();

        // Assert
        $this->assertTrue($result);
    }

    public function test_should_validate_return_false_always()
    {
        // Arrange
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $result = $guard->validate();

        // Assert
        $this->assertFalse($result);
    }

    public function test_should_set_claims()
    {
        // Arrange
        Carbon::setTestNow(now());
        $payload = [
            'iss' => 'https://oidc-server.test/auth',
            'sub' => 'unique-id',
            'azp' => 'client-id',
            'aud' => 'phpunit',
            'exp' => now()->unix() + 300,
            'iat' => now()->unix(),
            'scope' => 'scope1 scope2',
        ];
        $this->createToken($payload);
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $guard->user();

        // Assert
        $this->assertSame($payload, (array) $guard->claims);
    }

    public function test_should_list_scopes()
    {
        // Arrange
        $this->createToken(['scope' => 'scope1 scope2']);
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);

        // Act
        $guard->user();

        // Assert
        $this->assertSame(['scope1', 'scope2'], $guard->scopes());
    }

    public function test_should_assert_if_has_given_scope()
    {
        // Arrange
        $this->createToken(['scope' => 'scope1 scope2']);
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);
        $guard->user();

        // Act & Assert
        $this->assertTrue($guard->hasScope('scope1'));
        $this->assertTrue($guard->hasScope('scope2'));
        $this->assertFalse($guard->hasScope('scope3'));
    }

    public function test_should_assert_if_has_any_of_given_scopes()
    {
        // Arrange
        $this->createToken(['scope' => 'scope1 scope2']);
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);
        $guard->user();

        // Act & Assert
        $this->assertTrue($guard->hasAnyScope(['scope1', 'scope3']));
        $this->assertTrue($guard->hasAnyScope(['scope3', 'scope2']));
        $this->assertFalse($guard->hasAnyScope(['scope3', 'scope4']));
    }

    public function test_should_define_gates_based_on_scopes()
    {
        // Arrange
        $this->createToken(['scope' => 'scope1 scope2']);
        $guard = new OidcGuard($this->provider, $this->request, 'api', $this->config);
        $guard->user();

        // Act & Assert
        $this->assertTrue($this->user->can('scope1'));
        $this->assertTrue($this->user->can('scope2'));
        $this->assertFalse($this->user->can('scope3'));
    }

    public static function audienceProvider(): array
    {
        return [
            ['aud', 'aud'],
            [['aud'], 'aud'],
            ['aud', null],
            [['aud'], null],
            [null, null],
        ];
    }

    public static function audienceProviderForFailure(): array
    {
        return [
            ['aud'],
            [['aud']],
            [null],
        ];
    }
}
