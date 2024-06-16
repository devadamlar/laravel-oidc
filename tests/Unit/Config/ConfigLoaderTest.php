<?php

declare(strict_types=1);

namespace DevAdamlar\LaravelOidc\Tests\Unit\Config;

use DevAdamlar\LaravelOidc\Config\ConfigLoader;
use Illuminate\Support\Facades\Config;
use Orchestra\Testbench\TestCase;

class ConfigLoaderTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Config::shouldReceive('get')
            ->with('oidc.cache_ttl')
            ->andReturn(3600)->byDefault();
        Config::shouldReceive('get')
            ->with('oidc.input_key')
            ->andReturn('api_token')->byDefault();
        Config::shouldReceive('get')
            ->with('oidc.signing_algorithm')
            ->andReturn('RS256')->byDefault();
        Config::shouldReceive('get')
            ->with('oidc.public_key')
            ->andReturn('path/to/global/certificate.pem')->byDefault();
        Config::shouldReceive('get')
            ->with('oidc.issuer')
            ->andReturn('https://global-issuer.test')->byDefault();
        Config::shouldReceive('get')
            ->with('oidc.use_introspection')
            ->andReturn(true)->byDefault();
        Config::shouldReceive('get')
            ->with('oidc.client_id')
            ->andReturn('global-client-id')->byDefault();
        Config::shouldReceive('get')
            ->with('oidc.client_secret')
            ->andReturn('global-client-secret')->byDefault();
        Config::shouldReceive('get')
            ->with('oidc.introspection_auth_method')
            ->andReturn('client_secret_post')->byDefault();
        Config::shouldReceive('get')
            ->with('oidc.private_key')
            ->andReturn('path/to/global/private.key')->byDefault();
    }

    public function test_should_give_guard_configs_with_type_conversion()
    {
        // Arrange
        $config = [
            'cache_ttl' => 7200,
            'input_key' => 'custom_token',
            'signing_algorithm' => 'HS256',
            'public_key' => 'path/to/custom/certificate.pem',
            'issuer' => 'https://custom-issuer.test',
            'use_introspection' => false,
            'client_id' => 'custom-client-id',
            'client_secret' => 'custom-client-secret',
            'introspection_auth_method' => 'client_secret_basic',
            'private_key' => 'path/to/custom/private.key',
        ];

        // Act
        $configLoader = new ConfigLoader($config);

        // Assert
        $this->assertSame(7200, $configLoader->get('cache_ttl'));
        $this->assertSame('custom_token', $configLoader->get('input_key'));
        $this->assertSame('HS256', $configLoader->get('signing_algorithm'));
        $this->assertSame('path/to/custom/certificate.pem', $configLoader->get('public_key'));
        $this->assertSame('https://custom-issuer.test', $configLoader->get('issuer'));
        $this->assertFalse($configLoader->get('use_introspection'));
        $this->assertSame('custom-client-id', $configLoader->get('client_id'));
        $this->assertSame('custom-client-secret', $configLoader->get('client_secret'));
        $this->assertSame('client_secret_basic', $configLoader->get('introspection_auth_method'));
        $this->assertSame('path/to/custom/private.key', $configLoader->get('private_key'));
    }

    public function test_get_with_fallback_to_global()
    {
        // Arrange
        $config = [
            'issuer' => 'custom-issuer',
        ];

        // Act
        $configLoader = new ConfigLoader($config);

        // Assert
        $this->assertSame(3600, $configLoader->get('cache_ttl'));
        $this->assertSame('api_token', $configLoader->get('input_key'));
        $this->assertSame('RS256', $configLoader->get('signing_algorithm'));
        $this->assertSame('path/to/global/certificate.pem', $configLoader->get('public_key'));
        $this->assertSame('https://global-issuer.test/custom-issuer', $configLoader->get('issuer'));
        $this->assertTrue($configLoader->get('use_introspection'));
        $this->assertSame('global-client-id', $configLoader->get('client_id'));
        $this->assertSame('global-client-secret', $configLoader->get('client_secret'));
        $this->assertSame('client_secret_post', $configLoader->get('introspection_auth_method'));
        $this->assertSame('path/to/global/private.key', $configLoader->get('private_key'));
    }

    public function test_get_with_fallback_callback()
    {
        // Arrange
        $config = [
            'input_key' => null,
        ];

        Config::shouldReceive('get')->with('oidc.input_key')->andReturn('access_token');

        $configLoader = new ConfigLoader($config);

        // Act
        $inputKeyWithFallback = $configLoader->get('input_key', function ($value) {
            return true;
        });
        $inputKeyWithoutFallback = $configLoader->get('input_key', function ($value) {
            return false;
        });

        // Assert
        $this->assertSame('access_token', $inputKeyWithFallback);
        $this->assertNull($inputKeyWithoutFallback);
    }

    /**
     * @dataProvider urlProvider
     *
     * @return void
     */
    public function test_get_urls(?string $global, ?string $guard, string $expected)
    {
        // Arrange
        $config = [
            'issuer' => $guard,
        ];

        Config::shouldReceive('get')->with('oidc.issuer')->andReturn($global);

        // Act
        $configLoader = new ConfigLoader($config);

        // Assert
        $this->assertSame($expected, $configLoader->get('issuer'));
    }

    public static function urlProvider(): array
    {
        return [
            [null, 'https://guard-issuer.test', 'https://guard-issuer.test'],
            [null, 'https://guard-issuer.test/', 'https://guard-issuer.test'],
            ['https://global-issuer.test', 'https://guard-issuer.test', 'https://guard-issuer.test'],
            ['https://global-issuer.test', 'custom/path', 'https://global-issuer.test/custom/path'],
            ['https://global-issuer.test', 'custom/path/', 'https://global-issuer.test/custom/path'],
            ['https://global-issuer.test/', '/custom/path', 'https://global-issuer.test/custom/path'],
            ['https://global-issuer.test/', 'custom/path/', 'https://global-issuer.test/custom/path'],
            ['https://global-issuer.test', null, 'https://global-issuer.test'],
            ['https://global-issuer.test/', null, 'https://global-issuer.test'],
        ];
    }
}
