<?php

namespace DevAdamlar\LaravelOidc\Tests\Unit\Config;

use DevAdamlar\LaravelOidc\Config\PublicKeyResolver;
use DevAdamlar\LaravelOidc\Support\Key;
use DevAdamlar\LaravelOidc\Tests\TestCase;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Storage;

class PublicKeyTest extends TestCase
{
    public function test_builds_key_directly_from_input_if_it_is_key(): void
    {
        // Arrange
        ['private' => $privateKey] = Key::generateRsaKeyPair();
        $token = self::buildJwt([
            'sub' => 'some-uuid',
        ], privateKey: $privateKey);
        $pem = openssl_pkey_get_details($privateKey)['key'];
        $pem = preg_replace('/-----BEGIN PUBLIC KEY-----/', '', $pem);
        $pem = preg_replace('/-----END PUBLIC KEY-----/', '', $pem);
        $pem = str_replace(["\r", "\n"], '', $pem);
        $resolver = PublicKeyResolver::make($pem, 'RS256', 'local');

        // Act
        $key = $resolver->resolve();

        // Assert
        $this->assertEquals('some-uuid', JWT::decode($token, $key)->sub);
    }

    public function test_reads_key_from_file_if_input_is_file(): void
    {
        // Arrange
        ['private' => $privateKey, 'public' => $publicKey] = Key::generateRsaKeyPair();
        $token = self::buildJwt([
            'sub' => 'some-uuid',
        ], $privateKey);
        Storage::fake('local');
        Storage::disk('local')->put('certs/public.pem', $publicKey['key']);
        $resolver = PublicKeyResolver::make('certs/public.pem', 'RS256', 'local');

        // Act
        $key = $resolver->resolve();

        // Assert
        $this->assertEquals('some-uuid', JWT::decode($token, $key)->sub);
    }

    public function test_throws_exception_if_input_is_file_but_not_found(): void
    {
        // Arrange
        $resolver = PublicKeyResolver::make('certs/not-found.pem', 'RS256', 'local');

        // Assert
        $this->expectExceptionMessage('Key file certs/not-found.pem not found.');

        // Act
        $resolver->resolve();
    }
}
