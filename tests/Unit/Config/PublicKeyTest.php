<?php

namespace DevAdamlar\LaravelOidc\Tests\Unit\Config;

use DevAdamlar\LaravelOidc\Config\PublicKeyResolver;
use DevAdamlar\LaravelOidc\Tests\TestCase;
use Firebase\JWT\JWT;

class PublicKeyTest extends TestCase
{
    public function test_builds_key_directly_from_input_if_it_is_key()
    {
        // Arrange
        [$privateKey, $publicKey] = $this->generateKeyPair();
        $token = self::buildJwt([
            'sub' => 'some-uuid',
        ], privateKey: $privateKey, publicKey: $publicKey);
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

    public function test_reads_key_from_file_if_input_is_file()
    {
        // Arrange
        [$privateKey, $publicKey] = $this->generateKeyPair();
        $token = self::buildJwt([
            'sub' => 'some-uuid',
        ], $privateKey, $publicKey);
        $pem = openssl_pkey_get_details($privateKey)['key'];
        $resolver = PublicKeyResolver::make('certs/public.pem', 'RS256', 'local');

        // Act
        $key = $resolver->resolve();

        // Assert
        $this->assertEquals('some-uuid', JWT::decode($token, $key)->sub);
    }

    public function test_throws_exception_if_input_is_file_but_not_found()
    {
        // Arrange
        $resolver = PublicKeyResolver::make('certs/not-found.pem', 'RS256', 'local');

        // Assert
        $this->expectExceptionMessage('Certificate file certs/not-found.pem not found.');

        // Act
        $resolver->resolve();
    }
}
