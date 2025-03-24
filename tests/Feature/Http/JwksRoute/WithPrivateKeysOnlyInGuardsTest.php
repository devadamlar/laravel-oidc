<?php

namespace DevAdamlar\LaravelOidc\Tests\Feature\Http\JwksRoute;

use DevAdamlar\LaravelOidc\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;

class WithPrivateKeysOnlyInGuardsTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('oidc.cache_driver', 'array');
        $app['config']->set('oidc.cache_ttl', 86400);
        $app['config']->set('oidc.rp_jwks_path', 'jwks');
        $app['config']->set('oidc.signing_algorithm', 'ES256');
        $app['config']->set('auth.guards', [
            'session' => ['driver' => 'session', 'name' => 'id'],
            'jwt' => ['driver' => 'jwt', 'key' => 'key'],
            'oidc1' => ['driver' => 'oidc', 'private_key' => 'certs/guard1_private_key.pem'],
            'oidc2' => ['driver' => 'oidc', 'private_key' => 'certs/guard2_private_key.pem', 'signing_algorithm' => 'ES384'],
            'oidc3' => ['driver' => 'oidc', 'private_key' => 'certs/guard3_private_key.pem', 'signing_algorithm' => 'PS256'],
            'oidc4' => ['driver' => 'oidc', 'signing_algorithm' => 'ES512'],
            'oidc5' => ['driver' => 'oidc'],
        ]);
        Storage::fake();
        Storage::put('certs/guard1_private_key.pem', <<<'PEM'
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIDEGrPR6Qwf+WDi0d9/Ns7vKNFkQ491k8mvjHsnLX0T6oAoGCCqGSM49
AwEHoUQDQgAElXhKlrUC6IUl/xzigCphzTk9ZjCy775LTNI5/fZoGtiMhxAcB9Ya
y2pd8FfPozCPiO/xE5sBg37f/r4IOtUT7g==
-----END EC PRIVATE KEY-----
PEM
        );
        Storage::put('certs/guard2_private_key.pem', <<<'PEM'
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBTwr6SngzbcxPtbaU2pRHjlX5UboRrUCAWd8PITD3EuUBEFPCVmO6k
/ONdQRlBpsSgBwYFK4EEACKhZANiAASBKPVTH0OCI0izhucuOiwovUdvsRANevz5
fZ3XGeQYM5XXe5Swxqy8B6DtrGCOTPWmnzETVlg6EFrYALXeQKDqUIivdsjw5+Nu
HcOkeaMkTHdbYtIXkNSl0feRG7Y5Er0=
-----END EC PRIVATE KEY-----
PEM
        );
        Storage::put('certs/guard3_private_key.pem', <<<'PEM'
-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
dn/RsYEONbwQSjIfMPkvxF+8HQ==
-----END PRIVATE KEY-----
PEM
        );
    }

    public function test_should_return_jwks_based_on_given_private_keys(): void
    {
        // Act
        $response = $this->getJson('jwks');
        $expectedCacheKey = 'laravel-oidc:rp:jwks:b9e74cec7a3b8a3c7c9a31fc997a846c';
        $expectedJwks = [
            'keys' => [
                [
                    'kid' => 'F7wh0-cir65qmLcvJXuT4hjTEVcV8dQiPataxyG-Bpg',
                    'use' => 'sig',
                    'kty' => 'EC',
                    'alg' => 'ES256',
                    'crv' => 'prime256v1',
                    'x' => 'lXhKlrUC6IUl_xzigCphzTk9ZjCy775LTNI5_fZoGtg',
                    'y' => 'jIcQHAfWGstqXfBXz6Mwj4jv8RObAYN-3_6-CDrVE-4',
                ],
                [
                    'kid' => 'ccQWBkTXNEiNZYiNtLSgjfdexWERPZgE3IqeQfw-fOg',
                    'use' => 'sig',
                    'kty' => 'EC',
                    'alg' => 'ES384',
                    'crv' => 'secp384r1',
                    'x' => 'gSj1Ux9DgiNIs4bnLjosKL1Hb7EQDXr8-X2d1xnkGDOV13uUsMasvAeg7axgjkz1',
                    'y' => 'pp8xE1ZYOhBa2AC13kCg6lCIr3bI8Ofjbh3DpHmjJEx3W2LSF5DUpdH3kRu2ORK9',
                ],
                [
                    'kid' => 'oGDmHqCJ7yzMkWEkrlZVHkvrHIyQwtlDmeq5ForUHeY',
                    'use' => 'sig',
                    'kty' => 'RSA',
                    'alg' => 'PS256',
                    'n' => 'u1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0_IzW7yWR7QkrmBL7jTKEn5u-qKhbwKfBstIs-bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyehkd3qqGElvW_VDL5AaWTg0nLVkjRo9z-40RQzuVaE8AkAFmxZzow3x-VJYKdjykkJ0iT9wCS0DRTXu269V264Vf_3jvredZiKRkgwlL9xNAwxXFg0x_XFw005UWVRIkdgcKWTjpBP2dPwVZ4WWC-9aGVd-Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbcmw',
                    'e' => 'AQAB',
                ],
            ],
        ];

        // Assert
        $response
            ->assertStatus(200)
            ->assertJsonCount(3, 'keys')
            ->assertJson($expectedJwks);
        $this->assertTrue(Cache::driver('array')->has($expectedCacheKey));
        $this->assertEquals($expectedJwks, Cache::driver('array')->get($expectedCacheKey));
        $this->travelTo(now()->addDay());
        $this->assertNull(Cache::driver('array')->get($expectedCacheKey));
    }
}
