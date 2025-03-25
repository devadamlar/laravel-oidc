<?php

namespace DevAdamlar\LaravelOidc\Tests\Feature\Http\JwksRoute;

use DevAdamlar\LaravelOidc\Tests\TestCase;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Storage;

class WithPrivateKeysTest extends TestCase
{
    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('oidc.cache_driver', 'array');
        $app['config']->set('oidc.cache_ttl', 86400);
        $app['config']->set('oidc.rp_jwks_path', 'jwks');
        $app['config']->set('oidc.private_key', 'certs/private.pem');
        $app['config']->set('oidc.rp_signing_algorithm', 'ES256');
        $app['config']->set('auth.guards', [
            'session' => ['driver' => 'session', 'name' => 'id'],
            'jwt' => ['driver' => 'jwt', 'key' => 'key'],
            'oidc1' => ['driver' => 'oidc', 'private_key' => 'certs/guard1_private_key.pem'],
            'oidc2' => ['driver' => 'oidc', 'private_key' => 'certs/guard2_private_key.pem', 'rp_signing_algorithm' => 'ES384'],
            'oidc3' => ['driver' => 'oidc', 'private_key' => 'certs/guard3_private_key.pem', 'rp_signing_algorithm' => 'RS512'],
            'oidc4' => ['driver' => 'oidc', 'rp_signing_algorithm' => 'ES256K'],
            'oidc5' => ['driver' => 'oidc'],
        ]);
        Storage::fake();
        Storage::put('certs/private.pem', <<<'PEM'
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
-----END PRIVATE KEY-----
PEM
        );
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
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvz9igQWiA5UsMMi9nc9U1iqwUoIw1M8JUsi8L6CHfO20C6DY
LFex8n+FFXItz6MG5W8ovzkRRFOgTelEooe2DKMUzlke+La+ZI+E2kUU4T2GAlWf
7M4mlKw+JuaZXcR2HZrm4WaohukLxR9UtvmBuQsoiWfVx8f4PZsfxkYoKvzSGZg6
ZFsPw62CXdUaOzo415IL4nQyJKiQaza451Qs4SCyerXlPF8W+47S3ZeWYx4U49WE
AA6vxSIdIYoDviwVOAtAd5jBSFHSAaZV3ngyjoWoKDVe/q0NGa9rtwGMSBtPcHtv
CV8ncNzsG+KN1FEqtnSq3VcP+bdvaBrvzZMwcQIDAQABAoIBADPBq57PL3FYxYTO
TsKOgZ8UHnO12BE/ln5Y5NTe1MvyaG9dMCOP+BBwgkuzgsJWlF8zHgviHdIn75Im
NvTlVVdGKzNM2xzkF9KPJJ0NZQEv7Txkf8tOXxKNKqTMc2T07iJE8Ya+iY05NH48
ZGjATWMOqgHFoA1ZCM1jVc4K3oQDPuwZDD2eW/9/nOZFjCDs8kr5QsLU+SCjALx5
2NEy1hoq2fOstCGpEBK9CJzYsJTbdnERGIHDLise0rwQ/3UIKYb5BvxZhw64AO3h
/wOv8Bh1pQCMKCSfbBTmPZB0Yot/DMAQtiDEeFYCQ8zYSNFx43K2pQ9QB8/c8AEC
KbxHsKECgYEA/FmlX7SyP9dK7XtcTAqsdHFu5+OmQQOQhxVIZOgxLakUWyBHS7Vk
KWfp0dS1qJ4OJHUxubzAmuVMEyQaLxqe44BxD22dlQ7x0e5a4ZA1NiSOItDr9KZO
2LTlQa3UAbSWPnUpDleXlQc0BuMaQeOIqRs0+WG2ga22yutZIfO3SGMCgYEAwgN/
9JItPAkV2Fm37wFtCtZwigNPyj/7CIjumR65HqufC72kLmS5xvRV+SfPYAGgWKMv
mmqgpQHT/dLjtod/W8LhsqK+CgqB1qbTLY4h6BXSJRBe4hPmVdFqLASH6X7T0HIt
rxQCGZgKrGw5QuipQiVwFD2Lqw0Ah2sPA8xxmhsCgYEAvlh4b3qDQbiJohx9ADbE
4oh1maCT1VJ1AA/Drame/swcuKfeX3MRfFIPguEprWibTlDAE1QXDD+NZJrEzWcN
FpnZrkOGq9q7+RgLoTz/hjmIpSZl9QJFUx0QGLyfwDGRasdBErprclQeoFtJgQ26
FaSaDsnvul1oFiPz9bI6O/UCgYAB4f7P5MtDleL8YoKCc0UXodUdwcJ4d/57qriG
C+JIBepZNtHtEVUsNRrQfC5rBBkGQy8nFHnSoB3qjK1hDBeUUGPYU/P8LPXtm1jZ
TFPP6MZNTcdd8kt98bZSDwkynuR3VWRUGqGalfskiThVCeT6m1pnF+HPGyUyKzvO
EaHYmQKBgBD6ZCHsWJ7xGLiL7L067TprxL+VxinP/EfNHsSBCrTyKMhZCVSuSh6E
8IYoQqHGF0y6gRZ431oPxAZMu/XItB8s/8TXmoYxB6PPEaFpimf/NatH6NccbcXY
qN1RuLvm9IjLMmXps4slvZA49GaMdjoK+tfxd6qtkDtMlW0Cxg8a
-----END RSA PRIVATE KEY-----
PEM
        );
    }

    public function test_should_return_jwks_based_on_given_private_keys(): void
    {
        // Act
        $response = $this->getJson('jwks');
        $expectedCacheKey = 'laravel-oidc:rp:jwks:888e7f2e731c47431349feefbd23ee62';
        $expectedJwks = [
            'keys' => [
                [
                    'kid' => 'VrUsVk0eLNVAMnejOiLLccHcixeqjj1wAHPjm3Hu6dM',
                    'use' => 'sig',
                    'kty' => 'EC',
                    'alg' => 'ES256',
                    'crv' => 'prime256v1',
                    'x' => 'EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84',
                    'y' => 'kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY',
                ],
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
                    'kid' => 'HCSjgErl6G3OXNTnx5WCUU4BnlUpp6q4KYHTO959_60',
                    'use' => 'sig',
                    'kty' => 'RSA',
                    'alg' => 'RS512',
                    'n' => 'vz9igQWiA5UsMMi9nc9U1iqwUoIw1M8JUsi8L6CHfO20C6DYLFex8n-FFXItz6MG5W8ovzkRRFOgTelEooe2DKMUzlke-La-ZI-E2kUU4T2GAlWf7M4mlKw-JuaZXcR2HZrm4WaohukLxR9UtvmBuQsoiWfVx8f4PZsfxkYoKvzSGZg6ZFsPw62CXdUaOzo415IL4nQyJKiQaza451Qs4SCyerXlPF8W-47S3ZeWYx4U49WEAA6vxSIdIYoDviwVOAtAd5jBSFHSAaZV3ngyjoWoKDVe_q0NGa9rtwGMSBtPcHtvCV8ncNzsG-KN1FEqtnSq3VcP-bdvaBrvzZMwcQ',
                    'e' => 'AQAB',
                ],
                [
                    'kid' => 'VrUsVk0eLNVAMnejOiLLccHcixeqjj1wAHPjm3Hu6dM',
                    'use' => 'sig',
                    'kty' => 'EC',
                    'alg' => 'ES256K',
                    'crv' => 'prime256v1',
                    'x' => 'EVs_o5-uQbTjL3chynL4wXgUg2R9q9UU8I5mEovUf84',
                    'y' => 'kGe5DgSIycKp8w9aJmoHhB1sB3QTugfnRWm5nU_TzsY',
                ],
            ],
        ];

        // Assert
        $response
            ->assertStatus(200)
            ->assertJsonCount(5, 'keys')
            ->assertJson($expectedJwks);
        $this->assertTrue(Cache::driver('array')->has($expectedCacheKey));
        $this->assertEquals($expectedJwks, Cache::driver('array')->get($expectedCacheKey));
        $this->travelTo(now()->addDay());
        $this->assertNull(Cache::driver('array')->get($expectedCacheKey));
    }
}
