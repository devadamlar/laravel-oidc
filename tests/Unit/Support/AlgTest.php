<?php

namespace DevAdamlar\LaravelOidc\Tests\Unit\Support;

use DevAdamlar\LaravelOidc\Support\Alg;
use PHPUnit\Framework\TestCase;

class AlgTest extends TestCase
{
    /**
     * @dataProvider algProvider
     */
    public function test_is_ec(Alg $alg, bool $isEc): void
    {
        // Act & Assert
        $this->assertSame($isEc, $alg->isEc());
    }

    public static function algProvider(): array
    {
        return [
            [Alg::ES256, true],
            [Alg::ES384, true],
            [Alg::ES512, true],
            [Alg::ES256K, true],
            [Alg::RS256, false],
            [Alg::RS384, false],
            [Alg::RS512, false],
        ];
    }
}
