<?php

namespace DevAdamlar\LaravelOidc\Support;

enum Alg: string
{
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES256K = 'ES256K';

    public function isRsa(): bool
    {
        return match ($this) {
            self::RS256, self::RS384, self::RS512 => true,
            default => false,
        };
    }

    public function isEc(): bool
    {
        return ! $this->isRsa();
    }
}
