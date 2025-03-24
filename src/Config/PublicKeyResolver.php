<?php

namespace DevAdamlar\LaravelOidc\Config;

use Firebase\JWT\Key;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use InvalidArgumentException;

class PublicKeyResolver
{
    public function __construct(
        private readonly string $publicKey,
        private readonly string $algorithm,
        private readonly string $disk
    ) {}

    public static function make(string $publicKey, string $algorithm, string $disk): self
    {
        return app()->has(self::class) ? app(self::class) : new self($publicKey, $algorithm, $disk);
    }

    public function resolve(): Key
    {
        if ($this->isPath($this->publicKey)) {
            if (($material = Storage::disk($this->disk)->get($this->publicKey)) === null) {
                throw new InvalidArgumentException('Key file '.$this->publicKey.' not found.');
            }

            return new Key($material, $this->algorithm);
        }

        return new Key($this->buildKeyMaterial($this->publicKey), $this->algorithm);
    }

    private function isPath(string $config): bool
    {
        return Str::of($config)->test('/\.\w{3,4}$/');
    }

    private function buildKeyMaterial(string $material): string
    {
        return "-----BEGIN PUBLIC KEY-----\n".wordwrap($material, 64, cut_long_words: true)."\n-----END PUBLIC KEY-----";
    }
}
