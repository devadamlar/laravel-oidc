<?php

declare(strict_types=1);

namespace DevAdamlar\LaravelOidc\Config;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;

class ConfigLoader
{
    private array $config;

    public function __construct(array $config)
    {
        $this->config = $config;
    }

    public function get(string $key, ?callable $process = null): bool|int|float|string|null
    {
        $value = $this->config[$key] ?? null;

        if ($process === null || $process($value)) {
            $value = $value ?? Config::get("oidc.$key");
        }

        if (Str::isUrl($value, ['http', 'https'])) {
            return trim($value, '/');
        }

        if (Str::isUrl(Config::get("oidc.$key"), ['http', 'https'])) {
            return trim(Config::get("oidc.$key"), '/').'/'.trim($value, '/');
        }

        return is_numeric($value) ? (int) $value : $value;
    }
}
