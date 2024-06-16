<?php

namespace DevAdamlar\LaravelOidc\Http\Introspection;

use DevAdamlar\LaravelOidc\Config\ConfigLoader;
use DevAdamlar\LaravelOidc\Exceptions\OidcServerException;
use Error;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;
use stdClass;

abstract class Introspector
{
    public function __construct(protected readonly ConfigLoader $configLoader)
    {
    }

    public static function make(ConfigLoader $configLoader): self
    {
        /** @var string|null $type */
        $type = $configLoader->get('introspection_auth_method');
        $errorMessage = 'Valid introspection auth method is required';
        if (empty($type) || ! is_string($type)) {
            throw new InvalidArgumentException($errorMessage);
        }
        $class = __NAMESPACE__.'\\'.Str::studly($type);
        try {
            return app()->has($class) ? app()->get($class) : app()->make($class, ['configLoader' => $configLoader]);
        } catch (Error|BindingResolutionException|ContainerExceptionInterface|NotFoundExceptionInterface) {
            throw new InvalidArgumentException($errorMessage);
        }
    }

    public function introspect(string $endpoint, string $token, ?string $tokenTypeHint = null): ?stdClass
    {
        foreach ($this->getRequired() as $key) {
            if (empty($this->configLoader->get($key))) {
                $authMethod = $this->configLoader->get('introspection_auth_method');
                throw new InvalidArgumentException($key.' is required for introspection with '.$authMethod);
            }
        }
        $body = array_merge([
            'token' => $token,
            'token_type_hint' => $tokenTypeHint,
        ], $this->getBody());

        $response = $this->getRequest()->post($endpoint, $body);

        if ($response->failed()) {
            throw new OidcServerException('Introspection request failed at '.$endpoint);
        }

        return $response->object();
    }

    protected function getRequest(): PendingRequest|Factory
    {
        return Http::getFacadeRoot();
    }

    protected function getBody(): array
    {
        return [];
    }

    protected function getRequired(): array
    {
        return ['client_id', 'client_secret'];
    }
}
