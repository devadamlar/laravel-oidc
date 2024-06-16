<?php

namespace DevAdamlar\LaravelOidc\Http\Introspection;

class ClientSecretPost extends Introspector
{
    protected function getBody(): array
    {
        return [
            'client_id' => $this->configLoader->get('client_id'),
            'client_secret' => $this->configLoader->get('client_secret'),
        ];
    }
}
