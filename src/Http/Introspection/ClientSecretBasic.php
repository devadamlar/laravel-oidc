<?php

namespace DevAdamlar\LaravelOidc\Http\Introspection;

use Illuminate\Http\Client\PendingRequest;

class ClientSecretBasic extends Introspector
{
    public function getRequest(): PendingRequest
    {
        return parent::getRequest()->withBasicAuth(
            $this->configLoader->get('client_id'), $this->configLoader->get('client_secret')
        );
    }
}
