<?php

declare(strict_types=1);

namespace DevAdamlar\LaravelOidc\Exceptions;

use Illuminate\Auth\AuthenticationException;

class UserNotFoundException extends AuthenticationException
{
    public function __construct(string $guard)
    {
        parent::__construct('User not found.', [$guard]);
    }
}
