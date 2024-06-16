<?php

declare(strict_types=1);

namespace DevAdamlar\LaravelOidc\Tests\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    protected $fillable = ['auth_id'];

    public function getAuthIdentifierName(): string
    {
        return 'auth_id';
    }
}
