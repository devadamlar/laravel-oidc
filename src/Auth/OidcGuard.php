<?php

declare(strict_types=1);

namespace DevAdamlar\LaravelOidc\Auth;

use DevAdamlar\LaravelOidc\Config\ConfigLoader;
use DevAdamlar\LaravelOidc\Config\PublicKeyResolver;
use DevAdamlar\LaravelOidc\Exceptions\TokenException;
use DevAdamlar\LaravelOidc\Exceptions\UserNotFoundException;
use DevAdamlar\LaravelOidc\Http\Client\OidcClient;
use DomainException;
use ErrorException;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use InvalidArgumentException;
use stdClass;
use UnexpectedValueException;

class OidcGuard implements Guard
{
    use GuardHelpers;

    protected Request $request;

    protected string $name;

    public ?stdClass $claims = null;

    /**
     * The name of the query string item from the request containing the API token.
     */
    protected ?string $inputKey;

    protected bool $useIntrospection;

    protected int $leeway;

    protected string $principalIdentifier;

    protected ?PublicKeyResolver $publicKey;

    protected string $signingAlgorithm;

    protected ?string $keyMaterial;

    protected string $disk;

    protected ?string $audience;

    protected OidcClient $client;

    public function __construct(UserProvider $provider, Request $request, string $name, ConfigLoader $config)
    {
        $this->provider = $provider;
        $this->request = $request;
        $this->name = $name;
        $this->client = OidcClient::make($config);

        $this->inputKey = $config->get('input_key');
        $this->disk = $config->get('key_disk');

        // Authority
        $issuer = $config->get('issuer');
        $publicKey = $config->get('public_key', fn ($value) => ! Str::isUrl($issuer));

        $this->signingAlgorithm = $config->get('signing_algorithm');
        $this->publicKey = $publicKey !== null ? PublicKeyResolver::make($publicKey, $this->signingAlgorithm, $this->disk) : null;

        // Introspection
        $this->useIntrospection = $config->get('use_introspection');

        // JWT
        $this->leeway = $config->get('leeway');
        $this->principalIdentifier = $config->get('principal_identifier');
        $this->audience = $config->get('audience');
    }

    /**
     * @throws InvalidArgumentException Issuer is required for introspection
     * @throws InvalidArgumentException Client credentials are required for introspection
     * @throws InvalidArgumentException Issuer or public key is required for decoding JWT
     * @throws InvalidArgumentException Provided issuer is not a valid HTTP URL
     * @throws InvalidArgumentException Unable to load public key
     * @throws InvalidArgumentException Supplied public key is invalid
     * @throws InvalidArgumentException Invalid introspection auth method
     * @throws InvalidArgumentException Required configuration is missing for introspection
     * @throws TokenException Provided JWT is invalid
     * @throws TokenException Signature verification failed for provided JWT
     * @throws TokenException Audience does not match the expected audience
     * @throws UserNotFoundException Token was valid but user not found
     */
    public function user(): ?Authenticatable
    {
        if (! is_null($this->user)) {
            return $this->user;
        }

        $token = $this->getTokenForRequest();

        if (empty($token)) {
            return null;
        }

        $this->claims = match ($this->useIntrospection) {
            true => $this->introspect($token),
            false => $this->validateJwt($token)
        };

        if ($this->claims) {
            $this->validateAudience();
            $user = $this->provider->retrieveById($this->claims->{$this->principalIdentifier});
            if ($user === null) {
                throw new UserNotFoundException($this->name);
            }
            $this->setUser($user);
            $this->defineGates();
        }

        return $this->user;
    }

    /**
     * @throws TokenException
     */
    private function validateJwt(string $token): ?stdClass
    {
        $publicKeys = $this->getPublicKeys();
        try {
            JWT::$leeway = $this->leeway;

            return JWT::decode($token, $publicKeys);
        } catch (
            BeforeValidException|ExpiredException|SignatureInvalidException|UnexpectedValueException|DomainException $e
        ) {
            throw new TokenException($e->getMessage());
        } catch (ErrorException) {
            throw new InvalidArgumentException('Supplied public key is invalid.');
        }
    }

    private function getPublicKeys(): array|Key
    {
        if ($this->publicKey !== null) {
            return $this->publicKey->resolve();
        }
        if ($this->client->getIssuer() !== null) {
            return JWK::parseKeySet($this->client->downloadKeys(), $this->signingAlgorithm);
        }

        throw new InvalidArgumentException('Issuer or public key is required to verify JWT signature.');
    }

    private function introspect(string $token): ?stdClass
    {
        $response = $this->client->introspect($token);

        return $response?->active ? $response : null;
    }

    private function validateAudience(): void
    {
        if ($this->audience &&
            ((is_string($this->claims->aud) && $this->claims->aud !== $this->audience) ||
                (is_array($this->claims->aud) && ! in_array($this->audience, $this->claims->aud)) ||
                (is_null($this->claims->aud)))
        ) {
            throw new TokenException('Token audience does not match the expected audience.');
        }
    }

    /**
     * Get the token for the current request.
     */
    public function getTokenForRequest(): ?string
    {
        return $this->request->bearerToken() ?? $this->request->input($this->inputKey);
    }

    /**
     * Validate a user's credentials.
     */
    public function validate(array $credentials = []): bool
    {
        // Not applicable for OIDC
        // Consider whether to throw an exception or return false
        // Consider whether to send a request to token endpoint to validate password grant: NO!
        // $this->provider->retrieveByCredentials($credentials); // This is not applicable for OIDC, because it expects username and password
        return false;
    }

    /**
     * Get all scopes
     */
    public function scopes(): array
    {
        $scopes = $this->claims->scope ?? null;

        if ($scopes) {
            return explode(' ', $scopes);
        }

        return [];
    }

    /**
     * Check if authenticated user has a given scope
     */
    public function hasScope(string $scope): bool
    {
        $scopes = $this->scopes();

        if (in_array($scope, $scopes)) {
            return true;
        }

        return false;
    }

    /**
     * Check if authenticated user has any of the given scopes
     */
    public function hasAnyScope(array $scopes): bool
    {
        return count(array_intersect(
            $this->scopes(),
            $scopes
        )) > 0;
    }

    private function defineGates(): void
    {
        foreach ($this->scopes() as $scope) {
            Gate::define($scope, fn () => true);
        }
    }
}
