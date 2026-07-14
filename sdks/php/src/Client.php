<?php

declare(strict_types=1);

namespace Dalang\Sso;

use RuntimeException;

/**
 * Client for the Dalang SSO OAuth 2.0 / OpenID Connect provider.
 *
 * Drives the Authorization Code + PKCE flow against a self-hosted Dalang SSO
 * instance. Mirrors the Google OAuth client shape: you configure a client_id,
 * client_secret, and redirect_uri, then build an authorize URL, exchange the
 * returned code for tokens, refresh tokens, and fetch userinfo.
 */
final class Client
{
    private string $baseUrl;

    /**
     * @param string $baseUrl the SSO instance root, e.g. "https://sso.example.com"
     */
    public function __construct(
        string $baseUrl,
        private readonly string $clientId,
        private readonly string $clientSecret,
        private readonly string $redirectUri,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    /**
     * Build the URL to redirect the user's browser to for consent.
     */
    public function authorizeUrl(string $scope, string $state, ?Pkce $pkce = null): string
    {
        $params = [
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $this->redirectUri,
            'scope' => $scope,
            'state' => $state,
        ];
        if ($pkce !== null) {
            $params['code_challenge'] = $pkce->challenge;
            $params['code_challenge_method'] = 'S256';
        }

        return $this->baseUrl . '/oauth/authorize?' . http_build_query($params);
    }

    /**
     * Exchange an authorization code for tokens.
     *
     * @return array<string,mixed> decoded token response
     */
    public function exchangeCode(string $code, ?Pkce $pkce = null): array
    {
        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ];
        if ($pkce !== null) {
            $form['code_verifier'] = $pkce->verifier;
        }

        return $this->postToken($form);
    }

    /**
     * Exchange a refresh token for a fresh set of tokens.
     *
     * @return array<string,mixed> decoded token response
     */
    public function refresh(string $refreshToken): array
    {
        return $this->postToken([
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
        ]);
    }

    /**
     * Fetch the profile for a given access token.
     *
     * @return array<string,mixed> {sub, email}
     */
    public function userInfo(string $accessToken): array
    {
        [$status, $body] = $this->request(
            'GET',
            $this->baseUrl . '/oauth/userinfo',
            null,
            ['Authorization: Bearer ' . $accessToken],
        );
        if ($status >= 400) {
            throw new RuntimeException("userinfo request failed ($status): $body");
        }

        return $this->decode($body);
    }

    /**
     * @param array<string,string> $form
     * @return array<string,mixed>
     */
    private function postToken(array $form): array
    {
        [$status, $body] = $this->request(
            'POST',
            $this->baseUrl . '/oauth/token',
            http_build_query($form),
            ['Content-Type: application/x-www-form-urlencoded'],
        );
        $json = $this->decode($body);
        if ($status >= 400) {
            throw new OAuthException(
                (string) ($json['error'] ?? 'invalid_request'),
                (string) ($json['error_description'] ?? ''),
            );
        }

        return $json;
    }

    /**
     * Perform an HTTP request with curl.
     *
     * @param list<string> $headers
     * @return array{0:int,1:string} [status code, response body]
     */
    private function request(string $method, string $url, ?string $body, array $headers): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headers,
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $response = curl_exec($ch);
        if ($response === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new RuntimeException("http request failed: $err");
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        return [$status, (string) $response];
    }

    /**
     * @return array<string,mixed>
     */
    private function decode(string $body): array
    {
        $json = json_decode($body, true);
        if (!is_array($json)) {
            throw new RuntimeException('invalid JSON response: ' . $body);
        }

        return $json;
    }
}
