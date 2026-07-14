# Dalang SSO — PHP SDK

A small client for the [Dalang SSO](https://sso.example.com) OAuth 2.0 /
OpenID Connect provider, built on curl. Drives the Authorization Code + PKCE
flow.

```
composer require dalang/sso
```

## Usage

```php
<?php

require 'vendor/autoload.php';

use Dalang\Sso\Client;
use Dalang\Sso\Pkce;

// Configure with the values from your Dalang SSO dashboard.
$client = new Client(
    'https://sso.example.com',
    'CLIENT_ID',
    'CLIENT_SECRET',
    'https://app.example.com/callback',
);

// 1. Build the authorize URL with a fresh PKCE pair, then redirect the user's
//    browser to it. Persist $pkce->verifier (e.g. in the session).
$pkce = Pkce::generate();
$url = $client->authorizeUrl('openid email', 'state123', $pkce);
echo "Redirect the user to: $url\n";

// 2. At your callback, exchange the returned ?code=... for tokens.
$tokens = $client->exchangeCode('CODE_FROM_CALLBACK', $pkce);
echo "access token: {$tokens['access_token']}\n";

// 3. Fetch the user's profile.
$info = $client->userInfo($tokens['access_token']);
echo "logged in as: {$info['email']}\n";

// 4. Later, refresh the access token.
if (!empty($tokens['refresh_token'])) {
    $refreshed = $client->refresh($tokens['refresh_token']);
    echo "new access token: {$refreshed['access_token']}\n";
}
```

Omit PKCE by leaving off the `$pkce` argument (it defaults to `null`).
