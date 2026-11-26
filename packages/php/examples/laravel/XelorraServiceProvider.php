<?php

declare(strict_types=1);

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Xelorra\Identity\Constants;
use Xelorra\Identity\XelorraClient;

class XelorraServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(XelorraClient::class, function () {
            return new XelorraClient(
                clientId: (string) config('services.xelorra.client_id'),
                redirectUri: (string) config('services.xelorra.redirect_uri'),
                clientSecret: config('services.xelorra.client_secret'),
                issuer: (string) config('services.xelorra.issuer', Constants::DEFAULT_ISSUER),
                scopes: config('services.xelorra.scopes', Constants::DEFAULT_SCOPES),
            );
        });
    }
}
