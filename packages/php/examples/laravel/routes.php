<?php

declare(strict_types=1);

use App\Http\Controllers\XelorraAuthController;
use App\Http\Controllers\XelorraWebhookController;
use App\Http\Middleware\EnsureXelorraConnected;
use Illuminate\Support\Facades\Route;

// Web routes (routes/web.php)
Route::get('/auth/xelorra/login', [XelorraAuthController::class, 'redirectToSignIn'])->name('xelorra.login');
Route::get('/auth/xelorra/signup', [XelorraAuthController::class, 'redirectToSignUp'])->name('xelorra.signup');
Route::get('/auth/xelorra/callback', [XelorraAuthController::class, 'callback'])->name('xelorra.callback');
Route::post('/auth/xelorra/disconnect', [XelorraAuthController::class, 'disconnect'])
    ->middleware('auth')
    ->name('xelorra.disconnect');

// Protected area with two-way disconnect sync middleware
Route::middleware(['auth', EnsureXelorraConnected::class])->group(function () {
    Route::get('/dashboard', fn () => view('dashboard'))->name('dashboard');
});

// Webhook route (routes/api.php or excluded from CSRF middleware)
Route::post('/webhooks/xelorra', [XelorraWebhookController::class, 'handle'])->name('xelorra.webhook');
