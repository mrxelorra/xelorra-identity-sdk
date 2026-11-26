# WordPress & Symfony Quickstart Snippets

## WordPress Plugin Snippet (REST Callback + Webhook)

```php
<?php

use Xelorra\Identity\Constants;
use Xelorra\Identity\Exceptions\WebhookSignatureException;
use Xelorra\Identity\Webhook;
use Xelorra\Identity\XelorraClient;

add_action('rest_api_init', function () {
    register_rest_route('xelorra/v1', '/login', [
        'methods' => 'GET',
        'permission_callback' => '__return_true',
        'callback' => function (\WP_REST_Request $request) {
            $client = new XelorraClient(
                clientId: defined('XELORRA_CLIENT_ID') ? XELORRA_CLIENT_ID : '',
                redirectUri: rest_url('xelorra/v1/callback'),
                clientSecret: defined('XELORRA_CLIENT_SECRET') ? XELORRA_CLIENT_SECRET : null,
            );
            $isSignUp = $request->get_param('mode') === 'signup';
            $auth = $isSignUp ? $client->buildSignUpUrl() : $client->buildSignInUrl();

            set_transient('xelorra_pkce_' . $auth['pkce']['state'], $auth['pkce']['codeVerifier'], 600);
            wp_redirect($auth['url']);
            exit;
        },
    ]);

    register_rest_route('xelorra/v1', '/webhook', [
        'methods' => 'POST',
        'permission_callback' => '__return_true',
        'callback' => function (\WP_REST_Request $request) {
            try {
                $event = Webhook::parseEvent(
                    $request->get_body(),
                    (string) $request->get_header(Constants::HEADER_SIGNATURE),
                    defined('XELORRA_WEBHOOK_SECRET') ? XELORRA_WEBHOOK_SECRET : '',
                );
            } catch (WebhookSignatureException $e) {
                return new \WP_REST_Response(['error' => $e->errorCode], 401);
            }

            if ($event['type'] === Constants::EVENT_USER_ACCESS_REVOKED) {
                $sub = (string) ($event['data']['sub'] ?? '');
                $users = get_users(['meta_key' => 'xelorra_sub', 'meta_value' => $sub, 'fields' => 'ID']);
                foreach ($users as $userId) {
                    \WP_Session_Tokens::get_instance((int) $userId)->destroy_all();
                }
            }

            return new \WP_REST_Response(['received' => true], 200);
        },
    ]);
});
```

## Symfony 6/7 Controller Snippet

```php
<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Xelorra\Identity\Constants;
use Xelorra\Identity\Exceptions\WebhookSignatureException;
use Xelorra\Identity\Webhook;
use Xelorra\Identity\XelorraClient;

class XelorraController extends AbstractController
{
    public function __construct(private readonly XelorraClient $xelorra)
    {
    }

    #[Route('/auth/xelorra/signup', name: 'xelorra_signup', methods: ['GET'])]
    public function signUp(Request $request): RedirectResponse
    {
        $auth = $this->xelorra->buildSignUpUrl();
        $request->getSession()->set('xelorra_state', $auth['pkce']['state']);
        $request->getSession()->set('xelorra_verifier', $auth['pkce']['codeVerifier']);
        return $this->redirect($auth['url']);
    }

    #[Route('/webhooks/xelorra', name: 'xelorra_webhook', methods: ['POST'])]
    public function webhook(Request $request): JsonResponse
    {
        try {
            $event = Webhook::parseEvent(
                (string) $request->getContent(),
                (string) $request->headers->get(Constants::HEADER_SIGNATURE, ''),
                $_ENV['XELORRA_WEBHOOK_SECRET'] ?? '',
            );
        } catch (WebhookSignatureException $e) {
            return $this->json(['error' => $e->errorCode], 401);
        }

        return $this->json(['received' => true, 'event_type' => $event['type']]);
    }
}
```
