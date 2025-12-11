<?php
/**
 * Copyright © Lotus. All rights reserved.
 */
declare(strict_types=1);

namespace Lotus\CspWhitelist\Plugin;

use Lotus\CspWhitelist\Helper\Config;
use Magento\Csp\Helper\CspNonceProvider;
use Magento\Framework\View\Helper\SecureHtmlRenderer;

/**
 * Plugin to add nonce to script tags rendered by SecureHtmlRenderer
 * Uses Magento's core CSP nonce provider
 */
class AddNonceToScriptPlugin
{
    /**
     * @var CspNonceProvider
     */
    private CspNonceProvider $nonceProvider;

    /**
     * @var Config
     */
    private Config $config;

    /**
     * @param CspNonceProvider $nonceProvider
     * @param Config $config
     */
    public function __construct(
        CspNonceProvider $nonceProvider,
        Config $config
    ) {
        $this->nonceProvider = $nonceProvider;
        $this->config = $config;
    }

    /**
     * Add nonce attribute to script tags
     *
     * @param SecureHtmlRenderer $subject
     * @param string $result
     * @param string $tagName
     * @param array $attributes
     * @param string|null $content
     * @return string
     * @SuppressWarnings(PHPMD.UnusedFormalParameter)
     */
    public function afterRenderTag(
        SecureHtmlRenderer $subject,
        string $result,
        string $tagName,
        array $attributes,
        ?string $content = null
    ): string {
        // Check if module is enabled and request should not be excluded
        if ($this->config->shouldExcludeCurrentRequest()) {
            return $result;
        }

        // Only process script tags
        if (strtolower($tagName) !== 'script') {
            return $result;
        }

        try {
            // Generate nonce using Magento's core provider (auto-adds to CSP headers)
            $nonce = $this->nonceProvider->generateNonce();
            
            // Add nonce to the script tag if it doesn't already have one
            if (stripos($result, 'nonce=') === false && stripos($result, 'nonce =') === false) {
                // Insert nonce attribute after the opening script tag
                $result = preg_replace(
                    '/(<script\b)([^>]*)(>)/i',
                    '$1 nonce="' . $nonce . '"$2$3',
                    $result,
                    1
                );
            }
        } catch (\Exception $e) {
            // Log error but don't break the page
        }

        return $result;
    }
}

