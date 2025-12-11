<?php
/**
 * Copyright © Lotus. All rights reserved.
 */
declare(strict_types=1);

namespace Lotus\CspWhitelist\Plugin;

use Lotus\CspWhitelist\Helper\Config;
use Magento\Csp\Helper\CspNonceProvider;
use Magento\Framework\View\TemplateEngine\Php;

/**
 * Plugin to add nonce to inline scripts in PHTML templates
 * This is the key - we intercept template rendering, not just final output
 */
class AddNonceToTemplatePlugin
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
     * Add nonce to all script tags in rendered template output
     *
     * @param Php $subject
     * @param string $result
     * @return string
     * @SuppressWarnings(PHPMD.UnusedFormalParameter)
     */
    public function afterRender(Php $subject, string $result): string
    {
        // Check if module is enabled and request should not be excluded
        if ($this->config->shouldExcludeCurrentRequest()) {
            return $result;
        }

        // Skip if no script tags
        if (strpos($result, '<script') === false) {
            return $result;
        }

        try {
            // Generate nonce (auto-adds to CSP headers)
            $nonce = $this->nonceProvider->generateNonce();

            // Add nonce to all script tags that don't already have one
            // This handles ALL script types including text/x-magento-init
            $result = preg_replace_callback(
                '/<script\b(?![^>]*\bnonce[\s]*=)([^>]*)>/ius',
                function ($matches) use ($nonce) {
                    $attributes = trim($matches[1]);
                    if (!empty($attributes)) {
                        return '<script nonce="' . $nonce . '" ' . $attributes . '>';
                    }
                    return '<script nonce="' . $nonce . '">';
                },
                $result
            );
        } catch (\Exception $e) {
            // Silently fail to avoid breaking page
        }

        return $result;
    }
}

