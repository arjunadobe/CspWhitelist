<?php
/**
 * Copyright © Lotus. All rights reserved.
 */
declare(strict_types=1);

namespace Lotus\CspWhitelist\Observer;

use Lotus\CspWhitelist\Helper\Config;
use Magento\Csp\Helper\CspNonceProvider;
use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;

/**
 * Observer to add nonce to all script tags in HTML output
 * Uses Magento's core CSP nonce provider for consistency
 */
class AddNonceToScriptTags implements ObserverInterface
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
     * Add nonce to all script tags in the response
     *
     * @param Observer $observer
     * @return void
     */
    public function execute(Observer $observer): void
    {
        // Check if module is enabled and request should not be excluded
        if ($this->config->shouldExcludeCurrentRequest()) {
            return;
        }

        try {
            $response = $observer->getEvent()->getResponse();
            
            if (!$response) {
                return;
            }

            $html = $response->getBody();
            
            if (empty($html) || strpos($html, '<script') === false) {
                return;
            }

            // Generate nonce using Magento's core provider
            // This automatically adds it to CSP headers AND returns base64-encoded value
            $nonce = $this->nonceProvider->generateNonce();

            // Add nonce to all script tags that don't already have one
            // This regex handles all script tags including those with type="text/x-magento-init"
            $html = preg_replace_callback(
                '/<script\b(?![^>]*\bnonce[\s]*=)([^>]*)>/ius',
                function ($matches) use ($nonce) {
                    $attributes = trim($matches[1]);
                    // Add nonce attribute (already base64-encoded, no need to escape)
                    if (!empty($attributes)) {
                        return '<script nonce="' . $nonce . '" ' . $attributes . '>';
                    } else {
                        return '<script nonce="' . $nonce . '">';
                    }
                },
                $html
            );

            $response->setBody($html);
        } catch (\Exception $e) {
            // Log error but don't break the page
            // In production, you might want to log this properly
        }
    }
}


