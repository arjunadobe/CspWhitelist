<?php
/**
 * Copyright © Lotus. All rights reserved.
 */
declare(strict_types=1);

namespace Lotus\CspWhitelist\Helper;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Store\Model\ScopeInterface;

/**
 * Configuration Helper for Lotus CSP Whitelist
 */
class Config
{
    private const XML_PATH_ENABLED = 'csp/lotus_csp_whitelist/enabled';
    private const XML_PATH_EXCLUDE_REST_API = 'csp/lotus_csp_whitelist/exclude_rest_api';
    private const XML_PATH_EXCLUDE_ADMIN_TOKEN = 'csp/lotus_csp_whitelist/exclude_admin_token';
    private const XML_PATH_BLOCK_THIRD_PARTY = 'csp/lotus_csp_whitelist/block_third_party_domains';
    private const XML_PATH_BLOCKED_DOMAINS = 'csp/lotus_csp_whitelist/blocked_domains';

    /**
     * @var ScopeConfigInterface
     */
    private ScopeConfigInterface $scopeConfig;

    /**
     * @var RequestInterface
     */
    private RequestInterface $request;

    /**
     * @param ScopeConfigInterface $scopeConfig
     * @param RequestInterface $request
     */
    public function __construct(
        ScopeConfigInterface $scopeConfig,
        RequestInterface $request
    ) {
        $this->scopeConfig = $scopeConfig;
        $this->request = $request;
    }

    /**
     * Check if nonce generation is enabled
     *
     * @return bool
     */
    public function isEnabled(): bool
    {
        return $this->scopeConfig->isSetFlag(
            self::XML_PATH_ENABLED,
            ScopeInterface::SCOPE_STORE
        );
    }

    /**
     * Check if current request should be excluded from nonce generation
     *
     * @return bool
     */
    public function shouldExcludeCurrentRequest(): bool
    {
        if (!$this->isEnabled()) {
            return true;
        }

        $requestUri = $this->request->getRequestUri();
        $pathInfo = $this->request->getPathInfo();

        // Exclude REST API endpoints
        if ($this->isExcludeRestApi()) {
            if (strpos($pathInfo, '/rest/') !== false || 
                strpos($pathInfo, '/V1/') !== false ||
                strpos($requestUri, '/rest/') !== false ||
                strpos($requestUri, '/V1/') !== false) {
                return true;
            }
        }

        // Exclude admin token creation
        if ($this->isExcludeAdminToken()) {
            if (strpos($pathInfo, '/integration/admin/token') !== false ||
                strpos($pathInfo, '/integration/customer/token') !== false ||
                strpos($requestUri, '/integration/admin/token') !== false ||
                strpos($requestUri, '/integration/customer/token') !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if REST API should be excluded
     *
     * @return bool
     */
    private function isExcludeRestApi(): bool
    {
        return $this->scopeConfig->isSetFlag(
            self::XML_PATH_EXCLUDE_REST_API,
            ScopeInterface::SCOPE_STORE
        );
    }

    /**
     * Check if admin token creation should be excluded
     *
     * @return bool
     */
    private function isExcludeAdminToken(): bool
    {
        return $this->scopeConfig->isSetFlag(
            self::XML_PATH_EXCLUDE_ADMIN_TOKEN,
            ScopeInterface::SCOPE_STORE
        );
    }

    /**
     * Check if third-party domain blocking is enabled
     *
     * @return bool
     */
    public function isBlockThirdPartyDomainsEnabled(): bool
    {
        return $this->scopeConfig->isSetFlag(
            self::XML_PATH_BLOCK_THIRD_PARTY,
            ScopeInterface::SCOPE_STORE
        );
    }

    /**
     * Get blocked domain patterns
     *
     * @return array
     */
    public function getBlockedDomainPatterns(): array
    {
        if (!$this->isBlockThirdPartyDomainsEnabled()) {
            return [];
        }

        $blockedDomains = $this->scopeConfig->getValue(
            self::XML_PATH_BLOCKED_DOMAINS,
            ScopeInterface::SCOPE_STORE
        );

        if (empty($blockedDomains)) {
            return [];
        }

        // Split by newline and filter empty lines
        $patterns = array_filter(
            array_map('trim', explode("\n", $blockedDomains)),
            function ($pattern) {
                return !empty($pattern);
            }
        );

        return $patterns;
    }

    /**
     * Check if a host matches any blocked domain pattern
     *
     * @param string $host
     * @return bool
     */
    public function isHostBlocked(string $host): bool
    {
        $patterns = $this->getBlockedDomainPatterns();
        
        if (empty($patterns)) {
            return false;
        }

        foreach ($patterns as $pattern) {
            // Convert wildcard pattern to regex
            $regex = '/^' . str_replace(
                ['*', '.'],
                ['.*', '\.'],
                $pattern
            ) . '$/i';

            if (preg_match($regex, $host)) {
                return true;
            }
        }

        return false;
    }
}

