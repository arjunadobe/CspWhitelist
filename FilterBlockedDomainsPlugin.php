<?php
/**
 * Copyright © Lotus. All rights reserved.
 */
declare(strict_types=1);

namespace Lotus\CspWhitelist\Plugin;

use Lotus\CspWhitelist\Helper\Config;
use Magento\Csp\Model\Collector\CspWhitelistXmlCollector;
use Magento\Csp\Model\Policy\FetchPolicy;

/**
 * Plugin to filter blocked third-party domains from CSP whitelist
 */
class FilterBlockedDomainsPlugin
{
    /**
     * @var Config
     */
    private Config $config;

    /**
     * @param Config $config
     */
    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * Filter out blocked domains from collected CSP whitelist policies
     *
     * @param CspWhitelistXmlCollector $subject
     * @param array $result
     * @return array
     * @SuppressWarnings(PHPMD.UnusedFormalParameter)
     */
    public function afterCollect(CspWhitelistXmlCollector $subject, array $result): array
    {
        if (!$this->config->isBlockThirdPartyDomainsEnabled()) {
            return $result;
        }

        foreach ($result as $key => $policy) {
            if ($policy instanceof FetchPolicy) {
                $hostSources = $policy->getHostSources();
                $filteredHosts = [];

                // Filter out blocked hosts
                foreach ($hostSources as $host) {
                    if (!$this->config->isHostBlocked($host)) {
                        $filteredHosts[] = $host;
                    }
                }

                // If hosts were filtered, create new policy with filtered hosts
                if (count($filteredHosts) !== count($hostSources)) {
                    $result[$key] = new FetchPolicy(
                        $policy->getId(),
                        $policy->isReportOnly(),
                        $filteredHosts, // Filtered hosts
                        $policy->getSchemeSources(),
                        $policy->isSelfAllowed(),
                        $policy->isInlineAllowed(),
                        $policy->isEvalAllowed(),
                        $policy->getNonceValues(),
                        $policy->getHashes(),
                        $policy->isDynamicAllowed(),
                        $policy->isEventHandlersAllowed()
                    );
                }
            }
        }

        return $result;
    }
}

