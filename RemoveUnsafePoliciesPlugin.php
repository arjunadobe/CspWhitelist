<?php
/**
 * Copyright © Lotus. All rights reserved.
 */
declare(strict_types=1);

namespace Lotus\CspWhitelist\Plugin;

use Magento\Csp\Api\PolicyCollectorInterface;
use Magento\Csp\Model\Policy\FetchPolicy;

/**
 * Plugin to remove unsafe-inline and unsafe-eval from CSP policies
 * IMPORTANT: Works on CompositePolicyCollector to catch ALL policies including dynamic ones
 */
class RemoveUnsafePoliciesPlugin
{
    /**
     * Remove unsafe-inline and unsafe-eval from collected policies
     *
     * @param PolicyCollectorInterface $subject
     * @param array $result
     * @return array
     * @SuppressWarnings(PHPMD.UnusedFormalParameter)
     */
    public function afterCollect(PolicyCollectorInterface $subject, array $result): array
    {
        foreach ($result as $key => $policy) {
            if ($policy instanceof FetchPolicy) {
                // Check if policy has unsafe-inline or unsafe-eval enabled
                if ($policy->isInlineAllowed() || $policy->isEvalAllowed()) {
                    // Create a new policy without unsafe-inline and unsafe-eval
                    // IMPORTANT: Preserve 'self', hosts, schemes, and nonces
                    $result[$key] = new FetchPolicy(
                        $policy->getId(),
                        false, // reportOnly
                        $policy->getHostSources(),
                        $policy->getSchemeSources(),
                        $policy->isSelfAllowed(), // PRESERVE self setting
                        false, // inlineAllowed - DISABLED
                        false, // evalAllowed - DISABLED
                        $policy->getNonceValues(), // PRESERVE nonces
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

