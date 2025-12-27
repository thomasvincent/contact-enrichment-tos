package com.contactenrichment.domain.model;

/**
 * Legal basis for processing (GDPR/CCPA etc.).
 */
public enum LegalBasis {
    GDPR_ART6_1A_CONSENT,
    GDPR_ART6_1B_CONTRACT,
    GDPR_ART6_1F_LEGITIMATE_INTEREST,
    CCPA_NOTICE,
    CCPA_OPT_OUT
}
