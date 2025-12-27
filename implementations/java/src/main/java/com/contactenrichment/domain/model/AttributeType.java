package com.contactenrichment.domain.model;

/**
 * Attribute types used for contact enrichment.
 */
public enum AttributeType {
    // Demographic
    FULL_NAME,
    JOB_TITLE,
    SENIORITY_LEVEL,
    DEPARTMENT,
    PHONE_WORK,
    PHONE_MOBILE,
    LOCATION,
    LINKEDIN_URL,
    TWITTER_HANDLE,

    // Firmographic
    COMPANY_NAME,
    COMPANY_DOMAIN,
    COMPANY_SIZE,
    COMPANY_INDUSTRY,
    COMPANY_REVENUE,
    COMPANY_FUNDING_STAGE,

    // Technographic
    TECH_STACK,

    // Intent
    INTENT_TOPICS,
    INTENT_SCORE
}
