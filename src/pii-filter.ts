/**
 * SafePipe Core: Zero-Knowledge PII Redaction Engine
 * 
 * This module provides deterministic, in-memory PII detection and redaction.
 * No data is persisted, logged, or transmitted. All processing happens locally.
 * 
 * @license MIT
 * @author SafePipe.eu Security Team
 * @version 1.0.0
 */

// ═══════════════════════════════════════════════════════════════════════════════
// TYPE DEFINITIONS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Severity levels for detected PII
 * - critical: Data that could enable immediate financial fraud (SSN, Credit Cards)
 * - high: Data that could enable identity theft (Email, Phone, IBAN)
 * - medium: Data that could assist in targeting (IP Address)
 * - low: Potentially sensitive context-dependent data
 */
export type Severity = "critical" | "high" | "medium" | "low";

/**
 * Supported PII types for detection
 */
export type PIIType = 
  | "email" 
  | "phone" 
  | "creditCard" 
  | "ssn" 
  | "iban" 
  | "ipAddress";

/**
 * Represents a single detected PII instance with position metadata
 */
export interface PIIMatch {
  /** The type of PII detected */
  type: PIIType;
  /** Human-readable label for the PII type */
  label: string;
  /** The actual matched value (before redaction) */
  value: string;
  /** Start index in the original string */
  start: number;
  /** End index in the original string */
  end: number;
  /** Risk severity level */
  severity: Severity;
}

/**
 * Result of PII detection operation
 */
export interface DetectionResult {
  /** Original input text */
  originalText: string;
  /** Text with all PII replaced by redaction tokens */
  redactedText: string;
  /** Array of all detected PII matches */
  matches: PIIMatch[];
  /** Summary statistics of detected PII by type */
  stats: {
    total: number;
    emails: number;
    phones: number;
    creditCards: number;
    ssns: number;
    ibans: number;
    ipAddresses: number;
  };
}

/**
 * Configuration options for the PII filter
 */
export interface FilterConfig {
  /** Enable email detection (default: true) */
  detectEmails?: boolean;
  /** Enable phone number detection (default: true) */
  detectPhones?: boolean;
  /** Enable credit card detection (default: true) */
  detectCreditCards?: boolean;
  /** Enable SSN detection (default: true) */
  detectSSNs?: boolean;
  /** Enable IBAN detection (default: true) */
  detectIBANs?: boolean;
  /** Enable IP address detection (default: true) */
  detectIPAddresses?: boolean;
  /** Custom redaction tokens (default: [TYPE_REDACTED]) */
  redactionTokens?: Partial<Record<PIIType, string>>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// REGEX PATTERNS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Core regex patterns for PII detection.
 * 
 * These patterns are battle-tested in production and designed to:
 * - Minimize false negatives (prioritize security over convenience)
 * - Handle international formats where applicable
 * - Support common separators (spaces, dashes, dots)
 * 
 * SECURITY NOTE: These patterns err on the side of caution.
 * Some false positives are acceptable; false negatives are not.
 */
const PII_PATTERNS: Record<PIIType, {
  patterns: RegExp[];
  label: string;
  severity: Severity;
}> = {
  /**
   * Email Address Detection
   * Matches: user@domain.com, user.name+tag@sub.domain.co.uk
   */
  email: {
    patterns: [
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    ],
    label: "Email Address",
    severity: "high",
  },

  /**
   * Phone Number Detection (International)
   * Matches:
   * - +1 234 567 8901 (US with country code)
   * - 00491234567890 (German with 00 prefix)
   * - +49 (0) 123 456 789 (European format)
   * - (555) 123-4567 (US local format)
   * - 555.123.4567 (Dot-separated)
   * 
   * Note: Patterns require + or 00 prefix, or specific US format to avoid
   * false positives on credit cards/IBANs
   */
  phone: {
    patterns: [
      // International: +XX or 00XX followed by digits with optional separators
      /(?:\+|00)[1-9]\d{0,3}[\s\-.]?\(?\d{1,5}\)?[\s\-.]?\d{2,4}[\s\-.]?\d{2,4}[\s\-.]?\d{0,4}/g,
      // US/Canada: (XXX) XXX-XXXX format specifically (with parentheses)
      /\(\d{3}\)[\s\-.]?\d{3}[\s\-.]?\d{4}/g,
      // US/Canada with dashes or dots: XXX-XXX-XXXX or XXX.XXX.XXXX
      /\b\d{3}[\-\.]\d{3}[\-\.]\d{4}\b/g,
    ],
    label: "Phone Number",
    severity: "high",
  },

  /**
   * Credit Card Detection
   * Matches: 4111111111111111, 4111-1111-1111-1111, 4111 1111 1111 1111
   * Covers: Visa (16), MasterCard (16), Amex (15), Discover (16)
   * 
   * Note: Requires exactly 4 groups of 4 digits, or 13-19 consecutive digits
   */
  creditCard: {
    patterns: [
      // Format: XXXX-XXXX-XXXX-XXXX or XXXX XXXX XXXX XXXX
      /\b\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}\b/g,
      // Format: 16 consecutive digits (common credit card length)
      /\b[3-6]\d{15}\b/g,
      // Format: 15 digits for Amex
      /\b3[47]\d{13}\b/g,
    ],
    label: "Credit Card Number",
    severity: "critical",
  },

  /**
   * US Social Security Number Detection
   * Matches: 123-45-6789, 123456789
   * Note: Does not validate against SSA allocation rules (intentional)
   */
  ssn: {
    patterns: [
      /\b\d{3}[-]?\d{2}[-]?\d{4}\b/g,
    ],
    label: "Social Security Number",
    severity: "critical",
  },

  /**
   * International Bank Account Number (IBAN) Detection
   * Matches: DE89370400440532013000, GB82 WEST 1234 5698 7654 32
   * Covers: All 77 IBAN countries
   */
  iban: {
    patterns: [
      /\b[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?[A-Z0-9]{4}[\s]?[A-Z0-9]{4}[\s]?[A-Z0-9]{0,14}\b/g,
      /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/g,
    ],
    label: "IBAN",
    severity: "high",
  },

  /**
   * IPv4 Address Detection
   * Matches: 192.168.1.1, 10.0.0.1
   * Note: Does not validate octet ranges (0-255)
   */
  ipAddress: {
    patterns: [
      /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d{1,2})\b/g,
    ],
    label: "IP Address",
    severity: "medium",
  },
};

/**
 * Default redaction tokens for each PII type
 */
const DEFAULT_REDACTION_TOKENS: Record<PIIType, string> = {
  email: "[EMAIL_REDACTED]",
  phone: "[PHONE_REDACTED]",
  creditCard: "[CARD_REDACTED]",
  ssn: "[SSN_REDACTED]",
  iban: "[IBAN_REDACTED]",
  ipAddress: "[IP_REDACTED]",
};

/**
 * Default filter configuration
 */
const DEFAULT_CONFIG: FilterConfig = {
  detectEmails: true,
  detectPhones: true,
  detectCreditCards: true,
  detectSSNs: true,
  detectIBANs: true,
  detectIPAddresses: true,
};

// ═══════════════════════════════════════════════════════════════════════════════
// CORE DETECTION ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Detects all PII matches in the given text for a specific PII type.
 * 
 * @param text - Input text to scan
 * @param type - PII type to detect
 * @returns Array of PIIMatch objects
 */
function detectPIIType(text: string, type: PIIType): PIIMatch[] {
  const matches: PIIMatch[] = [];
  const patternConfig = PII_PATTERNS[type];

  for (const pattern of patternConfig.patterns) {
    // Create new regex instance to reset lastIndex
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      // Prevent duplicate matches at overlapping positions
      const isDuplicate = matches.some(
        (m) => m.start <= match!.index && m.end >= match!.index + match![0].length
      );

      if (!isDuplicate) {
        matches.push({
          type,
          label: patternConfig.label,
          value: match[0],
          start: match.index,
          end: match.index + match[0].length,
          severity: patternConfig.severity,
        });
      }
    }
  }

  return matches;
}

/**
 * Detects and redacts PII from the input text.
 * 
 * This is the main entry point for the PII filter. It performs:
 * 1. Pattern matching for all enabled PII types
 * 2. Position tracking for each match
 * 3. Text redaction with configurable tokens
 * 4. Statistics aggregation
 * 
 * @param text - Input text to process
 * @param config - Optional configuration for detection behavior
 * @returns DetectionResult with redacted text and match metadata
 * 
 * @example
 * ```typescript
 * const result = detectAndRedact("Email me at john@example.com");
 * console.log(result.redactedText);
 * // Output: "Email me at [EMAIL_REDACTED]"
 * ```
 */
export function detectAndRedact(
  text: string,
  config: FilterConfig = {}
): DetectionResult {
  const mergedConfig = { ...DEFAULT_CONFIG, ...config };
  const tokens = { ...DEFAULT_REDACTION_TOKENS, ...config.redactionTokens };

  const allMatches: PIIMatch[] = [];
  let redactedText = text;

  const stats = {
    total: 0,
    emails: 0,
    phones: 0,
    creditCards: 0,
    ssns: 0,
    ibans: 0,
    ipAddresses: 0,
  };

  // Type detection mapping
  const detectionMap: { type: PIIType; enabled: boolean; statKey: keyof typeof stats }[] = [
    { type: "email", enabled: mergedConfig.detectEmails!, statKey: "emails" },
    { type: "phone", enabled: mergedConfig.detectPhones!, statKey: "phones" },
    { type: "creditCard", enabled: mergedConfig.detectCreditCards!, statKey: "creditCards" },
    { type: "ssn", enabled: mergedConfig.detectSSNs!, statKey: "ssns" },
    { type: "iban", enabled: mergedConfig.detectIBANs!, statKey: "ibans" },
    { type: "ipAddress", enabled: mergedConfig.detectIPAddresses!, statKey: "ipAddresses" },
  ];

  // Detect all PII types
  for (const { type, enabled, statKey } of detectionMap) {
    if (enabled) {
      const matches = detectPIIType(text, type);
      allMatches.push(...matches);
    }
  }

  // Filter overlapping matches - keep higher severity and longer matches
  const severityOrder: Record<Severity, number> = {
    critical: 4,
    high: 3,
    medium: 2,
    low: 1,
  };

  const filteredMatches = allMatches.filter((match, index) => {
    // Check if this match overlaps with any other match
    for (let i = 0; i < allMatches.length; i++) {
      if (i === index) continue;
      const other = allMatches[i];
      
      // Check for overlap
      const overlaps = match.start < other.end && match.end > other.start;
      
      if (overlaps) {
        // Keep the one with higher severity, or longer match, or earlier in list
        const matchScore = severityOrder[match.severity] * 1000 + (match.end - match.start);
        const otherScore = severityOrder[other.severity] * 1000 + (other.end - other.start);
        
        if (otherScore > matchScore) return false;
        if (otherScore === matchScore && i < index) return false;
      }
    }
    return true;
  });

  // Update stats with filtered matches
  for (const match of filteredMatches) {
    const statKey = detectionMap.find(d => d.type === match.type)?.statKey;
    if (statKey) {
      stats[statKey]++;
      stats.total++;
    }
  }

  // Sort matches by position (descending) to replace from end to start
  // This preserves correct positions during replacement
  const sortedMatches = [...filteredMatches].sort((a, b) => b.start - a.start);

  // Perform redaction
  for (const match of sortedMatches) {
    redactedText =
      redactedText.slice(0, match.start) +
      tokens[match.type] +
      redactedText.slice(match.end);
  }

  return {
    originalText: text,
    redactedText,
    matches: filteredMatches.sort((a, b) => a.start - b.start),
    stats,
  };
}

/**
 * Quick redaction function that only returns the redacted text.
 * Use this when you don't need match metadata or statistics.
 * 
 * @param text - Input text to redact
 * @param config - Optional configuration
 * @returns Redacted text string
 * 
 * @example
 * ```typescript
 * const clean = redact("Call me at +1-555-123-4567");
 * // Returns: "Call me at [PHONE_REDACTED]"
 * ```
 */
export function redact(text: string, config: FilterConfig = {}): string {
  return detectAndRedact(text, config).redactedText;
}

/**
 * Checks if the text contains any PII without performing redaction.
 * Useful for validation gates before processing.
 * 
 * @param text - Input text to check
 * @param config - Optional configuration
 * @returns true if PII is detected, false otherwise
 * 
 * @example
 * ```typescript
 * if (containsPII(userMessage)) {
 *   throw new Error("Please remove personal information");
 * }
 * ```
 */
export function containsPII(text: string, config: FilterConfig = {}): boolean {
  const result = detectAndRedact(text, config);
  return result.stats.total > 0;
}

/**
 * Detects PII and returns only the matches without redaction.
 * Useful for analysis and auditing.
 * 
 * @param text - Input text to analyze
 * @param config - Optional configuration
 * @returns Array of detected PII matches
 */
export function detectPII(text: string, config: FilterConfig = {}): PIIMatch[] {
  return detectAndRedact(text, config).matches;
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════════

export {
  PII_PATTERNS,
  DEFAULT_REDACTION_TOKENS,
  DEFAULT_CONFIG,
};

