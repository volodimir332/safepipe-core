/**
 * SafePipe Core — Example Usage
 * 
 * This script demonstrates the PII detection and redaction capabilities.
 * Run with: npx ts-node tests/example.ts
 */

import {
  detectAndRedact,
  redact,
  containsPII,
  detectPII,
} from "../src/pii-filter";

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════════

function printDivider(title: string): void {
  console.log("\n" + "═".repeat(70));
  console.log(`  ${title}`);
  console.log("═".repeat(70) + "\n");
}

function printExample(input: string, output: string): void {
  console.log(`  Input:  "${input}"`);
  console.log(`  Output: "${output}"`);
  console.log();
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE 1: Basic Email Redaction
// ═══════════════════════════════════════════════════════════════════════════════

printDivider("Example 1: Basic Email Redaction");

const input1 = "Contact me at ivan@test.com";
const output1 = redact(input1);

printExample(input1, output1);
// Expected: "Contact me at [EMAIL_REDACTED]"

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE 2: Multiple PII Types
// ═══════════════════════════════════════════════════════════════════════════════

printDivider("Example 2: Multiple PII Types in One String");

const input2 = `
Customer Info:
- Email: john.doe@company.com
- Phone: +1-555-123-4567
- SSN: 123-45-6789
- Card: 4111-1111-1111-1111
- IBAN: DE89370400440532013000
`;

const result2 = detectAndRedact(input2);

console.log("  Redacted Text:");
console.log(result2.redactedText);
console.log("\n  Statistics:", result2.stats);
console.log("\n  Detected Matches:");
result2.matches.forEach((match, i) => {
  console.log(`    ${i + 1}. [${match.type.toUpperCase()}] "${match.value}" (severity: ${match.severity})`);
});

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE 3: PII Validation Check
// ═══════════════════════════════════════════════════════════════════════════════

printDivider("Example 3: PII Validation Check");

const safeMessage = "Hello, how can I help you today?";
const unsafeMessage = "My email is test@example.com";

console.log(`  Safe message contains PII:   ${containsPII(safeMessage)}`);    // false
console.log(`  Unsafe message contains PII: ${containsPII(unsafeMessage)}`);  // true

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE 4: Custom Redaction Tokens
// ═══════════════════════════════════════════════════════════════════════════════

printDivider("Example 4: Custom Redaction Tokens");

const input4 = "Call me at +49 30 1234567";
const output4 = redact(input4, {
  redactionTokens: {
    phone: "***-HIDDEN-***",
  },
});

printExample(input4, output4);
// Expected: "Call me at ***-HIDDEN-***"

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE 5: Selective Detection
// ═══════════════════════════════════════════════════════════════════════════════

printDivider("Example 5: Selective Detection (Only Emails)");

const input5 = "Email: test@example.com, Phone: 555-123-4567";
const output5 = redact(input5, {
  detectEmails: true,
  detectPhones: false,  // Disabled
});

printExample(input5, output5);
// Expected: "Email: [EMAIL_REDACTED], Phone: 555-123-4567"

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE 6: International Phone Formats
// ═══════════════════════════════════════════════════════════════════════════════

printDivider("Example 6: International Phone Number Formats");

const phoneExamples = [
  "+1 234 567 8901",       // US with country code
  "(555) 123-4567",        // US local
  "+49 30 12345678",       // German
  "00380501234567",        // Ukrainian with 00 prefix
  "+44 20 7946 0958",      // UK
];

phoneExamples.forEach((phone) => {
  const cleaned = redact(`Phone: ${phone}`);
  console.log(`  "${phone}" → "${cleaned}"`);
});

// ═══════════════════════════════════════════════════════════════════════════════
// EXAMPLE 7: Detection Only (No Redaction)
// ═══════════════════════════════════════════════════════════════════════════════

printDivider("Example 7: Detection Only (For Auditing)");

const input7 = "User IP: 192.168.1.100, Email: admin@internal.local";
const matches = detectPII(input7);

console.log("  Detected PII (without redaction):");
matches.forEach((match) => {
  console.log(`    - Type: ${match.type}, Value: "${match.value}", Position: ${match.start}-${match.end}`);
});

// ═══════════════════════════════════════════════════════════════════════════════
// FINAL SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════

printDivider("✅ All Examples Completed Successfully");

console.log(`
  SafePipe Core provides:
  
  • detectAndRedact() — Full detection with metadata
  • redact()          — Quick text cleaning
  • containsPII()     — Boolean validation check
  • detectPII()       — Detection without redaction

  For enterprise features (Vault, Smart Router, Analytics),
  visit: https://safepipe.eu
`);

