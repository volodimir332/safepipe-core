# SafePipe Core: Zero-Knowledge PII Redaction Engine

<p align="center">
  <img src="https://safepipe.eu/logo.svg" alt="SafePipe Logo" width="120" />
</p>

<p align="center">
  <strong>Deterministic, In-Memory PII Detection & Redaction</strong><br>
  <em>The open-source core of SafePipe.eu — Privacy by Design for LLM Applications</em>
</p>

<p align="center">
  <a href="https://safepipe.eu">Website</a> •
  <a href="https://safepipe.eu/docs">Documentation</a> •
  <a href="https://safepipe.eu/security">Security</a>
</p>

---

## 🛡️ What is This?

This is the **core logic** used by [SafePipe.eu](https://safepipe.eu) to sanitize data in-memory before it reaches LLM providers. We open-source this module to prove our **deterministic, zero-persistence architecture**.

**Key Guarantees:**
- ✅ **Zero Network Calls** — All processing happens locally
- ✅ **Zero Persistence** — No data is stored, logged, or cached
- ✅ **Zero Dependencies** — Pure TypeScript with no external packages
- ✅ **Deterministic Output** — Same input always produces same output

---

## 📋 Supported PII Types

| Type | Examples | Severity |
|------|----------|----------|
| **Email** | `user@domain.com`, `name+tag@sub.domain.co.uk` | High |
| **Phone** | `+1-555-123-4567`, `(555) 123-4567`, `00491234567890` | High |
| **Credit Card** | `4111-1111-1111-1111`, `4111111111111111` | Critical |
| **SSN** | `123-45-6789`, `123456789` | Critical |
| **IBAN** | `DE89370400440532013000`, `GB82 WEST 1234 5698` | High |
| **IP Address** | `192.168.1.1`, `10.0.0.1` | Medium |

---

## 🚀 Quick Start

### Installation

```bash
# Copy the source file to your project
cp src/pii-filter.ts your-project/lib/

# Or use as a module
npm install safepipe-core  # Coming soon
```

### Basic Usage

```typescript
import { redact, detectAndRedact, containsPII } from './pii-filter';

// Simple redaction
const clean = redact("Contact me at john@example.com or +1-555-123-4567");
// Output: "Contact me at [EMAIL_REDACTED] or [PHONE_REDACTED]"

// Full detection with metadata
const result = detectAndRedact("My SSN is 123-45-6789");
console.log(result.redactedText);  // "My SSN is [SSN_REDACTED]"
console.log(result.stats);         // { total: 1, ssns: 1, ... }
console.log(result.matches);       // [{ type: 'ssn', value: '123-45-6789', ... }]

// Validation check
if (containsPII(userInput)) {
  throw new Error("Please remove personal information before submitting");
}
```

### Custom Configuration

```typescript
import { detectAndRedact } from './pii-filter';

const result = detectAndRedact(text, {
  // Toggle specific detectors
  detectEmails: true,
  detectPhones: true,
  detectCreditCards: true,
  detectSSNs: true,
  detectIBANs: true,
  detectIPAddresses: false, // Disable IP detection

  // Custom redaction tokens
  redactionTokens: {
    email: "[HIDDEN_EMAIL]",
    phone: "***-***-****",
    ssn: "XXX-XX-XXXX",
  },
});
```

---

## 🔬 API Reference

### `detectAndRedact(text, config?)`

Main function for PII detection and redaction.

**Parameters:**
- `text: string` — Input text to process
- `config?: FilterConfig` — Optional configuration object

**Returns:** `DetectionResult`
```typescript
interface DetectionResult {
  originalText: string;     // Original input
  redactedText: string;     // Text with PII replaced
  matches: PIIMatch[];      // Array of detected matches
  stats: {                  // Summary statistics
    total: number;
    emails: number;
    phones: number;
    creditCards: number;
    ssns: number;
    ibans: number;
    ipAddresses: number;
  };
}
```

### `redact(text, config?)`

Quick redaction that returns only the cleaned text.

```typescript
const clean = redact("Email: test@example.com");
// Returns: "Email: [EMAIL_REDACTED]"
```

### `containsPII(text, config?)`

Boolean check for PII presence.

```typescript
if (containsPII(message)) {
  // Handle sensitive data
}
```

### `detectPII(text, config?)`

Returns only the match array without redaction.

```typescript
const matches = detectPII(sensitiveDocument);
// Returns: PIIMatch[]
```

---

## 🏗️ Architecture

> *Follow exactly what happens to your prompt from the moment it arrives until it's permanently deleted.*

```
  DATA CONTROLLER                                                    SUB-PROCESSOR
        │                                                                  │
        ▼                                                                  ▼
┌──────────────┐      ┌──────────────┐      ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│              │      │              │      │   ┌────────┐ │      │              │      │              │
│   Your App   │ ───▶ │ Input Shield │ ───▶ │   │ OpenAI │ │ ───▶ │ Output Guard │ ───▶ │  Clean Data  │
│              │      │              │      │   │ GPT-4o │ │      │              │      │              │
│   Request    │      │ PII Redaction│      │   ├────────┤ │      │ Brand Safety │      │  To Your App │
│              │      │              │      │   │Anthropic│ │      │              │      │              │
│      >_      │      │      🛡️      │      │   │ Claude │ │      │      🛡️      │      │      ✓       │
│              │      │              │      │   ├────────┤ │      │              │      │              │
└──────────────┘      └──────────────┘      │   │ Google │ │      └──────────────┘      └──────────────┘
                                            │   │ Gemini │ │
                                            │   └────────┘ │
                                            └──────────────┘

                              ┌─────────────────────────────────────────────────────┐
                              │  🗑️  Auto-Deleted from RAM                          │
                              │                                                     │
                              │  Original data wiped after ~30ms. Zero disk writes. │
                              └─────────────────────────────────────────────────────┘
```

### Data Flow

| Step | Component | What Happens |
|------|-----------|--------------|
| 1️⃣ | **Your App** | Sends raw request with potentially sensitive data |
| 2️⃣ | **Input Shield** | PII detected & redacted in-memory (this module) |
| 3️⃣ | **LLM Provider** | Receives only sanitized prompts |
| 4️⃣ | **Output Guard** | Filters brand/competitor mentions |
| 5️⃣ | **Clean Data** | Safe response returned to your app |
| 🗑️ | **RAM Wipe** | Original data deleted after ~30ms |

---

## ⚠️ Important Disclaimer

> **This is the logic layer only.**
> 
> The managed infrastructure that provides enterprise features including:
> - 🔐 **Cryptographic Vault** for reversible redaction
> - 🧭 **Smart Router** for multi-provider failover  
> - 📊 **Analytics Dashboard** with audit logs
> - 🏢 **Team Management** with RBAC
> - 🔌 **Drop-in API Compatibility** with OpenAI SDK
> 
> ...is hosted on our secure, SOC2-compliant cloud at [SafePipe.eu](https://safepipe.eu)

---

## 🔒 Security Considerations

### Pattern Design Philosophy

Our regex patterns are designed with a **security-first mindset**:

1. **False Positives > False Negatives**  
   We prefer to over-redact rather than leak sensitive data.

2. **International Support**  
   Phone and IBAN patterns support EU, US, and international formats.

3. **Separator Agnostic**  
   Patterns match regardless of spacing, dashes, or dots.

### Known Limitations

- **No NER/ML:** This is pure regex — no Named Entity Recognition
- **Context-Blind:** Cannot distinguish "John Smith" as a name
- **SSN Overlap:** 9-digit numbers may trigger false positives
- **No Validation:** Credit card numbers aren't Luhn-checked

For advanced detection (names, addresses, context-aware PII), use the full SafePipe API.

---

## 🧪 Testing

Run the included example:

```bash
npx ts-node tests/example.ts
```

Expected output:
```
Input:  Contact me at ivan@test.com or call +380501234567
Output: Contact me at [EMAIL_REDACTED] or call [PHONE_REDACTED]

Stats: { total: 2, emails: 1, phones: 1, ... }
```

---

## 📄 License

MIT License — Free for commercial and personal use.

See [LICENSE](./LICENSE) for details.

---

## 🤝 Contributing

We welcome security researchers to:

1. **Report vulnerabilities** — security@safepipe.eu
2. **Suggest pattern improvements** — Open an issue
3. **Submit test cases** — Edge cases help everyone

---

## 📞 Contact

- **Website:** [safepipe.eu](https://safepipe.eu)
- **Security:** security@safepipe.eu
- **Support:** support@safepipe.eu

---

<p align="center">
  <sub>Built with 🛡️ by the SafePipe Security Team</sub>
</p>

