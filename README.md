# simple-url-sanitizer

[![npm version](https://badge.fury.io/js/simple-url-sanitizer.svg)](https://badge.fury.io/js/simple-url-sanitizer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A URL sanitization library designed for secure sharing functions. Implements a hybrid approach combining external libraries with custom parameter filtering, following OWASP recommendations for XSS prevention.

## ⚠️ Security Disclaimer

**IMPORTANT: This library provides security measures but cannot guarantee complete protection against all possible attack vectors. URL sanitization is a complex security problem, and no solution is 100% foolproof.**

- This library could be used as part of a comprehensive security strategy
- Always implement additional security measures (CSP, input validation, output encoding, etc.)
- Regularly update dependencies and monitor for security vulnerabilities
- Test thoroughly in your specific use case
- Consider consulting security experts for high-risk applications

**Use at your own risk. The authors and contributors are not responsible for any security incidents, data breaches, or damages resulting from the use of this library.**

## Features

- **Hybrid Security Approach**: Combines `@braintree/sanitize-url` for protocol-level protection with custom parameter filtering
- **OWASP-Inspired Parameter Filtering**: Allowlist/blocklist approach for URL parameters
- **XSS Prevention**: Detects and filters suspicious patterns in parameter values
- **TypeScript Support**: Full TypeScript definitions and type safety
- **Comprehensive Testing**: Test suite covering various attack vectors
- **Configurable**: Customizable safe/blocked parameters and filtering options

## Installation

```bash
npm install simple-url-sanitizer
```

## Quick Start

```typescript
import { sanitizeUrlForSharing, isUrlSafeForSharing } from 'simple-url-sanitizer';

// Basic usage
const safeUrl = sanitizeUrlForSharing('https://example.com?utm_source=email&utm_medium=social');
console.log(safeUrl); // 'https://example.com?utm_source=email&utm_medium=social'

// Check if URL is safe
const isSafe = isUrlSafeForSharing('https://example.com?onload=alert("xss")');
console.log(isSafe); // false

// Filter dangerous parameters
const filteredUrl = sanitizeUrlForSharing('https://example.com?safe=value&onload=alert("xss")&onclick=evil()');
console.log(filteredUrl); // 'https://example.com?safe=value'
```

## API Reference

### `sanitizeUrlForSharing(url, options?)`

Sanitizes a URL for secure sharing by filtering dangerous parameters and protocols.

**Parameters:**
- `url` (string): The URL to sanitize
- `options` (SanitizeUrlOptions, optional): Configuration options

**Returns:** `string | null` - The sanitized URL, or `null` if the URL is invalid/dangerous

**Options:**
```typescript
interface SanitizeUrlOptions {
  allowSafeOnly?: boolean;        // Allow only predefined safe parameters (default: true)
  additionalSafeParams?: string[]; // Additional parameters to allow
  additionalBlockedParams?: string[]; // Additional parameters to block
  preserveStructure?: boolean;    // Preserve URL structure (default: true)
}
```

### `isUrlSafeForSharing(url, options?)`

Validates if a URL is safe for sharing.

**Parameters:**
- `url` (string): The URL to validate
- `options` (SanitizeUrlOptions, optional): Configuration options

**Returns:** `boolean` - `true` if the URL is safe

### `extractSafeParameters(url, options?)`

Extracts safe parameters from a URL as an object.

**Parameters:**
- `url` (string): The URL to extract parameters from
- `options` (SanitizeUrlOptions, optional): Configuration options

**Returns:** `Record<string, string>` - Object containing safe parameters

### Parameter Sets

#### Safe Parameters (`SAFE_URL_PARAMETERS`)
Commonly used parameters considered safe:
- Analytics: `utm_source`, `utm_medium`, `utm_campaign`, etc.
- Social: `ref`, `referrer`, `share`, `via`
- Content: `id`, `page`, `section`, `tab`, `view`
- Search: `q`, `query`, `search`, `filter`, `sort`
- RSS: `feed`, `rss`, `atom`, `xml`

#### Dangerous Parameters (`DANGEROUS_URL_PARAMETERS`)
Parameters that should be filtered out:
- JavaScript events: `onload`, `onclick`, `onerror`, etc.
- XSS vectors: `javascript`, `vbscript`, `data`, `script`
- Injection: `sql`, `union`, `select`, `exec`, etc.

## Advanced Usage

### Custom Parameter Configuration

```typescript
import { sanitizeUrlForSharing } from 'simple-url-sanitizer';

const options = {
  allowSafeOnly: false,  // Allow all parameters except blocked ones
  additionalSafeParams: ['custom_param'],
  additionalBlockedParams: ['evil_param']
};

const safeUrl = sanitizeUrlForSharing('https://example.com?custom_param=value&evil_param=bad', options);
```

### RSS Feed Sanitization

```typescript
// Perfect for RSS feed URLs
const rssUrls = [
  'https://example.com/feed.xml?feed=rss&format=xml',
  'https://example.com/rss?category=tech&limit=10'
];

rssUrls.forEach(url => {
  const safeUrl = sanitizeUrlForSharing(url);
  console.log('Safe RSS URL:', safeUrl);
});
```

### Extract Parameters for Analysis

```typescript
import { extractSafeParameters } from 'simple-url-sanitizer';

const url = 'https://example.com?utm_source=email&utm_medium=social&onload=alert("xss")';
const params = extractSafeParameters(url);
console.log(params); // { utm_source: 'email', utm_medium: 'social' }
```

## Security Considerations

### What This Library Does
- ✅ Filters dangerous protocols (`javascript:`, `data:`, `vbscript:`)
- ✅ Removes XSS-prone parameters (`onload`, `onclick`, etc.)
- ✅ Detects suspicious patterns in parameter values
- ✅ Uses allowlist/blocklist approach for parameters
- ✅ Follows OWASP recommendations

### What This Library Does NOT Do
- ❌ Guarantee 100% security (no solution can)
- ❌ Replace proper input validation
- ❌ Prevent all possible attack vectors
- ❌ Handle server-side security
- ❌ Replace Content Security Policy (CSP)

### Additional Security Measures
1. **Implement CSP**: Content Security Policy headers
2. **Input Validation**: Validate all inputs on server-side
3. **Output Encoding**: Encode output to prevent XSS
4. **HTTPS Only**: Use HTTPS for all communications
5. **Regular Updates**: Keep dependencies updated
6. **Security Audits**: Regular security reviews

## Testing

```bash
# Run tests
npm test

# Run tests in watch mode
npm run test:watch

# Build the library
npm run build
```

## Development

```bash
# Install dependencies
npm install

# Run linting
npm run lint

# Clean build artifacts
npm run clean

# Build for production
npm run build
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- Issues: [GitHub Issues](https://github.com/fathomly/fathomly-url-sanitizer/issues)
- Documentation: [GitHub Wiki](https://github.com/fathomly/fathomly-url-sanitizer/wiki)

---

**Remember: Security is a continuous process. Stay vigilant, keep updated, and implement defense in depth.**