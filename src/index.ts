/**
 * @package simple-url-sanitizer
 * @version 0.0.1
 * @license MIT
 *
 * Comprehensive URL sanitization library for secure sharing functions.
 * Implements hybrid approach combining external libraries with custom parameter filtering.
 *
 * WARNING: This library provides security measures but cannot guarantee complete protection
 * against all possible attack vectors. Use at your own risk and implement additional
 * security measures as needed.
 */

import { sanitizeUrl } from '@braintree/sanitize-url';

// For CommonJS compatibility, we can also use:
// const { sanitizeUrl } = require('@braintree/sanitize-url');

/**
 * Safe URL parameters that are commonly used and considered secure.
 * Based on OWASP recommendations and common web standards.
 */
export const SAFE_URL_PARAMETERS = new Set([
  // Common tracking and analytics
  'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
  'gclid', 'fbclid', 'msclkid', 'yclid', 'twclid',

  // Social media parameters
  'ref', 'referrer', 'share', 'via',

  // Content parameters
  'id', 'page', 'section', 'tab', 'view',

  // Search and filtering
  'q', 'query', 'search', 'filter', 'sort', 'order',

  // Pagination
  'page', 'limit', 'offset', 'per_page',

  // Language and localization
  'lang', 'locale', 'hl',

  // Time-based parameters
  'date', 'time', 'timestamp', 'from', 'to',

  // RSS-specific parameters
  'feed', 'rss', 'atom', 'xml',

  // Common application parameters
  'action', 'type', 'format', 'version'
]);

/**
 * Dangerous URL parameters that should be filtered out.
 * Based on OWASP XSS prevention guidelines and common attack vectors.
 */
export const DANGEROUS_URL_PARAMETERS = new Set([
  // JavaScript event handlers
  'onabort', 'onblur', 'onchange', 'onclick', 'ondblclick', 'onerror',
  'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onload', 'onmousedown',
  'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onreset',
  'onresize', 'onselect', 'onsubmit', 'onunload',

  // JavaScript execution vectors
  'javascript', 'vbscript', 'data', 'blob',

  // XSS vectors
  'alert', 'confirm', 'prompt', 'eval', 'expression', 'function',
  'script', 'iframe', 'object', 'embed', 'form', 'input', 'button',
  'link', 'meta', 'style', 'img', 'src', 'href', 'action',

  // Injection vectors
  'sql', 'union', 'select', 'insert', 'update', 'delete', 'drop',
  'exec', 'execute', 'script', 'cmd', 'command', 'shell',

  // Protocol handlers that can be dangerous
  'file', 'ftp', 'ldap', 'ldaps', 'news', 'telnet',

  // Potentially dangerous attributes
  'innerHTML', 'outerHTML', 'innerText', 'textContent', 'value',
  'srcdoc', 'formaction', 'formenctype', 'formmethod', 'formtarget'
]);

/**
 * Options for URL sanitization
 */
export interface SanitizeUrlOptions {
  /** Allow only safe parameters (default: true) */
  allowSafeOnly?: boolean;
  /** Additional safe parameters to allow */
  additionalSafeParams?: string[];
  /** Parameters to block in addition to dangerous ones */
  additionalBlockedParams?: string[];
  /** Whether to preserve the original URL structure (default: true) */
  preserveStructure?: boolean;
}

/**
 * Default sanitization options
 */
const DEFAULT_OPTIONS: Required<SanitizeUrlOptions> = {
  allowSafeOnly: true,
  additionalSafeParams: [],
  additionalBlockedParams: [],
  preserveStructure: true
};

/**
 * Sanitizes a URL for secure sharing by filtering dangerous parameters and protocols.
 *
 * This function implements a hybrid approach:
 * 1. Uses @braintree/sanitize-url for protocol-level protection
 * 2. Applies custom parameter filtering based on allowlist/blocklist approach
 * 3. Follows OWASP recommendations for XSS prevention
 *
 * @param url - The URL to sanitize
 * @param options - Sanitization options
 * @returns The sanitized URL or null if the URL is invalid/dangerous
 */
export function sanitizeUrlForSharing(
  url: string,
  options: SanitizeUrlOptions = {}
): string | null {
  // Validate input
  if (!url || typeof url !== 'string') {
    return null;
  }

  // Merge options with defaults
  const opts: Required<SanitizeUrlOptions> = { ...DEFAULT_OPTIONS, ...options };

  // Build complete safe and blocked parameter sets
  const safeParams = new Set([
    ...SAFE_URL_PARAMETERS,
    ...opts.additionalSafeParams
  ]);

  const blockedParams = new Set([
    ...DANGEROUS_URL_PARAMETERS,
    ...opts.additionalBlockedParams
  ]);

  try {
    // First, use @braintree/sanitize-url for protocol-level protection
    const protocolSanitized = sanitizeUrl(url);

    // If the URL was completely sanitized (made safe), return null for dangerous protocols
    if (protocolSanitized === 'about:blank') {
      return null;
    }

    // Parse the URL to work with parameters
    const urlObj = new URL(protocolSanitized);

    // Check for dangerous hostnames (localhost, private IPs)
    if (isDangerousHostname(urlObj.hostname)) {
      return null;
    }

    // Filter query parameters
    const filteredParams = new URLSearchParams();

    for (const [key, value] of urlObj.searchParams) {
      const lowerKey = key.toLowerCase();

      // Check if parameter should be blocked
      if (blockedParams.has(lowerKey)) {
        continue;
      }

      // If allowSafeOnly is true, only allow safe parameters
      if (opts.allowSafeOnly && !safeParams.has(lowerKey)) {
        continue;
      }

      // Additional validation: check for suspicious patterns in values
      if (isSuspiciousValue(value)) {
        continue;
      }

      filteredParams.append(key, value);
    }

    // Reconstruct URL with filtered parameters
    urlObj.search = filteredParams.toString();

    return urlObj.toString();
  } catch (error) {
    // If URL parsing fails, return null
    return null;
  }
}

/**
 * Checks if a hostname represents a dangerous IP address or localhost
 * 
 * @param hostname - The hostname to check
 * @returns true if the hostname is dangerous
 */
function isDangerousHostname(hostname: string): boolean {
  if (!hostname) return false;

  const lowerHostname = hostname.toLowerCase();

  // Block localhost and IPv6 localhost
  if (lowerHostname === 'localhost' || 
      lowerHostname === '127.0.0.1' || 
      lowerHostname === '::1' || 
      lowerHostname === '[::1]') {
    return true;
  }

  // Block private IP ranges
  const privateIpPatterns = [
    /^10\./,                    // 10.0.0.0/8
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,  // 172.16.0.0/12
    /^192\.168\./,              // 192.168.0.0/16
    /^169\.254\./,              // Link-local addresses
    /^fc00:/,                   // IPv6 private addresses (fc00::/7)
    /^fe80:/,                   // IPv6 link-local (fe80::/10)
  ];

  return privateIpPatterns.some(pattern => pattern.test(lowerHostname));
}

/**
 * Checks if a parameter value contains suspicious patterns that could indicate XSS attempts.
 *
 * @param value - The parameter value to check
 * @returns true if the value appears suspicious
 */
function isSuspiciousValue(value: string): boolean {
  if (!value) return false;

  const lowerValue = value.toLowerCase();

  // Check for common XSS patterns
  const suspiciousPatterns = [
    /<script/i,
    /javascript:/i,
    /vbscript:/i,
    /data:/i,
    /on\w+\s*=/i,
    /<iframe/i,
    /<object/i,
    /<embed/i,
    /expression\s*\(/i,
    /vbscript\s*:/i,
    /alert\s*\(/i,
    /confirm\s*\(/i,
    /prompt\s*\(/i,
    /eval\s*\(/i
  ];

  return suspiciousPatterns.some(pattern => pattern.test(lowerValue));
}

/**
 * Validates if a URL is safe for sharing.
 *
 * @param url - The URL to validate
 * @param options - Validation options
 * @returns true if the URL is safe
 */
export function isUrlSafeForSharing(
  url: string,
  options: SanitizeUrlOptions = {}
): boolean {
  const sanitized = sanitizeUrlForSharing(url, options);
  if (sanitized === null) {
    return false;
  }

  // Check if the sanitized URL is a normalized version of the original
  // This handles cases where @braintree/sanitize-url normalizes the URL (e.g., adding trailing slashes)
  try {
    const originalUrl = new URL(url);

    // Check for dangerous hostnames first
    if (isDangerousHostname(originalUrl.hostname)) {
      return false;
    }

    const sanitizedUrl = new URL(sanitized);

    // Compare key components that matter for safety
    return originalUrl.protocol === sanitizedUrl.protocol &&
           originalUrl.hostname === sanitizedUrl.hostname &&
           originalUrl.pathname === sanitizedUrl.pathname &&
           originalUrl.search === sanitizedUrl.search &&
           originalUrl.hash === sanitizedUrl.hash;
  } catch (error) {
    // If URL parsing fails, fall back to exact match
    return sanitized === url;
  }
}

/**
 * Extracts safe parameters from a URL.
 *
 * @param url - The URL to extract parameters from
 * @param options - Extraction options
 * @returns Object containing safe parameters
 */
export function extractSafeParameters(
  url: string,
  options: SanitizeUrlOptions = {}
): Record<string, string> {
  const opts: Required<SanitizeUrlOptions> = { ...DEFAULT_OPTIONS, ...options };

  const safeParams = new Set([
    ...SAFE_URL_PARAMETERS,
    ...opts.additionalSafeParams
  ]);

  const blockedParams = new Set([
    ...DANGEROUS_URL_PARAMETERS,
    ...opts.additionalBlockedParams
  ]);

  const result: Record<string, string> = {};

  try {
    const urlObj = new URL(url);

    // Check for dangerous hostnames
    if (isDangerousHostname(urlObj.hostname)) {
      return {};
    }

    for (const [key, value] of urlObj.searchParams) {
      const lowerKey = key.toLowerCase();

      if (!blockedParams.has(lowerKey) &&
          (!opts.allowSafeOnly || safeParams.has(lowerKey)) &&
          !isSuspiciousValue(value)) {
        result[key] = value;
      }
    }
  } catch (error) {
    // If URL parsing fails, return empty object
  }

  return result;
}