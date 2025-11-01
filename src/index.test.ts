/**
 * @package fathomly-url-sanitizer
 * Test suite for URL sanitization functionality
 */

import { describe, it, expect } from 'vitest';
import {
  sanitizeUrlForSharing,
  isUrlSafeForSharing,
  extractSafeParameters,
  SAFE_URL_PARAMETERS,
  DANGEROUS_URL_PARAMETERS,
  isValidUrl,
  sanitizeUrl
} from './index';

describe('URL Sanitization Library', () => {
  describe('sanitizeUrlForSharing', () => {
    it('should return null for invalid URLs', () => {
      expect(sanitizeUrlForSharing('')).toBeNull();
      expect(sanitizeUrlForSharing(null as any)).toBeNull();
      expect(sanitizeUrlForSharing(undefined as any)).toBeNull();
      expect(sanitizeUrlForSharing('not-a-url')).toBeNull();
    });

    it('should block localhost URLs', () => {
      expect(sanitizeUrlForSharing('http://localhost')).toBeNull();
      expect(sanitizeUrlForSharing('http://127.0.0.1')).toBeNull();
      expect(sanitizeUrlForSharing('http://[::1]')).toBeNull();
    });

    it('should block private IP addresses', () => {
      expect(sanitizeUrlForSharing('http://10.0.0.1')).toBeNull();
      expect(sanitizeUrlForSharing('http://172.16.0.1')).toBeNull();
      expect(sanitizeUrlForSharing('http://192.168.1.1')).toBeNull();
    });

    it('should allow safe URLs without parameters', () => {
      const safeUrl = 'https://example.com';
      const result = sanitizeUrlForSharing(safeUrl);
      expect(result).toBe('https://example.com/'); // @braintree/sanitize-url adds trailing slash
    });

    it('should filter dangerous parameters', () => {
      const dangerousUrl = 'https://example.com?onload=alert("xss")&utm_source=test';
      const result = sanitizeUrlForSharing(dangerousUrl);
      expect(result).toBe('https://example.com/?utm_source=test'); // @braintree/sanitize-url normalizes
    });

    it('should allow safe parameters', () => {
      const safeUrl = 'https://example.com?utm_source=test&utm_medium=email';
      const result = sanitizeUrlForSharing(safeUrl);
      expect(result).toBe('https://example.com/?utm_source=test&utm_medium=email'); // @braintree/sanitize-url normalizes
    });

    it('should filter parameters with suspicious values', () => {
      const suspiciousUrl = 'https://example.com?param=<script>alert("xss")</script>&utm_source=test';
      const result = sanitizeUrlForSharing(suspiciousUrl);
      expect(result).toBe('https://example.com/?utm_source=test'); // @braintree/sanitize-url normalizes
    });

    it('should handle custom options', () => {
      const url = 'https://example.com?custom=value&onload=alert("xss")';
      const result = sanitizeUrlForSharing(url, {
        additionalSafeParams: ['custom'],
        allowSafeOnly: true
      });
      expect(result).toBe('https://example.com/?custom=value'); // @braintree/sanitize-url normalizes
    });

    it('should block additional dangerous parameters', () => {
      const url = 'https://example.com?utm_source=test&blocked=value';
      const result = sanitizeUrlForSharing(url, {
        additionalBlockedParams: ['blocked']
      });
      expect(result).toBe('https://example.com/?utm_source=test'); // @braintree/sanitize-url normalizes
    });

    it('should handle RSS-specific parameters', () => {
      const rssUrl = 'https://example.com/feed.xml?feed=rss&format=xml';
      expect(sanitizeUrlForSharing(rssUrl)).toBe(rssUrl);
    });
  });

  describe('isUrlSafeForSharing', () => {
    it('should return true for safe URLs', () => {
      expect(isUrlSafeForSharing('https://example.com')).toBe(true);
      expect(isUrlSafeForSharing('https://example.com/?utm_source=test')).toBe(true); // normalized
    });

    it('should return false for dangerous URLs', () => {
      expect(isUrlSafeForSharing('javascript:alert("xss")')).toBe(false);
      expect(isUrlSafeForSharing('https://example.com?onload=alert("xss")')).toBe(false);
    });
  });

  describe('extractSafeParameters', () => {
    it('should extract safe parameters', () => {
      const url = 'https://example.com?utm_source=test&onload=alert("xss")&utm_medium=email';
      const result = extractSafeParameters(url);
      expect(result).toEqual({
        utm_source: 'test',
        utm_medium: 'email'
      });
    });

    it('should handle custom options', () => {
      const url = 'https://example.com?custom=value&blocked=value';
      const result = extractSafeParameters(url, {
        additionalSafeParams: ['custom'],
        additionalBlockedParams: ['blocked']
      });
      expect(result).toEqual({
        custom: 'value'
      });
    });
  });

  describe('Parameter Sets', () => {
    it('should contain expected safe parameters', () => {
      expect(SAFE_URL_PARAMETERS.has('utm_source')).toBe(true);
      expect(SAFE_URL_PARAMETERS.has('q')).toBe(true);
      expect(SAFE_URL_PARAMETERS.has('lang')).toBe(true);
    });

    it('should contain expected dangerous parameters', () => {
      expect(DANGEROUS_URL_PARAMETERS.has('onload')).toBe(true);
      expect(DANGEROUS_URL_PARAMETERS.has('javascript')).toBe(true);
      expect(DANGEROUS_URL_PARAMETERS.has('alert')).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle URLs with fragments', () => {
      const url = 'https://example.com#section';
      const result = sanitizeUrlForSharing(url);
      expect(result).toBe('https://example.com/#section'); // @braintree/sanitize-url normalizes
    });

    it('should handle URLs with special characters', () => {
      const url = 'https://example.com?q=test%20query';
      const result = sanitizeUrlForSharing(url);
      expect(result).toBe('https://example.com/?q=test+query'); // @braintree/sanitize-url normalizes %20 to +
    });

    it('should handle empty query strings', () => {
      const url = 'https://example.com?';
      const result = sanitizeUrlForSharing(url);
      expect(result).toBe('https://example.com/'); // @braintree/sanitize-url normalizes
    });

    it('should handle multiple dangerous parameters', () => {
      const url = 'https://example.com?onload=1&onclick=2&javascript=3&utm_source=test';
      const result = sanitizeUrlForSharing(url);
      expect(result).toBe('https://example.com/?utm_source=test'); // @braintree/sanitize-url normalizes
    });
  });

  describe('XSS Prevention', () => {
    it('should block script tags in values', () => {
      const urls = [
        'https://example.com?param=<script>alert(1)</script>',
        'https://example.com?param=javascript:alert(1)',
        'https://example.com?param=<iframe src="evil.com">',
        'https://example.com?param=<object data="evil.swf">'
      ];

      urls.forEach(url => {
        const result = sanitizeUrlForSharing(url);
        expect(result).toBe('https://example.com/'); // @braintree/sanitize-url normalizes
      });
    });

    it('should block event handler attributes', () => {
      const url = 'https://example.com?param=onmouseover=alert(1)';
      const result = sanitizeUrlForSharing(url);
      expect(result).toBe('https://example.com/'); // @braintree/sanitize-url normalizes
    });
  });

  describe('isValidUrl', () => {
    it('should return true for valid URLs', () => {
      expect(isValidUrl('https://example.com')).toBe(true);
      expect(isValidUrl('http://example.com')).toBe(true);
      expect(isValidUrl('https://example.com?param=value')).toBe(true);
      expect(isValidUrl('https://example.com#section')).toBe(true);
    });

    it('should return false for invalid URLs', () => {
      expect(isValidUrl('')).toBe(false);
      expect(isValidUrl(null as any)).toBe(false);
      expect(isValidUrl(undefined as any)).toBe(false);
      expect(isValidUrl('not-a-url')).toBe(false);
    });

    it('should reject dangerous protocols', () => {
      expect(isValidUrl('javascript:alert(1)')).toBe(false);
      expect(isValidUrl('data:text/html,<script>')).toBe(false);
      expect(isValidUrl('file:///etc/passwd')).toBe(false);
      expect(isValidUrl('ftp://example.com')).toBe(false);
      expect(isValidUrl('custom://example.com')).toBe(false);
    });

    it('should reject dangerous hostnames', () => {
      expect(isValidUrl('http://localhost')).toBe(false);
      expect(isValidUrl('http://127.0.0.1')).toBe(false);
      expect(isValidUrl('http://10.0.0.1')).toBe(false);
    });
  });

  describe('sanitizeUrl', () => {
    it('should return sanitized URL for valid URLs', () => {
      expect(sanitizeUrl('https://example.com')).toBe('https://example.com');
      expect(sanitizeUrl('http://example.com')).toBe('http://example.com');
      expect(sanitizeUrl('https://example.com?param=value')).toBe('https://example.com/?param=value');
      expect(sanitizeUrl('https://example.com/path')).toBe('https://example.com/path');
    });

    it('should return null for invalid URLs', () => {
      expect(sanitizeUrl('')).toBeNull();
      expect(sanitizeUrl(null as any)).toBeNull();
      expect(sanitizeUrl('javascript:alert(1)')).toBeNull();
      expect(sanitizeUrl('http://localhost')).toBeNull();
    });

    it('should handle malformed URLs', () => {
      expect(sanitizeUrl('not-a-url')).toBeNull();
      expect(sanitizeUrl('htp://example.com')).toBeNull();
    });
  });
});