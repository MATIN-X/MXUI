/**
 * ============================================================================
 * MX-UI VPN Panel - Utility Functions
 * Part 1: Core Helpers, Storage, Validation, Formatting, Date/Time
 * ============================================================================
 */

'use strict';

// ============================================================================
// CONSTANTS
// ============================================================================

const MXUI = {
    VERSION: '1.0.0',
    APP_NAME: 'MX-UI VPN Panel',
    STORAGE_PREFIX: 'mxui_',
    DEFAULT_LANG: 'en',
    SUPPORTED_LANGS: ['en', 'fa', 'ru', 'zh'],
    DATE_FORMAT: 'YYYY-MM-DD',
    TIME_FORMAT: 'HH:mm:ss',
    DATETIME_FORMAT: 'YYYY-MM-DD HH:mm:ss',
};

// ============================================================================
// TYPE CHECKING
// ============================================================================

const is = {
    undefined: (val) => typeof val === 'undefined',
    null: (val) => val === null,
    nil: (val) => is.undefined(val) || is.null(val),
    string: (val) => typeof val === 'string',
    number: (val) => typeof val === 'number' && !isNaN(val),
    boolean: (val) => typeof val === 'boolean',
    array: (val) => Array.isArray(val),
    object: (val) => val !== null && typeof val === 'object' && !Array.isArray(val),
    function: (val) => typeof val === 'function',
    promise: (val) => val instanceof Promise,
    date: (val) => val instanceof Date && !isNaN(val),
    regexp: (val) => val instanceof RegExp,
    element: (val) => val instanceof Element || val instanceof HTMLDocument,
    empty: (val) => {
        if (is.nil(val)) return true;
        if (is.string(val) || is.array(val)) return val.length === 0;
        if (is.object(val)) return Object.keys(val).length === 0;
        return false;
    },
    email: (val) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val),
    url: (val) => {
        try {
            new URL(val);
            return true;
        } catch {
            return false;
        }
    },
    uuid: (val) => /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(val),
    ip: (val) => is.ipv4(val) || is.ipv6(val),
    ipv4: (val) => /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(val),
    ipv6: (val) => /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(val),
    json: (val) => {
        try {
            JSON.parse(val);
            return true;
        } catch {
            return false;
        }
    },
    mobile: () => /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent),
    touch: () => 'ontouchstart' in window || navigator.maxTouchPoints > 0,
    online: () => navigator.onLine,
    rtl: () => document.documentElement.dir === 'rtl' || document.body.dir === 'rtl',
    darkMode: () => window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches,
};

// ============================================================================
// STORAGE UTILITIES
// ============================================================================

const storage = {
    /**
     * Set item in localStorage with optional expiry
     */
    set(key, value, expiryMinutes = null) {
        const prefixedKey = MXUI.STORAGE_PREFIX + key;
        const item = {
            value,
            timestamp: Date.now(),
            expiry: expiryMinutes ? Date.now() + (expiryMinutes * 60 * 1000) : null
        };
        try {
            localStorage.setItem(prefixedKey, JSON.stringify(item));
            return true;
        } catch (e) {
            console.error('Storage set error:', e);
            return false;
        }
    },

    /**
     * Get item from localStorage
     */
    get(key, defaultValue = null) {
        const prefixedKey = MXUI.STORAGE_PREFIX + key;
        try {
            const item = localStorage.getItem(prefixedKey);
            if (!item) return defaultValue;

            const parsed = JSON.parse(item);
            
            // Check expiry
            if (parsed.expiry && Date.now() > parsed.expiry) {
                this.remove(key);
                return defaultValue;
            }

            return parsed.value;
        } catch (e) {
            console.error('Storage get error:', e);
            return defaultValue;
        }
    },

    /**
     * Remove item from localStorage
     */
    remove(key) {
        const prefixedKey = MXUI.STORAGE_PREFIX + key;
        try {
            localStorage.removeItem(prefixedKey);
            return true;
        } catch (e) {
            console.error('Storage remove error:', e);
            return false;
        }
    },

    /**
     * Clear all MXUI items from localStorage
     */
    clear() {
        try {
            Object.keys(localStorage)
                .filter(key => key.startsWith(MXUI.STORAGE_PREFIX))
                .forEach(key => localStorage.removeItem(key));
            return true;
        } catch (e) {
            console.error('Storage clear error:', e);
            return false;
        }
    },

    /**
     * Get all MXUI items
     */
    getAll() {
        const items = {};
        try {
            Object.keys(localStorage)
                .filter(key => key.startsWith(MXUI.STORAGE_PREFIX))
                .forEach(key => {
                    const cleanKey = key.replace(MXUI.STORAGE_PREFIX, '');
                    items[cleanKey] = this.get(cleanKey);
                });
        } catch (e) {
            console.error('Storage getAll error:', e);
        }
        return items;
    },

    /**
     * Check if key exists
     */
    has(key) {
        return this.get(key) !== null;
    },

    /**
     * Get storage size in bytes
     */
    size() {
        let size = 0;
        Object.keys(localStorage)
            .filter(key => key.startsWith(MXUI.STORAGE_PREFIX))
            .forEach(key => {
                size += localStorage.getItem(key).length * 2; // UTF-16
            });
        return size;
    }
};

// Session Storage wrapper
const session = {
    set(key, value) {
        try {
            sessionStorage.setItem(MXUI.STORAGE_PREFIX + key, JSON.stringify(value));
            return true;
        } catch (e) {
            return false;
        }
    },

    get(key, defaultValue = null) {
        try {
            const item = sessionStorage.getItem(MXUI.STORAGE_PREFIX + key);
            return item ? JSON.parse(item) : defaultValue;
        } catch (e) {
            return defaultValue;
        }
    },

    remove(key) {
        sessionStorage.removeItem(MXUI.STORAGE_PREFIX + key);
    },

    clear() {
        Object.keys(sessionStorage)
            .filter(key => key.startsWith(MXUI.STORAGE_PREFIX))
            .forEach(key => sessionStorage.removeItem(key));
    }
};

// ============================================================================
// STRING UTILITIES
// ============================================================================

const str = {
    /**
     * Capitalize first letter
     */
    capitalize(str) {
        if (!is.string(str)) return '';
        return str.charAt(0).toUpperCase() + str.slice(1).toLowerCase();
    },

    /**
     * Capitalize each word
     */
    titleCase(str) {
        if (!is.string(str)) return '';
        return str.replace(/\b\w/g, char => char.toUpperCase());
    },

    /**
     * Convert to camelCase
     */
    camelCase(str) {
        if (!is.string(str)) return '';
        return str
            .replace(/(?:^\w|[A-Z]|\b\w)/g, (letter, index) =>
                index === 0 ? letter.toLowerCase() : letter.toUpperCase()
            )
            .replace(/[\s\-_]+/g, '');
    },

    /**
     * Convert to kebab-case
     */
    kebabCase(str) {
        if (!is.string(str)) return '';
        return str
            .replace(/([a-z])([A-Z])/g, '$1-$2')
            .replace(/[\s_]+/g, '-')
            .toLowerCase();
    },

    /**
     * Convert to snake_case
     */
    snakeCase(str) {
        if (!is.string(str)) return '';
        return str
            .replace(/([a-z])([A-Z])/g, '$1_$2')
            .replace(/[\s\-]+/g, '_')
            .toLowerCase();
    },

    /**
     * Truncate string
     */
    truncate(str, length = 50, suffix = '...') {
        if (!is.string(str)) return '';
        if (str.length <= length) return str;
        return str.substring(0, length - suffix.length) + suffix;
    },

    /**
     * Remove HTML tags
     */
    stripTags(str) {
        if (!is.string(str)) return '';
        return str.replace(/<[^>]*>/g, '');
    },

    /**
     * Escape HTML entities
     */
    escapeHtml(str) {
        if (!is.string(str)) return '';
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return str.replace(/[&<>"']/g, m => map[m]);
    },

    /**
     * Unescape HTML entities
     */
    unescapeHtml(str) {
        if (!is.string(str)) return '';
        const map = {
            '&amp;': '&',
            '&lt;': '<',
            '&gt;': '>',
            '&quot;': '"',
            '&#039;': "'"
        };
        return str.replace(/&amp;|&lt;|&gt;|&quot;|&#039;/g, m => map[m]);
    },

    /**
     * Generate random string
     */
    random(length = 16, charset = 'alphanumeric') {
        const charsets = {
            alphanumeric: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
            alpha: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
            numeric: '0123456789',
            hex: '0123456789abcdef',
            special: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()'
        };
        const chars = charsets[charset] || charset;
        let result = '';
        const randomValues = new Uint32Array(length);
        crypto.getRandomValues(randomValues);
        for (let i = 0; i < length; i++) {
            result += chars[randomValues[i] % chars.length];
        }
        return result;
    },

    /**
     * Generate UUID v4
     */
    uuid() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    },

    /**
     * Slug from string
     */
    slug(str, separator = '-') {
        if (!is.string(str)) return '';
        return str
            .toLowerCase()
            .trim()
            .replace(/[^\w\s-]/g, '')
            .replace(/[\s_-]+/g, separator)
            .replace(/^-+|-+$/g, '');
    },

    /**
     * Count words
     */
    wordCount(str) {
        if (!is.string(str)) return 0;
        return str.trim().split(/\s+/).filter(Boolean).length;
    },

    /**
     * Mask string (for sensitive data)
     */
    mask(str, visibleStart = 4, visibleEnd = 4, maskChar = '*') {
        if (!is.string(str)) return '';
        if (str.length <= visibleStart + visibleEnd) return str;
        const start = str.substring(0, visibleStart);
        const end = str.substring(str.length - visibleEnd);
        const masked = maskChar.repeat(str.length - visibleStart - visibleEnd);
        return start + masked + end;
    },

    /**
     * Template string interpolation
     */
    template(str, data) {
        if (!is.string(str) || !is.object(data)) return str;
        return str.replace(/\{\{(\w+)\}\}/g, (match, key) => {
            return data.hasOwnProperty(key) ? data[key] : match;
        });
    },

    /**
     * Pluralize word
     */
    pluralize(count, singular, plural = null) {
        if (count === 1) return singular;
        return plural || singular + 's';
    }
};

// ============================================================================
// NUMBER UTILITIES
// ============================================================================

const num = {
    /**
     * Format number with commas
     */
    format(number, decimals = 0, locale = 'en-US') {
        if (!is.number(number)) return '0';
        return number.toLocaleString(locale, {
            minimumFractionDigits: decimals,
            maximumFractionDigits: decimals
        });
    },

    /**
     * Format as currency
     */
    currency(amount, currency = 'USD', locale = 'en-US') {
        if (!is.number(amount)) return '';
        return new Intl.NumberFormat(locale, {
            style: 'currency',
            currency: currency
        }).format(amount);
    },

    /**
     * Format as percentage
     */
    percentage(value, decimals = 1) {
        if (!is.number(value)) return '0%';
        return value.toFixed(decimals) + '%';
    },

    /**
     * Format bytes to human readable
     */
    formatBytes(bytes, decimals = 2) {
        if (!is.number(bytes) || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + ' ' + sizes[i];
    },

    /**
     * Parse bytes from string
     */
    parseBytes(str) {
        if (!is.string(str)) return 0;
        const units = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4 };
        const match = str.match(/^([\d.]+)\s*(B|KB|MB|GB|TB)$/i);
        if (!match) return 0;
        return parseFloat(match[1]) * (units[match[2].toUpperCase()] || 1);
    },

    /**
     * Format speed (bytes per second)
     */
    formatSpeed(bytesPerSecond) {
        return this.formatBytes(bytesPerSecond) + '/s';
    },

    /**
     * Clamp number between min and max
     */
    clamp(value, min, max) {
        return Math.min(Math.max(value, min), max);
    },

    /**
     * Round to decimal places
     */
    round(value, decimals = 0) {
        const factor = Math.pow(10, decimals);
        return Math.round(value * factor) / factor;
    },

    /**
     * Check if between range
     */
    between(value, min, max) {
        return value >= min && value <= max;
    },

    /**
     * Generate random number
     */
    random(min = 0, max = 100) {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    },

    /**
     * Ordinal suffix (1st, 2nd, 3rd, etc.)
     */
    ordinal(n) {
        const s = ['th', 'st', 'nd', 'rd'];
        const v = n % 100;
        return n + (s[(v - 20) % 10] || s[v] || s[0]);
    },

    /**
     * Abbreviate large numbers (1K, 1M, etc.)
     */
    abbreviate(value, decimals = 1) {
        if (!is.number(value)) return '0';
        const abbrev = ['', 'K', 'M', 'B', 'T'];
        const tier = Math.floor(Math.log10(Math.abs(value)) / 3);
        if (tier === 0) return value.toString();
        const suffix = abbrev[tier];
        const scale = Math.pow(10, tier * 3);
        const scaled = value / scale;
        return scaled.toFixed(decimals) + suffix;
    }
};

// ============================================================================
// DATE & TIME UTILITIES
// ============================================================================

const date = {
    /**
     * Format date
     */
    format(date, format = MXUI.DATE_FORMAT) {
        if (!date) return '';
        const d = is.date(date) ? date : new Date(date);
        if (isNaN(d.getTime())) return '';

        const pad = (n) => String(n).padStart(2, '0');
        
        const tokens = {
            'YYYY': d.getFullYear(),
            'YY': String(d.getFullYear()).slice(-2),
            'MM': pad(d.getMonth() + 1),
            'M': d.getMonth() + 1,
            'DD': pad(d.getDate()),
            'D': d.getDate(),
            'HH': pad(d.getHours()),
            'H': d.getHours(),
            'hh': pad(d.getHours() % 12 || 12),
            'h': d.getHours() % 12 || 12,
            'mm': pad(d.getMinutes()),
            'm': d.getMinutes(),
            'ss': pad(d.getSeconds()),
            's': d.getSeconds(),
            'A': d.getHours() < 12 ? 'AM' : 'PM',
            'a': d.getHours() < 12 ? 'am' : 'pm'
        };

        return format.replace(/YYYY|YY|MM|M|DD|D|HH|H|hh|h|mm|m|ss|s|A|a/g, match => tokens[match]);
    },

    /**
     * Get relative time (e.g., "2 hours ago")
     */
    relative(date, locale = 'en') {
        if (!date) return '';
        const d = is.date(date) ? date : new Date(date);
        if (isNaN(d.getTime())) return '';

        const now = new Date();
        const diffMs = now - d;
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHour = Math.floor(diffMin / 60);
        const diffDay = Math.floor(diffHour / 24);
        const diffWeek = Math.floor(diffDay / 7);
        const diffMonth = Math.floor(diffDay / 30);
        const diffYear = Math.floor(diffDay / 365);

        const rtf = new Intl.RelativeTimeFormat(locale, { numeric: 'auto' });

        if (diffSec < 60) return rtf.format(-diffSec, 'second');
        if (diffMin < 60) return rtf.format(-diffMin, 'minute');
        if (diffHour < 24) return rtf.format(-diffHour, 'hour');
        if (diffDay < 7) return rtf.format(-diffDay, 'day');
        if (diffWeek < 4) return rtf.format(-diffWeek, 'week');
        if (diffMonth < 12) return rtf.format(-diffMonth, 'month');
        return rtf.format(-diffYear, 'year');
    },

    /**
     * Parse date string
     */
    parse(str, format = MXUI.DATE_FORMAT) {
        if (!is.string(str)) return null;
        
        // Try native parsing first
        const d = new Date(str);
        if (!isNaN(d.getTime())) return d;

        // Manual parsing for specific format
        const formatParts = format.match(/YYYY|MM|DD|HH|mm|ss/g) || [];
        const regex = format
            .replace(/YYYY/g, '(\\d{4})')
            .replace(/MM|DD|HH|mm|ss/g, '(\\d{2})');
        
        const match = str.match(new RegExp(regex));
        if (!match) return null;

        const parts = {};
        formatParts.forEach((part, i) => {
            parts[part] = parseInt(match[i + 1], 10);
        });

        return new Date(
            parts.YYYY || 0,
            (parts.MM || 1) - 1,
            parts.DD || 1,
            parts.HH || 0,
            parts.mm || 0,
            parts.ss || 0
        );
    },

    /**
     * Add time to date
     */
    add(date, amount, unit = 'days') {
        const d = is.date(date) ? new Date(date) : new Date();
        const units = {
            seconds: () => d.setSeconds(d.getSeconds() + amount),
            minutes: () => d.setMinutes(d.getMinutes() + amount),
            hours: () => d.setHours(d.getHours() + amount),
            days: () => d.setDate(d.getDate() + amount),
            weeks: () => d.setDate(d.getDate() + (amount * 7)),
            months: () => d.setMonth(d.getMonth() + amount),
            years: () => d.setFullYear(d.getFullYear() + amount)
        };
        if (units[unit]) units[unit]();
        return d;
    },

    /**
     * Subtract time from date
     */
    subtract(date, amount, unit = 'days') {
        return this.add(date, -amount, unit);
    },

    /**
     * Get difference between dates
     */
    diff(date1, date2, unit = 'days') {
        const d1 = is.date(date1) ? date1 : new Date(date1);
        const d2 = is.date(date2) ? date2 : new Date(date2);
        const diffMs = Math.abs(d2 - d1);
        
        const conversions = {
            seconds: 1000,
            minutes: 1000 * 60,
            hours: 1000 * 60 * 60,
            days: 1000 * 60 * 60 * 24,
            weeks: 1000 * 60 * 60 * 24 * 7,
            months: 1000 * 60 * 60 * 24 * 30,
            years: 1000 * 60 * 60 * 24 * 365
        };

        return Math.floor(diffMs / (conversions[unit] || conversions.days));
    },

    /**
     * Check if date is today
     */
    isToday(date) {
        const d = is.date(date) ? date : new Date(date);
        const today = new Date();
        return d.toDateString() === today.toDateString();
    },

    /**
     * Check if date is in past
     */
    isPast(date) {
        const d = is.date(date) ? date : new Date(date);
        return d < new Date();
    },

    /**
     * Check if date is in future
     */
    isFuture(date) {
        const d = is.date(date) ? date : new Date(date);
        return d > new Date();
    },

    /**
     * Get start of period
     */
    startOf(date, unit = 'day') {
        const d = is.date(date) ? new Date(date) : new Date();
        
        switch (unit) {
            case 'minute':
                d.setSeconds(0, 0);
                break;
            case 'hour':
                d.setMinutes(0, 0, 0);
                break;
            case 'day':
                d.setHours(0, 0, 0, 0);
                break;
            case 'week':
                d.setHours(0, 0, 0, 0);
                d.setDate(d.getDate() - d.getDay());
                break;
            case 'month':
                d.setHours(0, 0, 0, 0);
                d.setDate(1);
                break;
            case 'year':
                d.setHours(0, 0, 0, 0);
                d.setMonth(0, 1);
                break;
        }
        return d;
    },

    /**
     * Get end of period
     */
    endOf(date, unit = 'day') {
        const d = is.date(date) ? new Date(date) : new Date();
        
        switch (unit) {
            case 'minute':
                d.setSeconds(59, 999);
                break;
            case 'hour':
                d.setMinutes(59, 59, 999);
                break;
            case 'day':
                d.setHours(23, 59, 59, 999);
                break;
            case 'week':
                d.setHours(23, 59, 59, 999);
                d.setDate(d.getDate() + (6 - d.getDay()));
                break;
            case 'month':
                d.setHours(23, 59, 59, 999);
                d.setMonth(d.getMonth() + 1, 0);
                break;
            case 'year':
                d.setHours(23, 59, 59, 999);
                d.setMonth(11, 31);
                break;
        }
        return d;
    },

    /**
     * Format duration (seconds to HH:MM:SS)
     */
    formatDuration(seconds) {
        if (!is.number(seconds) || seconds < 0) return '00:00:00';
        
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = Math.floor(seconds % 60);
        
        return [hours, minutes, secs]
            .map(v => String(v).padStart(2, '0'))
            .join(':');
    },

    /**
     * Format remaining time
     */
    formatRemaining(targetDate) {
        const target = is.date(targetDate) ? targetDate : new Date(targetDate);
        const now = new Date();
        const diff = target - now;

        if (diff <= 0) return { expired: true, text: 'Expired' };

        const days = Math.floor(diff / (1000 * 60 * 60 * 24));
        const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((diff % (1000 * 60)) / 1000);

        let text = '';
        if (days > 0) text += `${days}d `;
        if (hours > 0) text += `${hours}h `;
        if (minutes > 0) text += `${minutes}m `;
        if (days === 0) text += `${seconds}s`;

        return { expired: false, days, hours, minutes, seconds, text: text.trim() };
    },

    /**
     * Get timestamp
     */
    timestamp(date = null) {
        const d = date ? (is.date(date) ? date : new Date(date)) : new Date();
        return Math.floor(d.getTime() / 1000);
    },

    /**
     * From timestamp
     */
    fromTimestamp(timestamp) {
        return new Date(timestamp * 1000);
    }
};

// ============================================================================
// VALIDATION UTILITIES
// ============================================================================

const validate = {
    /**
     * Validate email
     */
    email(email) {
        const regex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        return regex.test(email);
    },

    /**
     * Validate password strength
     */
    password(password, options = {}) {
        const {
            minLength = 8,
            maxLength = 128,
            requireUppercase = true,
            requireLowercase = true,
            requireNumber = true,
            requireSpecial = false
        } = options;

        const result = {
            valid: true,
            errors: [],
            strength: 0
        };

        if (password.length < minLength) {
            result.errors.push(`Minimum ${minLength} characters required`);
            result.valid = false;
        }

        if (password.length > maxLength) {
            result.errors.push(`Maximum ${maxLength} characters allowed`);
            result.valid = false;
        }

        if (requireUppercase && !/[A-Z]/.test(password)) {
            result.errors.push('At least one uppercase letter required');
            result.valid = false;
        } else if (/[A-Z]/.test(password)) {
            result.strength += 1;
        }

        if (requireLowercase && !/[a-z]/.test(password)) {
            result.errors.push('At least one lowercase letter required');
            result.valid = false;
        } else if (/[a-z]/.test(password)) {
            result.strength += 1;
        }

        if (requireNumber && !/[0-9]/.test(password)) {
            result.errors.push('At least one number required');
            result.valid = false;
        } else if (/[0-9]/.test(password)) {
            result.strength += 1;
        }

        if (requireSpecial && !/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
            result.errors.push('At least one special character required');
            result.valid = false;
        } else if (/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
            result.strength += 1;
        }

        // Bonus for length
        if (password.length >= 12) result.strength += 1;
        if (password.length >= 16) result.strength += 1;

        // Strength level: weak, medium, strong, very-strong
        result.strengthLevel = result.strength <= 2 ? 'weak' :
                              result.strength <= 4 ? 'medium' :
                              result.strength <= 5 ? 'strong' : 'very-strong';

        return result;
    },

    /**
     * Validate URL
     */
    url(url, options = {}) {
        const { protocols = ['http', 'https'], requireProtocol = true } = options;
        
        try {
            const parsed = new URL(url);
            if (requireProtocol && !protocols.includes(parsed.protocol.replace(':', ''))) {
                return false;
            }
            return true;
        } catch {
            return false;
        }
    },

    /**
     * Validate IP address
     */
    ip(ip, version = null) {
        if (version === 4 || version === 'v4') return is.ipv4(ip);
        if (version === 6 || version === 'v6') return is.ipv6(ip);
        return is.ip(ip);
    },

    /**
     * Validate port number
     */
    port(port) {
        const p = parseInt(port, 10);
        return is.number(p) && p >= 1 && p <= 65535;
    },

    /**
     * Validate UUID
     */
    uuid(uuid) {
        return is.uuid(uuid);
    },

    /**
     * Validate phone number (basic)
     */
    phone(phone) {
        return /^[\d\s\-\+\(\)]{10,}$/.test(phone);
    },

    /**
     * Validate credit card (Luhn algorithm)
     */
    creditCard(number) {
        const cleaned = number.replace(/\s|-/g, '');
        if (!/^\d{13,19}$/.test(cleaned)) return false;

        let sum = 0;
        let isEven = false;

        for (let i = cleaned.length - 1; i >= 0; i--) {
            let digit = parseInt(cleaned.charAt(i), 10);

            if (isEven) {
                digit *= 2;
                if (digit > 9) digit -= 9;
            }

            sum += digit;
            isEven = !isEven;
        }

        return sum % 10 === 0;
    },

    /**
     * Validate form data
     */
    form(data, rules) {
        const errors = {};
        let isValid = true;

        for (const [field, fieldRules] of Object.entries(rules)) {
            const value = data[field];
            const fieldErrors = [];

            for (const rule of fieldRules) {
                let valid = true;
                let message = '';

                if (rule === 'required' || rule.type === 'required') {
                    valid = !is.empty(value);
                    message = rule.message || `${field} is required`;
                }
                else if (rule === 'email' || rule.type === 'email') {
                    valid = is.empty(value) || this.email(value);
                    message = rule.message || `${field} must be a valid email`;
                }
                else if (rule.type === 'min') {
                    valid = is.empty(value) || (is.string(value) ? value.length >= rule.value : value >= rule.value);
                    message = rule.message || `${field} must be at least ${rule.value}`;
                }
                else if (rule.type === 'max') {
                    valid = is.empty(value) || (is.string(value) ? value.length <= rule.value : value <= rule.value);
                    message = rule.message || `${field} must be at most ${rule.value}`;
                }
                else if (rule.type === 'pattern') {
                    valid = is.empty(value) || rule.value.test(value);
                    message = rule.message || `${field} format is invalid`;
                }
                else if (rule.type === 'match') {
                    valid = value === data[rule.field];
                    message = rule.message || `${field} must match ${rule.field}`;
                }
                else if (rule.type === 'custom' && is.function(rule.validator)) {
                    valid = rule.validator(value, data);
                    message = rule.message || `${field} is invalid`;
                }

                if (!valid) {
                    fieldErrors.push(message);
                    isValid = false;
                }
            }

            if (fieldErrors.length > 0) {
                errors[field] = fieldErrors;
            }
        }

        return { valid: isValid, errors };
    }
};

// ============================================================================
// URL UTILITIES
// ============================================================================

const url = {
    /**
     * Parse URL
     */
    parse(urlString) {
        try {
            return new URL(urlString);
        } catch {
            return null;
        }
    },

    /**
     * Get query parameters as object
     */
    getParams(urlString = window.location.href) {
        const params = {};
        const url = new URL(urlString);
        url.searchParams.forEach((value, key) => {
            params[key] = value;
        });
        return params;
    },

    /**
     * Get single query parameter
     */
    getParam(name, urlString = window.location.href) {
        const url = new URL(urlString);
        return url.searchParams.get(name);
    },

    /**
     * Build URL with query parameters
     */
    build(baseUrl, params = {}) {
        const url = new URL(baseUrl);
        Object.entries(params).forEach(([key, value]) => {
            if (!is.nil(value)) {
                url.searchParams.set(key, value);
            }
        });
        return url.toString();
    },

    /**
     * Update current URL without reload
     */
    update(params, replace = false) {
        const url = new URL(window.location.href);
        Object.entries(params).forEach(([key, value]) => {
            if (is.nil(value)) {
                url.searchParams.delete(key);
            } else {
                url.searchParams.set(key, value);
            }
        });
        
        if (replace) {
            history.replaceState(null, '', url.toString());
        } else {
            history.pushState(null, '', url.toString());
        }
    },

    /**
     * Encode object to query string
     */
    encode(params) {
        return Object.entries(params)
            .filter(([, value]) => !is.nil(value))
            .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
            .join('&');
    },

    /**
     * Decode query string to object
     */
    decode(queryString) {
        const params = {};
        const query = queryString.startsWith('?') ? queryString.slice(1) : queryString;
        query.split('&').forEach(pair => {
            const [key, value] = pair.split('=').map(decodeURIComponent);
            if (key) params[key] = value || '';
        });
        return params;
    },

    /**
     * Check if URL is external
     */
    isExternal(urlString) {
        try {
            const url = new URL(urlString);
            return url.origin !== window.location.origin;
        } catch {
            return false;
        }
    },

    /**
     * Get domain from URL
     */
    getDomain(urlString) {
        try {
            return new URL(urlString).hostname;
        } catch {
            return '';
        }
    }
};

// ============================================================================
// EXPORT (for module systems)
// ============================================================================

// Export for different module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { MXUI, is, storage, session, str, num, date, validate, url };
}

// Global export
window.MXUI = MXUI;
window.is = is;
window.storage = storage;
window.session = session;
window.str = str;
window.num = num;
window.date = date;
window.validate = validate;
window.url = url;
/**
 * ============================================================================
 * MX-UI VPN Panel - Utility Functions
 * Part 2: DOM, Events, i18n, Clipboard, Debounce, HTTP, Notifications, Theme
 * ============================================================================
 */

// ============================================================================
// DOM UTILITIES
// ============================================================================

const dom = {
    /**
     * Query selector shorthand
     */
    $(selector, context = document) {
        return context.querySelector(selector);
    },

    /**
     * Query selector all shorthand
     */
    $$(selector, context = document) {
        return Array.from(context.querySelectorAll(selector));
    },

    /**
     * Get element by ID
     */
    id(id) {
        return document.getElementById(id);
    },

    /**
     * Create element with attributes
     */
    create(tag, attributes = {}, children = []) {
        const element = document.createElement(tag);
        
        Object.entries(attributes).forEach(([key, value]) => {
            if (key === 'class' || key === 'className') {
                element.className = is.array(value) ? value.join(' ') : value;
            } else if (key === 'style' && is.object(value)) {
                Object.assign(element.style, value);
            } else if (key === 'data' && is.object(value)) {
                Object.entries(value).forEach(([dataKey, dataValue]) => {
                    element.dataset[dataKey] = dataValue;
                });
            } else if (key === 'html') {
                element.innerHTML = value;
            } else if (key === 'text') {
                element.textContent = value;
            } else if (key.startsWith('on') && is.function(value)) {
                element.addEventListener(key.slice(2).toLowerCase(), value);
            } else {
                element.setAttribute(key, value);
            }
        });

        children.forEach(child => {
            if (is.string(child)) {
                element.appendChild(document.createTextNode(child));
            } else if (is.element(child)) {
                element.appendChild(child);
            }
        });

        return element;
    },

    /**
     * Parse HTML string to elements
     */
    parseHTML(html) {
        const template = document.createElement('template');
        template.innerHTML = html.trim();
        return template.content.firstChild;
    },

    /**
     * Insert element after reference
     */
    insertAfter(newElement, referenceElement) {
        referenceElement.parentNode.insertBefore(newElement, referenceElement.nextSibling);
    },

    /**
     * Insert element before reference
     */
    insertBefore(newElement, referenceElement) {
        referenceElement.parentNode.insertBefore(newElement, referenceElement);
    },

    /**
     * Remove element
     */
    remove(element) {
        if (is.string(element)) {
            element = this.$(element);
        }
        if (element && element.parentNode) {
            element.parentNode.removeChild(element);
        }
    },

    /**
     * Empty element
     */
    empty(element) {
        if (is.string(element)) {
            element = this.$(element);
        }
        if (element) {
            while (element.firstChild) {
                element.removeChild(element.firstChild);
            }
        }
    },

    /**
     * Replace element
     */
    replace(oldElement, newElement) {
        if (oldElement && oldElement.parentNode) {
            oldElement.parentNode.replaceChild(newElement, oldElement);
        }
    },

    /**
     * Clone element
     */
    clone(element, deep = true) {
        return element.cloneNode(deep);
    },

    /**
     * Check if element has class
     */
    hasClass(element, className) {
        if (is.string(element)) element = this.$(element);
        return element?.classList.contains(className);
    },

    /**
     * Add class(es)
     */
    addClass(element, ...classes) {
        if (is.string(element)) element = this.$(element);
        if (element) {
            classes.forEach(cls => {
                if (cls.includes(' ')) {
                    cls.split(' ').forEach(c => element.classList.add(c.trim()));
                } else {
                    element.classList.add(cls);
                }
            });
        }
        return element;
    },

    /**
     * Remove class(es)
     */
    removeClass(element, ...classes) {
        if (is.string(element)) element = this.$(element);
        if (element) {
            classes.forEach(cls => {
                if (cls.includes(' ')) {
                    cls.split(' ').forEach(c => element.classList.remove(c.trim()));
                } else {
                    element.classList.remove(cls);
                }
            });
        }
        return element;
    },

    /**
     * Toggle class
     */
    toggleClass(element, className, force) {
        if (is.string(element)) element = this.$(element);
        if (element) {
            return element.classList.toggle(className, force);
        }
        return false;
    },

    /**
     * Get/Set attribute
     */
    attr(element, name, value) {
        if (is.string(element)) element = this.$(element);
        if (!element) return null;
        
        if (is.undefined(value)) {
            return element.getAttribute(name);
        }
        
        if (value === null) {
            element.removeAttribute(name);
        } else {
            element.setAttribute(name, value);
        }
        return element;
    },

    /**
     * Get/Set data attribute
     */
    data(element, key, value) {
        if (is.string(element)) element = this.$(element);
        if (!element) return null;

        if (is.undefined(key)) {
            return { ...element.dataset };
        }
        
        if (is.undefined(value)) {
            return element.dataset[key];
        }
        
        element.dataset[key] = value;
        return element;
    },

    /**
     * Get/Set CSS property
     */
    css(element, property, value) {
        if (is.string(element)) element = this.$(element);
        if (!element) return null;

        if (is.object(property)) {
            Object.entries(property).forEach(([prop, val]) => {
                element.style[prop] = val;
            });
            return element;
        }

        if (is.undefined(value)) {
            return getComputedStyle(element).getPropertyValue(property);
        }

        element.style[property] = value;
        return element;
    },

    /**
     * Get element dimensions
     */
    dimensions(element) {
        if (is.string(element)) element = this.$(element);
        if (!element) return null;

        const rect = element.getBoundingClientRect();
        return {
            width: rect.width,
            height: rect.height,
            top: rect.top + window.scrollY,
            left: rect.left + window.scrollX,
            bottom: rect.bottom + window.scrollY,
            right: rect.right + window.scrollX,
            viewportTop: rect.top,
            viewportLeft: rect.left
        };
    },

    /**
     * Get element offset
     */
    offset(element) {
        if (is.string(element)) element = this.$(element);
        if (!element) return { top: 0, left: 0 };

        const rect = element.getBoundingClientRect();
        return {
            top: rect.top + window.scrollY,
            left: rect.left + window.scrollX
        };
    },

    /**
     * Show element
     */
    show(element, display = 'block') {
        if (is.string(element)) element = this.$(element);
        if (element) {
            element.style.display = display;
            element.removeAttribute('hidden');
        }
        return element;
    },

    /**
     * Hide element
     */
    hide(element) {
        if (is.string(element)) element = this.$(element);
        if (element) {
            element.style.display = 'none';
        }
        return element;
    },

    /**
     * Toggle visibility
     */
    toggle(element, show) {
        if (is.string(element)) element = this.$(element);
        if (!element) return;

        if (is.undefined(show)) {
            show = element.style.display === 'none';
        }

        return show ? this.show(element) : this.hide(element);
    },

    /**
     * Fade in
     */
    async fadeIn(element, duration = 300) {
        if (is.string(element)) element = this.$(element);
        if (!element) return;

        element.style.opacity = '0';
        element.style.display = '';
        element.style.transition = `opacity ${duration}ms ease`;

        await this.nextFrame();
        element.style.opacity = '1';

        return new Promise(resolve => {
            setTimeout(() => {
                element.style.transition = '';
                resolve(element);
            }, duration);
        });
    },

    /**
     * Fade out
     */
    async fadeOut(element, duration = 300) {
        if (is.string(element)) element = this.$(element);
        if (!element) return;

        element.style.opacity = '1';
        element.style.transition = `opacity ${duration}ms ease`;

        await this.nextFrame();
        element.style.opacity = '0';

        return new Promise(resolve => {
            setTimeout(() => {
                element.style.display = 'none';
                element.style.transition = '';
                resolve(element);
            }, duration);
        });
    },

    /**
     * Slide down
     */
    async slideDown(element, duration = 300) {
        if (is.string(element)) element = this.$(element);
        if (!element) return;

        element.style.display = '';
        const height = element.scrollHeight;
        element.style.height = '0';
        element.style.overflow = 'hidden';
        element.style.transition = `height ${duration}ms ease`;

        await this.nextFrame();
        element.style.height = height + 'px';

        return new Promise(resolve => {
            setTimeout(() => {
                element.style.height = '';
                element.style.overflow = '';
                element.style.transition = '';
                resolve(element);
            }, duration);
        });
    },

    /**
     * Slide up
     */
    async slideUp(element, duration = 300) {
        if (is.string(element)) element = this.$(element);
        if (!element) return;

        element.style.height = element.scrollHeight + 'px';
        element.style.overflow = 'hidden';
        element.style.transition = `height ${duration}ms ease`;

        await this.nextFrame();
        element.style.height = '0';

        return new Promise(resolve => {
            setTimeout(() => {
                element.style.display = 'none';
                element.style.height = '';
                element.style.overflow = '';
                element.style.transition = '';
                resolve(element);
            }, duration);
        });
    },

    /**
     * Check if element is visible
     */
    isVisible(element) {
        if (is.string(element)) element = this.$(element);
        if (!element) return false;
        return !!(element.offsetWidth || element.offsetHeight || element.getClientRects().length);
    },

    /**
     * Check if element is in viewport
     */
    isInViewport(element, threshold = 0) {
        if (is.string(element)) element = this.$(element);
        if (!element) return false;

        const rect = element.getBoundingClientRect();
        return (
            rect.top >= -threshold &&
            rect.left >= -threshold &&
            rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) + threshold &&
            rect.right <= (window.innerWidth || document.documentElement.clientWidth) + threshold
        );
    },

    /**
     * Scroll to element
     */
    scrollTo(element, options = {}) {
        if (is.string(element)) element = this.$(element);
        if (!element) return;

        const { behavior = 'smooth', block = 'start', offset = 0 } = options;

        if (offset) {
            const top = element.getBoundingClientRect().top + window.scrollY - offset;
            window.scrollTo({ top, behavior });
        } else {
            element.scrollIntoView({ behavior, block });
        }
    },

    /**
     * Get scroll position
     */
    scrollPosition() {
        return {
            x: window.pageXOffset || document.documentElement.scrollLeft,
            y: window.pageYOffset || document.documentElement.scrollTop
        };
    },

    /**
     * Wait for next frame
     */
    nextFrame() {
        return new Promise(resolve => requestAnimationFrame(resolve));
    },

    /**
     * Wait for element to exist
     */
    waitFor(selector, timeout = 5000) {
        return new Promise((resolve, reject) => {
            const element = this.$(selector);
            if (element) {
                return resolve(element);
            }

            const observer = new MutationObserver((mutations, obs) => {
                const element = this.$(selector);
                if (element) {
                    obs.disconnect();
                    resolve(element);
                }
            });

            observer.observe(document.body, {
                childList: true,
                subtree: true
            });

            setTimeout(() => {
                observer.disconnect();
                reject(new Error(`Element ${selector} not found within ${timeout}ms`));
            }, timeout);
        });
    },

    /**
     * Get form data as object
     */
    formData(form) {
        if (is.string(form)) form = this.$(form);
        if (!form) return {};

        const formData = new FormData(form);
        const data = {};

        formData.forEach((value, key) => {
            if (data.hasOwnProperty(key)) {
                if (!is.array(data[key])) {
                    data[key] = [data[key]];
                }
                data[key].push(value);
            } else {
                data[key] = value;
            }
        });

        return data;
    },

    /**
     * Set form data from object
     */
    setFormData(form, data) {
        if (is.string(form)) form = this.$(form);
        if (!form || !is.object(data)) return;

        Object.entries(data).forEach(([key, value]) => {
            const field = form.elements[key];
            if (!field) return;

            if (field.type === 'checkbox') {
                field.checked = Boolean(value);
            } else if (field.type === 'radio') {
                const radio = form.querySelector(`[name="${key}"][value="${value}"]`);
                if (radio) radio.checked = true;
            } else if (field.tagName === 'SELECT' && field.multiple) {
                Array.from(field.options).forEach(option => {
                    option.selected = is.array(value) ? value.includes(option.value) : option.value === value;
                });
            } else {
                field.value = value;
            }
        });
    },

    /**
     * Focus element with optional select
     */
    focus(element, select = false) {
        if (is.string(element)) element = this.$(element);
        if (!element) return;

        element.focus();
        if (select && (element.tagName === 'INPUT' || element.tagName === 'TEXTAREA')) {
            element.select();
        }
    },

    /**
     * Get parent matching selector
     */
    closest(element, selector) {
        if (is.string(element)) element = this.$(element);
        return element?.closest(selector);
    },

    /**
     * Get all siblings
     */
    siblings(element) {
        if (is.string(element)) element = this.$(element);
        if (!element || !element.parentNode) return [];
        return Array.from(element.parentNode.children).filter(child => child !== element);
    },

    /**
     * Get index of element in parent
     */
    index(element) {
        if (is.string(element)) element = this.$(element);
        if (!element || !element.parentNode) return -1;
        return Array.from(element.parentNode.children).indexOf(element);
    }
};

// ============================================================================
// EVENT UTILITIES
// ============================================================================

const events = {
    _handlers: new WeakMap(),

    /**
     * Add event listener
     */
    on(element, event, handler, options = {}) {
        if (is.string(element)) element = dom.$(element);
        if (!element) return;

        const { delegate, once = false, passive = true, capture = false } = options;

        let actualHandler = handler;

        // Event delegation
        if (delegate) {
            actualHandler = (e) => {
                const target = e.target.closest(delegate);
                if (target && element.contains(target)) {
                    handler.call(target, e, target);
                }
            };
        }

        // Handle multiple events
        const eventList = event.split(' ');
        eventList.forEach(evt => {
            element.addEventListener(evt, actualHandler, { once, passive, capture });
        });

        // Store handler for removal
        if (!this._handlers.has(element)) {
            this._handlers.set(element, new Map());
        }
        const elementHandlers = this._handlers.get(element);
        const key = `${event}_${handler.toString().slice(0, 50)}`;
        elementHandlers.set(key, { event: eventList, handler: actualHandler, options: { passive, capture } });

        return () => this.off(element, event, handler);
    },

    /**
     * Remove event listener
     */
    off(element, event, handler) {
        if (is.string(element)) element = dom.$(element);
        if (!element) return;

        const elementHandlers = this._handlers.get(element);
        if (!elementHandlers) return;

        const key = `${event}_${handler.toString().slice(0, 50)}`;
        const stored = elementHandlers.get(key);

        if (stored) {
            stored.event.forEach(evt => {
                element.removeEventListener(evt, stored.handler, stored.options);
            });
            elementHandlers.delete(key);
        }
    },

    /**
     * Add one-time event listener
     */
    once(element, event, handler, options = {}) {
        return this.on(element, event, handler, { ...options, once: true });
    },

    /**
     * Trigger custom event
     */
    trigger(element, eventName, detail = {}) {
        if (is.string(element)) element = dom.$(element);
        if (!element) return;

        const event = new CustomEvent(eventName, {
            bubbles: true,
            cancelable: true,
            detail
        });

        return element.dispatchEvent(event);
    },

    /**
     * Delegate event listener
     */
    delegate(parent, selector, event, handler) {
        return this.on(parent, event, handler, { delegate: selector });
    },

    /**
     * Ready event (DOM loaded)
     */
    ready(callback) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', callback, { once: true });
        } else {
            callback();
        }
    },

    /**
     * Window load event
     */
    load(callback) {
        if (document.readyState === 'complete') {
            callback();
        } else {
            window.addEventListener('load', callback, { once: true });
        }
    },

    /**
     * Resize event with debounce
     */
    onResize(callback, delay = 100) {
        const debouncedCallback = debounce(callback, delay);
        window.addEventListener('resize', debouncedCallback);
        return () => window.removeEventListener('resize', debouncedCallback);
    },

    /**
     * Scroll event with throttle
     */
    onScroll(callback, delay = 16) {
        const throttledCallback = throttle(callback, delay);
        window.addEventListener('scroll', throttledCallback, { passive: true });
        return () => window.removeEventListener('scroll', throttledCallback);
    },

    /**
     * Click outside element
     */
    onClickOutside(element, callback) {
        if (is.string(element)) element = dom.$(element);
        if (!element) return;

        const handler = (e) => {
            if (!element.contains(e.target)) {
                callback(e);
            }
        };

        document.addEventListener('click', handler);
        return () => document.removeEventListener('click', handler);
    },

    /**
     * Escape key handler
     */
    onEscape(callback) {
        const handler = (e) => {
            if (e.key === 'Escape') {
                callback(e);
            }
        };
        document.addEventListener('keydown', handler);
        return () => document.removeEventListener('keydown', handler);
    },

    /**
     * Keyboard shortcut
     */
    onShortcut(keys, callback) {
        const keyList = keys.toLowerCase().split('+');
        
        const handler = (e) => {
            const pressed = [];
            if (e.ctrlKey || e.metaKey) pressed.push('ctrl');
            if (e.altKey) pressed.push('alt');
            if (e.shiftKey) pressed.push('shift');
            pressed.push(e.key.toLowerCase());

            if (keyList.every(k => pressed.includes(k)) && pressed.length === keyList.length) {
                e.preventDefault();
                callback(e);
            }
        };

        document.addEventListener('keydown', handler);
        return () => document.removeEventListener('keydown', handler);
    },

    /**
     * Prevent default wrapper
     */
    prevent(handler) {
        return (e) => {
            e.preventDefault();
            return handler(e);
        };
    },

    /**
     * Stop propagation wrapper
     */
    stop(handler) {
        return (e) => {
            e.stopPropagation();
            return handler(e);
        };
    }
};

// ============================================================================
// DEBOUNCE & THROTTLE
// ============================================================================

/**
 * Debounce function
 */
function debounce(func, wait = 300, immediate = false) {
    let timeout;
    
    const debounced = function(...args) {
        const context = this;
        const later = () => {
            timeout = null;
            if (!immediate) func.apply(context, args);
        };
        
        const callNow = immediate && !timeout;
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
        
        if (callNow) func.apply(context, args);
    };

    debounced.cancel = () => {
        clearTimeout(timeout);
        timeout = null;
    };

    return debounced;
}

/**
 * Throttle function
 */
function throttle(func, limit = 100) {
    let inThrottle;
    let lastResult;

    const throttled = function(...args) {
        const context = this;
        
        if (!inThrottle) {
            lastResult = func.apply(context, args);
            inThrottle = true;
            
            setTimeout(() => {
                inThrottle = false;
            }, limit);
        }
        
        return lastResult;
    };

    throttled.cancel = () => {
        inThrottle = false;
    };

    return throttled;
}

/**
 * Request Animation Frame throttle
 */
function rafThrottle(func) {
    let ticking = false;
    
    return function(...args) {
        const context = this;
        
        if (!ticking) {
            requestAnimationFrame(() => {
                func.apply(context, args);
                ticking = false;
            });
            ticking = true;
        }
    };
}

// ============================================================================
// CLIPBOARD UTILITIES
// ============================================================================

const clipboard = {
    /**
     * Copy text to clipboard
     */
    async copy(text) {
        try {
            if (navigator.clipboard && navigator.clipboard.writeText) {
                await navigator.clipboard.writeText(text);
                return true;
            }

            // Fallback for older browsers
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.left = '-9999px';
            textarea.style.top = '-9999px';
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();

            const success = document.execCommand('copy');
            document.body.removeChild(textarea);
            return success;
        } catch (err) {
            console.error('Copy failed:', err);
            return false;
        }
    },

    /**
     * Read text from clipboard
     */
    async read() {
        try {
            if (navigator.clipboard && navigator.clipboard.readText) {
                return await navigator.clipboard.readText();
            }
            return null;
        } catch (err) {
            console.error('Read clipboard failed:', err);
            return null;
        }
    },

    /**
     * Copy element content
     */
    async copyElement(element) {
        if (is.string(element)) element = dom.$(element);
        if (!element) return false;

        const text = element.textContent || element.value || '';
        return this.copy(text);
    },

    /**
     * Copy with visual feedback
     */
    async copyWithFeedback(text, button) {
        const success = await this.copy(text);
        
        if (button) {
            if (is.string(button)) button = dom.$(button);
            if (button) {
                const originalHTML = button.innerHTML;
                button.innerHTML = success ? 'âœ“ Copied!' : 'âœ— Failed';
                button.disabled = true;
                
                setTimeout(() => {
                    button.innerHTML = originalHTML;
                    button.disabled = false;
                }, 2000);
            }
        }
        
        return success;
    }
};

// ============================================================================
// INTERNATIONALIZATION (i18n)
// ============================================================================

const i18n = {
    _locale: MXUI.DEFAULT_LANG,
    _translations: {},
    _fallback: 'en',
    _rtlLocales: ['fa', 'ar', 'he', 'ur'],

    /**
     * Initialize i18n
     */
    async init(locale = null) {
        this._locale = locale || storage.get('locale') || this._detectLocale();
        await this.loadTranslations(this._locale);
        this._applyDirection();
        return this;
    },

    /**
     * Detect browser locale
     */
    _detectLocale() {
        const browserLang = navigator.language || navigator.userLanguage;
        const shortLang = browserLang.split('-')[0];
        return MXUI.SUPPORTED_LANGS.includes(shortLang) ? shortLang : MXUI.DEFAULT_LANG;
    },

    /**
     * Load translations file
     */
    async loadTranslations(locale) {
        try {
            // Try to load from window if already loaded
            if (window[`lang_${locale}`]) {
                this._translations[locale] = window[`lang_${locale}`];
                return true;
            }

            // Load from file
            const response = await fetch(`./lang_${locale}.json`);
            if (response.ok) {
                this._translations[locale] = await response.json();
                return true;
            }

            // Fallback
            if (locale !== this._fallback) {
                return this.loadTranslations(this._fallback);
            }
            
            return false;
        } catch (err) {
            console.error(`Failed to load translations for ${locale}:`, err);
            if (locale !== this._fallback) {
                return this.loadTranslations(this._fallback);
            }
            return false;
        }
    },

    /**
     * Set locale
     */
    async setLocale(locale) {
        if (!MXUI.SUPPORTED_LANGS.includes(locale)) {
            console.warn(`Locale ${locale} not supported`);
            return false;
        }

        await this.loadTranslations(locale);
        this._locale = locale;
        storage.set('locale', locale);
        this._applyDirection();
        this._translatePage();
        
        events.trigger(document, 'locale:change', { locale });
        return true;
    },

    /**
     * Get current locale
     */
    getLocale() {
        return this._locale;
    },

    /**
     * Check if RTL
     */
    isRTL() {
        return this._rtlLocales.includes(this._locale);
    },

    /**
     * Apply text direction
     */
    _applyDirection() {
        const dir = this.isRTL() ? 'rtl' : 'ltr';
        document.documentElement.dir = dir;
        document.documentElement.lang = this._locale;
        document.body.classList.toggle('rtl', this.isRTL());
    },

    /**
     * Translate key
     */
    t(key, params = {}, defaultValue = null) {
        const translations = this._translations[this._locale] || this._translations[this._fallback] || {};
        
        // Get nested value
        let value = key.split('.').reduce((obj, k) => obj?.[k], translations);

        // Use fallback
        if (is.undefined(value) && this._locale !== this._fallback) {
            const fallbackTranslations = this._translations[this._fallback] || {};
            value = key.split('.').reduce((obj, k) => obj?.[k], fallbackTranslations);
        }

        // Use default or key
        if (is.undefined(value)) {
            value = defaultValue || key;
        }

        // Replace parameters
        if (is.string(value) && !is.empty(params)) {
            Object.entries(params).forEach(([param, replacement]) => {
                value = value.replace(new RegExp(`{${param}}`, 'g'), replacement);
            });
        }

        return value;
    },

    /**
     * Pluralize
     */
    plural(key, count, params = {}) {
        const translations = this._translations[this._locale] || {};
        const pluralKey = count === 1 ? `${key}.one` : `${key}.other`;
        return this.t(pluralKey, { ...params, count }, this.t(key, { ...params, count }));
    },

    /**
     * Translate all elements with data-i18n
     */
    _translatePage() {
        dom.$$('[data-i18n]').forEach(element => {
            const key = element.dataset.i18n;
            const attr = element.dataset.i18nAttr;
            
            if (attr) {
                element.setAttribute(attr, this.t(key));
            } else {
                element.textContent = this.t(key);
            }
        });

        dom.$$('[data-i18n-placeholder]').forEach(element => {
            element.placeholder = this.t(element.dataset.i18nPlaceholder);
        });

        dom.$$('[data-i18n-title]').forEach(element => {
            element.title = this.t(element.dataset.i18nTitle);
        });
    },

    /**
     * Format number according to locale
     */
    formatNumber(number, options = {}) {
        return new Intl.NumberFormat(this._locale, options).format(number);
    },

    /**
     * Format date according to locale
     */
    formatDate(date, options = {}) {
        const d = is.date(date) ? date : new Date(date);
        return new Intl.DateTimeFormat(this._locale, options).format(d);
    },

    /**
     * Format currency according to locale
     */
    formatCurrency(amount, currency = 'USD') {
        return new Intl.NumberFormat(this._locale, {
            style: 'currency',
            currency
        }).format(amount);
    },

    /**
     * Get available locales
     */
    getAvailableLocales() {
        return MXUI.SUPPORTED_LANGS;
    },

    /**
     * Check if locale is loaded
     */
    isLoaded(locale) {
        return !!this._translations[locale];
    }
};

// Shorthand
const __ = (key, params, defaultValue) => i18n.t(key, params, defaultValue);

// ============================================================================
// THEME UTILITIES
// ============================================================================

const theme = {
    _current: 'light',
    _storageKey: 'theme',
    _mediaQuery: window.matchMedia('(prefers-color-scheme: dark)'),

    /**
     * Initialize theme
     */
    init() {
        // Get saved theme or detect system preference
        this._current = storage.get(this._storageKey) || 
                       (this._mediaQuery.matches ? 'dark' : 'light');
        
        this.apply(this._current);

        // Listen for system theme changes
        this._mediaQuery.addEventListener('change', (e) => {
            if (!storage.has(this._storageKey)) {
                this.apply(e.matches ? 'dark' : 'light');
            }
        });

        return this;
    },

    /**
     * Get current theme
     */
    get() {
        return this._current;
    },

    /**
     * Set theme
     */
    set(themeName) {
        if (themeName !== 'light' && themeName !== 'dark') {
            console.warn(`Invalid theme: ${themeName}`);
            return;
        }

        this._current = themeName;
        storage.set(this._storageKey, themeName);
        this.apply(themeName);
        
        events.trigger(document, 'theme:change', { theme: themeName });
    },

    /**
     * Apply theme to document
     */
    apply(themeName) {
        document.documentElement.setAttribute('data-theme', themeName);
        document.body.classList.remove('light', 'dark');
        document.body.classList.add(themeName);

        // Update meta theme-color
        let metaTheme = document.querySelector('meta[name="theme-color"]');
        if (!metaTheme) {
            metaTheme = document.createElement('meta');
            metaTheme.name = 'theme-color';
            document.head.appendChild(metaTheme);
        }
        metaTheme.content = themeName === 'dark' ? '#0f0f23' : '#f0f4ff';
    },

    /**
     * Toggle theme
     */
    toggle() {
        this.set(this._current === 'dark' ? 'light' : 'dark');
        return this._current;
    },

    /**
     * Check if dark mode
     */
    isDark() {
        return this._current === 'dark';
    },

    /**
     * Check if light mode
     */
    isLight() {
        return this._current === 'light';
    },

    /**
     * Use system preference
     */
    useSystem() {
        storage.remove(this._storageKey);
        this.apply(this._mediaQuery.matches ? 'dark' : 'light');
    },

    /**
     * Get CSS variable value
     */
    getVar(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim();
    },

    /**
     * Set CSS variable value
     */
    setVar(name, value) {
        document.documentElement.style.setProperty(`--${name}`, value);
    }
};

// ============================================================================
// NOTIFICATION UTILITIES
// ============================================================================

const notify = {
    _container: null,
    _queue: [],
    _maxVisible: 5,
    _position: 'top-right',

    /**
     * Initialize notification container
     */
    init(options = {}) {
        this._position = options.position || 'top-right';
        this._maxVisible = options.maxVisible || 5;

        if (!this._container) {
            this._container = dom.create('div', {
                class: `toast-container ${this._position}`,
                id: 'toast-container'
            });
            document.body.appendChild(this._container);
        }

        return this;
    },

    /**
     * Show notification
     */
    show(options) {
        if (!this._container) this.init();

        const {
            title = '',
            message = '',
            type = 'info',
            duration = 5000,
            closable = true,
            icon = true,
            onClick = null,
            onClose = null
        } = is.string(options) ? { message: options } : options;

        // Create toast element
        const toast = dom.create('div', { class: 'toast' });

        // Icon
        if (icon) {
            const iconSvg = this._getIcon(type);
            const iconWrapper = dom.create('div', {
                class: `toast-icon ${type}`,
                html: iconSvg
            });
            toast.appendChild(iconWrapper);
        }

        // Content
        const content = dom.create('div', { class: 'toast-content' });
        
        if (title) {
            content.appendChild(dom.create('div', { class: 'toast-title', text: title }));
        }
        
        if (message) {
            content.appendChild(dom.create('div', { class: 'toast-message', text: message }));
        }
        
        toast.appendChild(content);

        // Close button
        if (closable) {
            const closeBtn = dom.create('button', {
                class: 'toast-close',
                html: '&times;',
                onClick: () => this._dismiss(toast, onClose)
            });
            toast.appendChild(closeBtn);
        }

        // Click handler
        if (onClick) {
            toast.style.cursor = 'pointer';
            toast.addEventListener('click', (e) => {
                if (!e.target.closest('.toast-close')) {
                    onClick();
                }
            });
        }

        // Progress bar
        if (duration > 0) {
            const progress = dom.create('div', { class: 'toast-progress' });
            progress.style.animationDuration = `${duration}ms`;
            toast.appendChild(progress);
        }

        // Add to container
        this._container.appendChild(toast);

        // Manage queue
        const visibleToasts = this._container.children;
        if (visibleToasts.length > this._maxVisible) {
            this._dismiss(visibleToasts[0]);
        }

        // Auto dismiss
        if (duration > 0) {
            setTimeout(() => this._dismiss(toast, onClose), duration);
        }

        return toast;
    },

    /**
     * Dismiss toast
     */
    _dismiss(toast, onClose = null) {
        if (!toast || !toast.parentNode) return;

        toast.classList.add('exiting');
        
        setTimeout(() => {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
            if (onClose) onClose();
        }, 300);
    },

    /**
     * Get icon SVG
     */
    _getIcon(type) {
        const icons = {
            success: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>',
            error: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
            warning: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
            info: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
        };
        return icons[type] || icons.info;
    },

    /**
     * Shorthand methods
     */
    success(message, options = {}) {
        return this.show({ ...options, message, type: 'success', title: options.title || i18n.t('common.success') });
    },

    error(message, options = {}) {
        return this.show({ ...options, message, type: 'error', title: options.title || i18n.t('common.error') });
    },

    warning(message, options = {}) {
        return this.show({ ...options, message, type: 'warning', title: options.title || i18n.t('common.warning') });
    },

    info(message, options = {}) {
        return this.show({ ...options, message, type: 'info', title: options.title || i18n.t('common.info') });
    },

    /**
     * Clear all toasts
     */
    clear() {
        if (this._container) {
            dom.empty(this._container);
        }
    }
};

// ============================================================================
// MODAL UTILITIES
// ============================================================================

const modal = {
    _stack: [],
    _backdrop: null,

    /**
     * Open modal
     */
    open(selector, options = {}) {
        const element = is.string(selector) ? dom.$(selector) : selector;
        if (!element) return;

        const {
            backdrop = true,
            keyboard = true,
            onOpen = null,
            onClose = null
        } = options;

        // Create backdrop if needed
        if (backdrop && !this._backdrop) {
            this._backdrop = dom.create('div', { class: 'modal-backdrop' });
            document.body.appendChild(this._backdrop);
        }

        // Show backdrop
        if (this._backdrop) {
            setTimeout(() => this._backdrop.classList.add('show'), 10);
        }

        // Show modal
        element.classList.add('show');
        document.body.classList.add('modal-open');
        document.body.style.overflow = 'hidden';

        // Store in stack
        this._stack.push({ element, options });

        // Keyboard handler
        if (keyboard) {
            element._escHandler = events.onEscape(() => this.close(element));
        }

        // Backdrop click
        if (backdrop) {
            element._backdropHandler = (e) => {
                if (e.target === element) {
                    this.close(element);
                }
            };
            element.addEventListener('click', element._backdropHandler);
        }

        // Focus trap
        this._trapFocus(element);

        // Callback
        if (onOpen) onOpen(element);

        events.trigger(element, 'modal:open');
    },

    /**
     * Close modal
     */
    close(selector) {
        const element = is.string(selector) ? dom.$(selector) : selector;
        if (!element) return;

        // Find in stack
        const index = this._stack.findIndex(m => m.element === element);
        if (index === -1) return;

        const { options } = this._stack[index];
        this._stack.splice(index, 1);

        // Hide modal
        element.classList.remove('show');

        // Remove handlers
        if (element._escHandler) element._escHandler();
        if (element._backdropHandler) {
            element.removeEventListener('click', element._backdropHandler);
        }

        // Hide backdrop if no more modals
        if (this._stack.length === 0) {
            if (this._backdrop) {
                this._backdrop.classList.remove('show');
            }
            document.body.classList.remove('modal-open');
            document.body.style.overflow = '';
        }

        // Callback
        if (options.onClose) options.onClose(element);

        events.trigger(element, 'modal:close');
    },

    /**
     * Close all modals
     */
    closeAll() {
        [...this._stack].forEach(({ element }) => this.close(element));
    },

    /**
     * Toggle modal
     */
    toggle(selector, options = {}) {
        const element = is.string(selector) ? dom.$(selector) : selector;
        if (!element) return;

        if (element.classList.contains('show')) {
            this.close(element);
        } else {
            this.open(element, options);
        }
    },

    /**
     * Trap focus inside modal
     */
    _trapFocus(element) {
        const focusable = element.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        
        if (focusable.length === 0) return;

        const firstFocusable = focusable[0];
        const lastFocusable = focusable[focusable.length - 1];

        firstFocusable.focus();

        element._focusTrap = (e) => {
            if (e.key !== 'Tab') return;

            if (e.shiftKey) {
                if (document.activeElement === firstFocusable) {
                    e.preventDefault();
                    lastFocusable.focus();
                }
            } else {
                if (document.activeElement === lastFocusable) {
                    e.preventDefault();
                    firstFocusable.focus();
                }
            }
        };

        element.addEventListener('keydown', element._focusTrap);
    },

    /**
     * Confirm dialog
     */
    confirm(options = {}) {
        return new Promise((resolve) => {
            const {
                title = i18n.t('modal.confirm'),
                message = i18n.t('modal.confirmMessage'),
                confirmText = i18n.t('common.confirm'),
                cancelText = i18n.t('common.cancel'),
                type = 'warning'
            } = is.string(options) ? { message: options } : options;

            const modalHtml = `
                <div class="modal" id="confirm-modal">
                    <div class="modal-content modal-sm">
                        <div class="modal-body modal-confirm">
                            <div class="modal-icon ${type}">
                                ${notify._getIcon(type)}
                            </div>
                            <h4 class="modal-title">${title}</h4>
                            <p class="text-secondary">${message}</p>
                        </div>
                        <div class="modal-footer">
                            <button class="btn btn-ghost" data-action="cancel">${cancelText}</button>
                            <button class="btn btn-${type === 'error' ? 'danger' : 'primary'}" data-action="confirm">${confirmText}</button>
                        </div>
                    </div>
                </div>
            `;

            const modalElement = dom.parseHTML(modalHtml);
            document.body.appendChild(modalElement);

            const cleanup = (result) => {
                this.close(modalElement);
                setTimeout(() => dom.remove(modalElement), 300);
                resolve(result);
            };

            modalElement.querySelector('[data-action="confirm"]').onclick = () => cleanup(true);
            modalElement.querySelector('[data-action="cancel"]').onclick = () => cleanup(false);

            this.open(modalElement, {
                onClose: () => cleanup(false)
            });
        });
    },

    /**
     * Alert dialog
     */
    alert(options = {}) {
        return new Promise((resolve) => {
            const {
                title = i18n.t('modal.alert'),
                message = '',
                buttonText = i18n.t('common.ok'),
                type = 'info'
            } = is.string(options) ? { message: options } : options;

            const modalHtml = `
                <div class="modal" id="alert-modal">
                    <div class="modal-content modal-sm">
                        <div class="modal-body modal-confirm">
                            <div class="modal-icon ${type}">
                                ${notify._getIcon(type)}
                            </div>
                            <h4 class="modal-title">${title}</h4>
                            <p class="text-secondary">${message}</p>
                        </div>
                        <div class="modal-footer" style="justify-content: center;">
                            <button class="btn btn-primary" data-action="ok">${buttonText}</button>
                        </div>
                    </div>
                </div>
            `;

            const modalElement = dom.parseHTML(modalHtml);
            document.body.appendChild(modalElement);

            const cleanup = () => {
                this.close(modalElement);
                setTimeout(() => dom.remove(modalElement), 300);
                resolve();
            };

            modalElement.querySelector('[data-action="ok"]').onclick = cleanup;

            this.open(modalElement, { onClose: cleanup });
        });
    },

    /**
     * Prompt dialog
     */
    prompt(options = {}) {
        return new Promise((resolve) => {
            const {
                title = i18n.t('modal.prompt'),
                message = '',
                placeholder = '',
                defaultValue = '',
                confirmText = i18n.t('common.submit'),
                cancelText = i18n.t('common.cancel'),
                type = 'text'
            } = is.string(options) ? { title: options } : options;

            const modalHtml = `
                <div class="modal" id="prompt-modal">
                    <div class="modal-content modal-sm">
                        <div class="modal-header">
                            <h4 class="modal-title">${title}</h4>
                            <button class="modal-close" data-action="close">&times;</button>
                        </div>
                        <div class="modal-body">
                            ${message ? `<p class="text-secondary mb-4">${message}</p>` : ''}
                            <input type="${type}" class="form-input" placeholder="${placeholder}" value="${defaultValue}">
                        </div>
                        <div class="modal-footer">
                            <button class="btn btn-ghost" data-action="cancel">${cancelText}</button>
                            <button class="btn btn-primary" data-action="confirm">${confirmText}</button>
                        </div>
                    </div>
                </div>
            `;

            const modalElement = dom.parseHTML(modalHtml);
            document.body.appendChild(modalElement);

            const input = modalElement.querySelector('input');

            const cleanup = (value) => {
                this.close(modalElement);
                setTimeout(() => dom.remove(modalElement), 300);
                resolve(value);
            };

            modalElement.querySelector('[data-action="confirm"]').onclick = () => cleanup(input.value);
            modalElement.querySelector('[data-action="cancel"]').onclick = () => cleanup(null);
            modalElement.querySelector('[data-action="close"]').onclick = () => cleanup(null);

            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') cleanup(input.value);
            });

            this.open(modalElement, {
                onClose: () => cleanup(null),
                onOpen: () => input.focus()
            });
        });
    }
};

// ============================================================================
// LOADING UTILITIES
// ============================================================================

const loading = {
    _overlay: null,
    _count: 0,

    /**
     * Show loading overlay
     */
    show(message = '') {
        this._count++;

        if (!this._overlay) {
            this._overlay = dom.create('div', {
                class: 'page-loader',
                id: 'page-loader',
                html: `
                    <div class="spinner spinner-lg"></div>
                    <div class="page-loader-text">${message || i18n.t('common.loading')}</div>
                `
            });
            document.body.appendChild(this._overlay);
        } else {
            if (message) {
                const textEl = this._overlay.querySelector('.page-loader-text');
                if (textEl) textEl.textContent = message;
            }
            this._overlay.style.display = 'flex';
        }
    },

    /**
     * Hide loading overlay
     */
    hide() {
        this._count = Math.max(0, this._count - 1);

        if (this._count === 0 && this._overlay) {
            this._overlay.style.display = 'none';
        }
    },

    /**
     * Force hide
     */
    forceHide() {
        this._count = 0;
        if (this._overlay) {
            this._overlay.style.display = 'none';
        }
    },

    /**
     * Show button loading state
     */
    button(button, loading = true) {
        if (is.string(button)) button = dom.$(button);
        if (!button) return;

        if (loading) {
            button.dataset.originalText = button.innerHTML;
            button.classList.add('btn-loading');
            button.disabled = true;
        } else {
            button.innerHTML = button.dataset.originalText || button.innerHTML;
            button.classList.remove('btn-loading');
            button.disabled = false;
        }
    },

    /**
     * Wrap async function with loading
     */
    async wrap(asyncFn, options = {}) {
        const { button, message, showOverlay = false } = options;

        if (button) this.button(button, true);
        if (showOverlay) this.show(message);

        try {
            return await asyncFn();
        } finally {
            if (button) this.button(button, false);
            if (showOverlay) this.hide();
        }
    }
};

// ============================================================================
// ANIMATION UTILITIES
// ============================================================================

const animate = {
    /**
     * Animate element with class
     */
    async run(element, animation, duration = 300) {
        if (is.string(element)) element = dom.$(element);
        if (!element) return;

        return new Promise((resolve) => {
            element.classList.add(animation);
            
            const handler = () => {
                element.classList.remove(animation);
                element.removeEventListener('animationend', handler);
                resolve(element);
            };

            element.addEventListener('animationend', handler);

            // Fallback
            setTimeout(handler, duration + 50);
        });
    },

    /**
     * Fade in
     */
    fadeIn(element, duration = 300) {
        return dom.fadeIn(element, duration);
    },

    /**
     * Fade out
     */
    fadeOut(element, duration = 300) {
        return dom.fadeOut(element, duration);
    },

    /**
     * Slide down
     */
    slideDown(element, duration = 300) {
        return dom.slideDown(element, duration);
    },

    /**
     * Slide up
     */
    slideUp(element, duration = 300) {
        return dom.slideUp(element, duration);
    },

    /**
     * Shake element
     */
    shake(element) {
        return this.run(element, 'shake', 500);
    },

    /**
     * Bounce element
     */
    bounce(element) {
        return this.run(element, 'bounce', 1000);
    },

    /**
     * Pulse element
     */
    pulse(element) {
        return this.run(element, 'pulse', 2000);
    },

    /**
     * Stagger animations for list
     */
    stagger(elements, animation, delay = 100) {
        if (is.string(elements)) elements = dom.$$(elements);
        
        elements.forEach((element, index) => {
            setTimeout(() => {
                element.classList.add(animation);
            }, index * delay);
        });
    },

    /**
     * Number counter animation
     */
    counter(element, target, duration = 1000) {
        if (is.string(element)) element = dom.$(element);
        if (!element) return;

        const start = parseInt(element.textContent, 10) || 0;
        const increment = (target - start) / (duration / 16);
        let current = start;

        const step = () => {
            current += increment;
            
            if ((increment > 0 && current >= target) || (increment < 0 && current <= target)) {
                element.textContent = num.format(target);
            } else {
                element.textContent = num.format(Math.round(current));
                requestAnimationFrame(step);
            }
        };

        requestAnimationFrame(step);
    },

    /**
     * Typewriter effect
     */
    typewriter(element, text, speed = 50) {
        if (is.string(element)) element = dom.$(element);
        if (!element) return Promise.resolve();

        return new Promise((resolve) => {
            element.textContent = '';
            let i = 0;

            const type = () => {
                if (i < text.length) {
                    element.textContent += text.charAt(i);
                    i++;
                    setTimeout(type, speed);
                } else {
                    resolve();
                }
            };

            type();
        });
    }
};

// ============================================================================
// EXPORT
// ============================================================================

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        dom, events, debounce, throttle, rafThrottle,
        clipboard, i18n, __, theme, notify, modal, loading, animate
    };
}

// Global export
Object.assign(window, {
    dom, events, debounce, throttle, rafThrottle,
    clipboard, i18n, __, theme, notify, modal, loading, animate
});