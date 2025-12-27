/**
 * MX-UI VPN Panel - Theme
 * theme.js - Dark/Light Mode, Theme Customization
 */

'use strict';

// ============================================================================
// THEME MANAGER
// ============================================================================

class ThemeManager {
    constructor() {
        this.current = storage.get('theme') || 'dark';
        this.colors = storage.get('themeColors') || {};
        this.init();
    }

    init() {
        this.apply(this.current);
        this.watchSystemTheme();
    }

    // Apply theme
    apply(theme) {
        this.current = theme;
        document.documentElement.setAttribute('data-theme', theme);
        storage.set('theme', theme);

        // Update meta theme-color
        const metaTheme = document.querySelector('meta[name="theme-color"]');
        if (metaTheme) {
            metaTheme.content = theme === 'dark' ? '#0f172a' : '#ffffff';
        }

        this.emit('change', theme);
    }

    // Toggle theme
    toggle() {
        const newTheme = this.current === 'dark' ? 'light' : 'dark';
        this.apply(newTheme);
        return newTheme;
    }

    // Check if dark mode
    isDark() {
        return this.current === 'dark';
    }

    // Watch system theme preference
    watchSystemTheme() {
        if (window.matchMedia) {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
            mediaQuery.addEventListener('change', (e) => {
                if (storage.get('useSystemTheme')) {
                    this.apply(e.matches ? 'dark' : 'light');
                }
            });
        }
    }

    // Use system theme
    useSystem() {
        storage.set('useSystemTheme', true);
        if (window.matchMedia) {
            const isDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
            this.apply(isDark ? 'dark' : 'light');
        }
    }

    // Set custom color
    setColor(name, value) {
        this.colors[name] = value;
        storage.set('themeColors', this.colors);
        document.documentElement.style.setProperty(`--${name}`, value);
    }

    // Get color
    getColor(name) {
        return getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim();
    }

    // Reset colors
    resetColors() {
        this.colors = {};
        storage.remove('themeColors');
        // Remove custom properties
        const root = document.documentElement;
        for (const prop of root.style) {
            if (prop.startsWith('--')) {
                root.style.removeProperty(prop);
            }
        }
    }

    // Event emitter
    emit(event, data) {
        document.dispatchEvent(new CustomEvent(`theme:${event}`, { detail: data }));
    }

    on(event, handler) {
        document.addEventListener(`theme:${event}`, (e) => handler(e.detail));
    }
}

// ============================================================================
// THEME PRESETS
// ============================================================================

const ThemePresets = {
    default: {
        name: 'پیش‌فرض',
        primary: '#6366f1',
        secondary: '#ec4899',
        accent: '#06b6d4'
    },
    ocean: {
        name: 'اقیانوس',
        primary: '#0ea5e9',
        secondary: '#14b8a6',
        accent: '#8b5cf6'
    },
    sunset: {
        name: 'غروب',
        primary: '#f97316',
        secondary: '#ef4444',
        accent: '#facc15'
    },
    forest: {
        name: 'جنگل',
        primary: '#22c55e',
        secondary: '#10b981',
        accent: '#84cc16'
    },
    purple: {
        name: 'بنفش',
        primary: '#8b5cf6',
        secondary: '#a855f7',
        accent: '#ec4899'
    }
};

// ============================================================================
// THEME TOGGLE BUTTON
// ============================================================================

class ThemeToggle {
    constructor(theme) {
        this.theme = theme;
        this.element = null;
    }

    render() {
        const btn = document.createElement('button');
        btn.className = 'theme-toggle';
        btn.setAttribute('aria-label', 'تغییر تم');
        btn.innerHTML = this.getIcon();
        btn.addEventListener('click', () => {
            this.theme.toggle();
            btn.innerHTML = this.getIcon();
        });
        this.element = btn;
        return btn;
    }

    getIcon() {
        return this.theme.isDark() 
            ? '<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>'
            : '<svg viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/></svg>';
    }

    mount(selector) {
        const container = document.querySelector(selector);
        if (container) {
            container.appendChild(this.render());
        }
    }
}

// ============================================================================
// THEME SELECTOR
// ============================================================================

class ThemeSelector {
    constructor(theme, presets = ThemePresets) {
        this.theme = theme;
        this.presets = presets;
    }

    render() {
        const container = document.createElement('div');
        container.className = 'theme-selector';
        container.innerHTML = `
            <div class="theme-selector-header">
                <span>انتخاب تم رنگی</span>
            </div>
            <div class="theme-presets">
                ${Object.entries(this.presets).map(([key, preset]) => `
                    <button class="theme-preset" data-preset="${key}" 
                            style="--preset-primary: ${preset.primary}">
                        <span class="preset-preview">
                            <span style="background: ${preset.primary}"></span>
                            <span style="background: ${preset.secondary}"></span>
                            <span style="background: ${preset.accent}"></span>
                        </span>
                        <span class="preset-name">${preset.name}</span>
                    </button>
                `).join('')}
            </div>
            <div class="theme-options">
                <label class="theme-option">
                    <input type="checkbox" id="useSystemTheme" ${storage.get('useSystemTheme') ? 'checked' : ''}>
                    <span>استفاده از تم سیستم</span>
                </label>
            </div>
        `;

        container.querySelectorAll('.theme-preset').forEach(btn => {
            btn.addEventListener('click', () => {
                const preset = this.presets[btn.dataset.preset];
                this.applyPreset(preset);
            });
        });

        container.querySelector('#useSystemTheme')?.addEventListener('change', (e) => {
            if (e.target.checked) {
                this.theme.useSystem();
            }
            storage.set('useSystemTheme', e.target.checked);
        });

        return container;
    }

    applyPreset(preset) {
        this.theme.setColor('primary', preset.primary);
        this.theme.setColor('secondary', preset.secondary);
        this.theme.setColor('accent', preset.accent);
    }
}

// ============================================================================
// EXPORTS
// ============================================================================

window.ThemeManager = ThemeManager;
window.ThemePresets = ThemePresets;
window.ThemeToggle = ThemeToggle;
window.ThemeSelector = ThemeSelector;

// Auto-initialize
window.theme = new ThemeManager();
