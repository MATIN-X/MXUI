/**
 * MX-UI VPN Panel - Router
 * router.js - SPA Routing, Navigation, History
 */

'use strict';

// ============================================================================
// ROUTER CLASS
// ============================================================================

class Router {
    constructor(options = {}) {
        this.routes = new Map();
        this.currentRoute = null;
        this.params = {};
        this.query = {};
        this.container = options.container || '#app';
        this.notFound = options.notFound || this.defaultNotFound;
        this.beforeEach = options.beforeEach || null;
        this.afterEach = options.afterEach || null;
        this.base = options.base || '';
    }

    // Register a route
    route(path, handler, options = {}) {
        const pattern = this.pathToRegex(path);
        this.routes.set(path, { pattern, handler, options, path });
        return this;
    }

    // Convert path to regex
    pathToRegex(path) {
        const pattern = path
            .replace(/\//g, '\\/')
            .replace(/:(\w+)/g, '(?<$1>[^/]+)')
            .replace(/\*/g, '.*');
        return new RegExp(`^${pattern}$`);
    }

    // Navigate to path
    async navigate(path, options = {}) {
        const fullPath = this.base + path;
        
        // Parse query string
        const [pathname, queryString] = fullPath.split('?');
        this.query = this.parseQuery(queryString);

        // Find matching route
        let matched = null;
        for (const [routePath, route] of this.routes) {
            const match = pathname.match(route.pattern);
            if (match) {
                matched = route;
                this.params = match.groups || {};
                break;
            }
        }

        // Before navigation hook
        if (this.beforeEach) {
            const result = await this.beforeEach(matched, this.currentRoute);
            if (result === false) return;
            if (typeof result === 'string') {
                return this.navigate(result);
            }
        }

        // Update URL
        if (!options.replace) {
            history.pushState({ path: fullPath }, '', '#' + pathname);
        } else {
            history.replaceState({ path: fullPath }, '', '#' + pathname);
        }

        // Execute handler
        const container = document.querySelector(this.container);
        if (!container) return;

        try {
            if (matched) {
                this.currentRoute = matched;
                const content = await matched.handler(this.params, this.query);
                if (typeof content === 'string') {
                    container.innerHTML = content;
                } else if (content instanceof Element) {
                    container.innerHTML = '';
                    container.appendChild(content);
                }
            } else {
                container.innerHTML = await this.notFound(pathname);
            }
        } catch (error) {
            console.error('Router error:', error);
            container.innerHTML = this.errorPage(error);
        }

        // After navigation hook
        if (this.afterEach) {
            this.afterEach(matched, this.params, this.query);
        }

        // Scroll to top
        window.scrollTo(0, 0);
    }

    // Parse query string
    parseQuery(queryString) {
        if (!queryString) return {};
        const params = new URLSearchParams(queryString);
        const result = {};
        for (const [key, value] of params) {
            result[key] = value;
        }
        return result;
    }

    // Start listening for navigation
    start() {
        // Handle hash changes
        window.addEventListener('hashchange', () => {
            const path = location.hash.slice(1) || '/';
            this.navigate(path, { replace: true });
        });

        // Handle link clicks
        document.addEventListener('click', (e) => {
            const link = e.target.closest('a[href^="#"]');
            if (link) {
                e.preventDefault();
                const path = link.getAttribute('href').slice(1);
                this.navigate(path);
            }
        });

        // Handle popstate
        window.addEventListener('popstate', (e) => {
            const path = location.hash.slice(1) || '/';
            this.navigate(path, { replace: true });
        });

        // Initial navigation
        const initialPath = location.hash.slice(1) || '/';
        this.navigate(initialPath, { replace: true });

        return this;
    }

    // Go back
    back() {
        history.back();
    }

    // Go forward
    forward() {
        history.forward();
    }

    // Default 404 page
    defaultNotFound(path) {
        return `
            <div class="error-page">
                <h1>404</h1>
                <p>صفحه مورد نظر یافت نشد</p>
                <p><code>${path}</code></p>
                <a href="#/" class="btn btn-primary">بازگشت به خانه</a>
            </div>
        `;
    }

    // Error page
    errorPage(error) {
        return `
            <div class="error-page">
                <h1>خطا</h1>
                <p>${error.message}</p>
                <a href="#/" class="btn btn-primary">بازگشت به خانه</a>
            </div>
        `;
    }

    // Get current path
    get path() {
        return location.hash.slice(1) || '/';
    }
}

// ============================================================================
// ROUTE GUARDS
// ============================================================================

const RouteGuards = {
    // Check if user is authenticated
    requireAuth: async (to, from) => {
        if (!state?.get('isAuthenticated')) {
            Notification?.warning('لطفاً وارد شوید');
            return '/login';
        }
        return true;
    },

    // Check if user is admin/owner
    requireAdmin: async (to, from) => {
        const isOwner = state?.get('isOwner');
        const isAdmin = state?.get('admin');
        if (!isOwner && !isAdmin) {
            Notification?.error('دسترسی غیرمجاز');
            return '/';
        }
        return true;
    },

    // Check if user is owner only
    requireOwner: async (to, from) => {
        if (!state?.get('isOwner')) {
            Notification?.error('فقط مالک دسترسی دارد');
            return '/';
        }
        return true;
    },

    // Redirect if already authenticated
    guestOnly: async (to, from) => {
        if (state?.get('isAuthenticated')) {
            return '/';
        }
        return true;
    }
};

// ============================================================================
// NAVIGATION HELPERS
// ============================================================================

// Navigate to path
function navigateTo(path, options) {
    if (window.router) {
        router.navigate(path, options);
    } else {
        location.hash = path;
    }
}

// Go back
function goBack() {
    if (window.router) {
        router.back();
    } else {
        history.back();
    }
}

// Redirect
function redirect(path) {
    navigateTo(path, { replace: true });
}

// ============================================================================
// EXPORTS
// ============================================================================

window.Router = Router;
window.RouteGuards = RouteGuards;
window.navigateTo = navigateTo;
window.goBack = goBack;
window.redirect = redirect;
