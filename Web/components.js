/**
 * MXUI VPN Panel - UI Components
 * components.js - Sidebar, Modals, Cards, Notifications
 */

'use strict';

// ============================================================================
// SIDEBAR COMPONENT
// ============================================================================

class Sidebar {
    constructor(options = {}) {
        this.element = null;
        this.collapsed = storage.get('sidebarCollapsed') || false;
        this.items = options.items || [];
        this.onSelect = options.onSelect || (() => {});
    }

    render() {
        const sidebar = document.createElement('aside');
        sidebar.className = `sidebar ${this.collapsed ? 'collapsed' : ''}`;
        sidebar.innerHTML = `
            <div class="sidebar-header">
                <div class="logo">
                    <span class="logo-icon">🔐</span>
                    <span class="logo-text">MXUI Panel</span>
                </div>
                <button class="sidebar-toggle" onclick="sidebar.toggle()">
                    <span>☰</span>
                </button>
            </div>
            <nav class="sidebar-nav">
                ${this.items.map(item => this.renderItem(item)).join('')}
            </nav>
            <div class="sidebar-footer">
                <div class="user-info">
                    <span class="user-avatar">👤</span>
                    <span class="user-name">${state.get('admin')?.username || 'Admin'}</span>
                </div>
            </div>
        `;
        this.element = sidebar;
        return sidebar;
    }

    renderItem(item) {
        if (item.divider) return '<div class="nav-divider"></div>';
        const active = state.get('currentPage') === item.id ? 'active' : '';
        return `
            <a href="#${item.path || item.id}" class="nav-item ${active}" data-page="${item.id}">
                <span class="nav-icon">${item.icon}</span>
                <span class="nav-text">${item.label}</span>
                ${item.badge ? `<span class="nav-badge">${item.badge}</span>` : ''}
            </a>
        `;
    }

    toggle() {
        this.collapsed = !this.collapsed;
        this.element?.classList.toggle('collapsed', this.collapsed);
        storage.set('sidebarCollapsed', this.collapsed);
    }

    setActive(pageId) {
        this.element?.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.page === pageId);
        });
    }
}

// ============================================================================
// MODAL COMPONENT
// ============================================================================

class Modal {
    constructor(options = {}) {
        this.title = options.title || '';
        this.content = options.content || '';
        this.size = options.size || 'medium'; // small, medium, large, fullscreen
        this.closable = options.closable !== false;
        this.onClose = options.onClose || (() => {});
        this.onConfirm = options.onConfirm || null;
        this.confirmText = options.confirmText || 'تایید';
        this.cancelText = options.cancelText || 'لغو';
        this.element = null;
    }

    render() {
        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal modal-${this.size}">
                <div class="modal-header">
                    <h3 class="modal-title">${this.title}</h3>
                    ${this.closable ? '<button class="modal-close" onclick="this.closest(\'.modal-overlay\').remove()">✕</button>' : ''}
                </div>
                <div class="modal-body">
                    ${typeof this.content === 'string' ? this.content : ''}
                </div>
                ${this.onConfirm ? `
                    <div class="modal-footer">
                        <button class="btn btn-secondary modal-cancel">${this.cancelText}</button>
                        <button class="btn btn-primary modal-confirm">${this.confirmText}</button>
                    </div>
                ` : ''}
            </div>
        `;

        if (typeof this.content !== 'string') {
            modal.querySelector('.modal-body').appendChild(this.content);
        }

        modal.querySelector('.modal-cancel')?.addEventListener('click', () => this.close());
        modal.querySelector('.modal-confirm')?.addEventListener('click', () => {
            if (this.onConfirm) this.onConfirm();
            this.close();
        });

        if (this.closable) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) this.close();
            });
        }

        this.element = modal;
        return modal;
    }

    show() {
        document.body.appendChild(this.render());
        requestAnimationFrame(() => this.element.classList.add('active'));
        return this;
    }

    close() {
        this.element?.classList.remove('active');
        setTimeout(() => {
            this.element?.remove();
            this.onClose();
        }, 300);
    }

    static confirm(message, onConfirm) {
        return new Modal({
            title: 'تایید',
            content: `<p>${message}</p>`,
            size: 'small',
            onConfirm
        }).show();
    }

    static alert(message, title = 'توجه') {
        return new Modal({
            title,
            content: `<p>${message}</p>`,
            size: 'small'
        }).show();
    }
}

// ============================================================================
// CARD COMPONENT
// ============================================================================

class Card {
    constructor(options = {}) {
        this.title = options.title || '';
        this.icon = options.icon || '';
        this.value = options.value || '';
        this.subtitle = options.subtitle || '';
        this.trend = options.trend || null; // { value: 5, up: true }
        this.color = options.color || 'primary';
        this.onClick = options.onClick || null;
    }

    render() {
        const card = document.createElement('div');
        card.className = `stat-card stat-card-${this.color} ${this.onClick ? 'clickable' : ''}`;
        card.innerHTML = `
            ${this.icon ? `<div class="card-icon">${this.icon}</div>` : ''}
            <div class="card-content">
                <div class="card-title">${this.title}</div>
                <div class="card-value">${this.value}</div>
                ${this.subtitle ? `<div class="card-subtitle">${this.subtitle}</div>` : ''}
                ${this.trend ? `
                    <div class="card-trend ${this.trend.up ? 'up' : 'down'}">
                        ${this.trend.up ? '↑' : '↓'} ${this.trend.value}%
                    </div>
                ` : ''}
            </div>
        `;

        if (this.onClick) {
            card.addEventListener('click', this.onClick);
        }

        return card;
    }
}

// ============================================================================
// NOTIFICATION COMPONENT
// ============================================================================

class Notification {
    static container = null;

    static init() {
        if (!this.container) {
            this.container = document.createElement('div');
            this.container.className = 'notification-container';
            document.body.appendChild(this.container);
        }
    }

    static show(message, type = 'info', duration = 5000) {
        this.init();

        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        
        const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
        notification.innerHTML = `
            <span class="notification-icon">${icons[type] || icons.info}</span>
            <span class="notification-message">${message}</span>
            <button class="notification-close">✕</button>
        `;

        notification.querySelector('.notification-close').addEventListener('click', () => {
            this.hide(notification);
        });

        this.container.appendChild(notification);
        requestAnimationFrame(() => notification.classList.add('show'));

        if (duration > 0) {
            setTimeout(() => this.hide(notification), duration);
        }

        return notification;
    }

    static hide(notification) {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }

    static success(message, duration) { return this.show(message, 'success', duration); }
    static error(message, duration) { return this.show(message, 'error', duration); }
    static warning(message, duration) { return this.show(message, 'warning', duration); }
    static info(message, duration) { return this.show(message, 'info', duration); }
}

// ============================================================================
// TABLE COMPONENT
// ============================================================================

class DataTable {
    constructor(options = {}) {
        this.columns = options.columns || [];
        this.data = options.data || [];
        this.sortable = options.sortable !== false;
        this.searchable = options.searchable !== false;
        this.paginated = options.paginated !== false;
        this.pageSize = options.pageSize || 10;
        this.currentPage = 1;
        this.sortColumn = null;
        this.sortDir = 'asc';
        this.searchTerm = '';
        this.onRowClick = options.onRowClick || null;
        this.element = null;
    }

    render() {
        const table = document.createElement('div');
        table.className = 'data-table-container';
        table.innerHTML = `
            ${this.searchable ? `
                <div class="table-toolbar">
                    <input type="text" class="table-search" placeholder="جستجو..." />
                </div>
            ` : ''}
            <table class="data-table">
                <thead>
                    <tr>
                        ${this.columns.map(col => `
                            <th ${this.sortable && col.sortable !== false ? 'class="sortable"' : ''} data-field="${col.field}">
                                ${col.label}
                                ${this.sortable && col.sortable !== false ? '<span class="sort-icon"></span>' : ''}
                            </th>
                        `).join('')}
                    </tr>
                </thead>
                <tbody></tbody>
            </table>
            ${this.paginated ? '<div class="table-pagination"></div>' : ''}
        `;

        this.element = table;
        this.bindEvents();
        this.refresh();
        return table;
    }

    bindEvents() {
        this.element.querySelector('.table-search')?.addEventListener('input', (e) => {
            this.searchTerm = e.target.value;
            this.currentPage = 1;
            this.refresh();
        });

        this.element.querySelectorAll('th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const field = th.dataset.field;
                if (this.sortColumn === field) {
                    this.sortDir = this.sortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    this.sortColumn = field;
                    this.sortDir = 'asc';
                }
                this.refresh();
            });
        });
    }

    refresh() {
        let data = [...this.data];

        // Search
        if (this.searchTerm) {
            const term = this.searchTerm.toLowerCase();
            data = data.filter(row => 
                this.columns.some(col => 
                    String(row[col.field]).toLowerCase().includes(term)
                )
            );
        }

        // Sort
        if (this.sortColumn) {
            data.sort((a, b) => {
                const aVal = a[this.sortColumn];
                const bVal = b[this.sortColumn];
                const cmp = aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
                return this.sortDir === 'asc' ? cmp : -cmp;
            });
        }

        // Paginate
        const total = data.length;
        const totalPages = Math.ceil(total / this.pageSize);
        const start = (this.currentPage - 1) * this.pageSize;
        const pageData = this.paginated ? data.slice(start, start + this.pageSize) : data;

        // Render body
        const tbody = this.element.querySelector('tbody');
        tbody.innerHTML = pageData.map(row => `
            <tr ${this.onRowClick ? 'class="clickable"' : ''}>
                ${this.columns.map(col => `
                    <td>${col.render ? col.render(row[col.field], row) : row[col.field]}</td>
                `).join('')}
            </tr>
        `).join('');

        if (this.onRowClick) {
            tbody.querySelectorAll('tr').forEach((tr, i) => {
                tr.addEventListener('click', () => this.onRowClick(pageData[i]));
            });
        }

        // Render pagination
        if (this.paginated) {
            this.element.querySelector('.table-pagination').innerHTML = `
                <span>صفحه ${this.currentPage} از ${totalPages} (${total} مورد)</span>
                <div class="pagination-btns">
                    <button ${this.currentPage <= 1 ? 'disabled' : ''} onclick="this.closest('.data-table-container').__table.prevPage()">قبلی</button>
                    <button ${this.currentPage >= totalPages ? 'disabled' : ''} onclick="this.closest('.data-table-container').__table.nextPage()">بعدی</button>
                </div>
            `;
            this.element.__table = this;
        }
    }

    setData(data) {
        this.data = data;
        this.refresh();
    }

    prevPage() { if (this.currentPage > 1) { this.currentPage--; this.refresh(); } }
    nextPage() { this.currentPage++; this.refresh(); }
}

// ============================================================================
// EXPORTS
// ============================================================================

window.Sidebar = Sidebar;
window.Modal = Modal;
window.Card = Card;
window.Notification = Notification;
window.DataTable = DataTable;
