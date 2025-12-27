/**
 * ============================================================================
 * MXUI VPN Panel - UI Components
 * ui.js - Modals, Tables, Forms, Charts, Notifications, Drag & Drop
 * ============================================================================
 */

'use strict';

// ============================================================================
// MODAL SYSTEM
// ============================================================================

class Modal {
    static instances = new Map();
    static zIndex = 1000;

    /**
     * Open modal
     */
    static open(options = {}) {
        const id = options.id || `modal-${Date.now()}`;
        
        if (this.instances.has(id)) {
            this.instances.get(id).show();
            return id;
        }
        
        const modal = document.createElement('div');
        modal.id = id;
        modal.className = `modal ${options.class || ''}`;
        modal.style.zIndex = ++this.zIndex;
        
        const sizeClass = options.size ? `modal-${options.size}` : '';
        
        modal.innerHTML = `
            <div class="modal-backdrop" onclick="Modal.close('${id}')"></div>
            <div class="modal-dialog ${sizeClass}">
                <div class="modal-content">
                    ${options.title ? `
                        <div class="modal-header">
                            <h3 class="modal-title">${options.title}</h3>
                            <button class="modal-close" onclick="Modal.close('${id}')">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M18 6L6 18M6 6l12 12"/>
                                </svg>
                            </button>
                        </div>
                    ` : ''}
                    <div class="modal-body">
                        ${options.content || ''}
                    </div>
                    ${options.footer !== false ? `
                        <div class="modal-footer">
                            ${options.footer || `
                                <button class="btn btn-outline" onclick="Modal.close('${id}')">${i18n.t('common.cancel')}</button>
                                ${options.confirmText ? `
                                    <button class="btn btn-primary" onclick="Modal.handleConfirm('${id}')">${options.confirmText}</button>
                                ` : ''}
                            `}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        document.body.classList.add('modal-open');
        
        // Store instance
        this.instances.set(id, {
            element: modal,
            options,
            show: () => {
                modal.classList.add('show');
                document.body.classList.add('modal-open');
            },
            hide: () => {
                modal.classList.remove('show');
            }
        });
        
        // Trigger animation
        requestAnimationFrame(() => {
            modal.classList.add('show');
        });
        
        // onOpen callback
        if (options.onOpen) {
            setTimeout(() => options.onOpen(modal), 300);
        }
        
        return id;
    }

    /**
     * Close modal
     */
    static close(id) {
        const instance = this.instances.get(id);
        if (!instance) return;
        
        const { element, options } = instance;
        
        // onClose callback
        if (options.onClose && options.onClose() === false) {
            return;
        }
        
        element.classList.remove('show');
        
        setTimeout(() => {
            element.remove();
            this.instances.delete(id);
            
            if (this.instances.size === 0) {
                document.body.classList.remove('modal-open');
            }
        }, 300);
    }

    /**
     * Close all modals
     */
    static closeAll() {
        for (const id of this.instances.keys()) {
            this.close(id);
        }
    }

    /**
     * Handle confirm button
     */
    static handleConfirm(id) {
        const instance = this.instances.get(id);
        if (!instance) return;
        
        if (instance.options.onConfirm) {
            const result = instance.options.onConfirm();
            if (result !== false) {
                this.close(id);
            }
        } else {
            this.close(id);
        }
    }

    /**
     * Confirm dialog
     */
    static confirm(options = {}) {
        return new Promise((resolve) => {
            const id = this.open({
                title: options.title || i18n.t('common.confirm'),
                content: `
                    <div class="confirm-dialog ${options.type || ''}">
                        ${options.icon || ''}
                        <p>${options.message}</p>
                    </div>
                `,
                confirmText: options.confirmText || i18n.t('common.confirm'),
                onConfirm: () => {
                    resolve(true);
                    return true;
                },
                onClose: () => {
                    resolve(false);
                    return true;
                }
            });
        });
    }

    /**
     * Alert dialog
     */
    static alert(options = {}) {
        return new Promise((resolve) => {
            const id = this.open({
                title: options.title || i18n.t('common.alert'),
                content: `<p>${options.message}</p>`,
                footer: `<button class="btn btn-primary" onclick="Modal.close('${id}'); this.resolve && this.resolve();">${i18n.t('common.ok')}</button>`,
                onClose: () => {
                    resolve();
                    return true;
                }
            });
        });
    }

    /**
     * Prompt dialog
     */
    static prompt(options = {}) {
        return new Promise((resolve) => {
            const inputId = `prompt-input-${Date.now()}`;
            const id = this.open({
                title: options.title || i18n.t('common.input'),
                content: `
                    <div class="form-group">
                        ${options.label ? `<label for="${inputId}">${options.label}</label>` : ''}
                        <input type="${options.type || 'text'}" id="${inputId}" 
                            class="form-control" value="${options.value || ''}"
                            placeholder="${options.placeholder || ''}">
                    </div>
                `,
                confirmText: options.confirmText || i18n.t('common.ok'),
                onConfirm: () => {
                    const value = document.getElementById(inputId).value;
                    resolve(value);
                    return true;
                },
                onClose: () => {
                    resolve(null);
                    return true;
                },
                onOpen: () => {
                    document.getElementById(inputId).focus();
                }
            });
        });
    }
}

// ============================================================================
// DATA TABLE
// ============================================================================

class DataTable {
    constructor(selector, options = {}) {
        this.container = typeof selector === 'string' 
            ? document.querySelector(selector) 
            : selector;
        
        this.options = {
            columns: options.columns || [],
            data: options.data || [],
            pageSize: options.pageSize || 20,
            currentPage: 1,
            sortColumn: options.sortColumn || null,
            sortOrder: options.sortOrder || 'asc',
            selectable: options.selectable || false,
            searchable: options.searchable !== false,
            onSelect: options.onSelect || null,
            onRowClick: options.onRowClick || null,
            emptyText: options.emptyText || i18n.t('common.noData'),
            loadingText: options.loadingText || i18n.t('common.loading'),
            fetchData: options.fetchData || null,
            ...options
        };
        
        this.selectedIds = new Set();
        this.filteredData = [];
        this.searchQuery = '';
        
        this.init();
    }

    init() {
        this.render();
        this.bindEvents();
    }

    render() {
        if (!this.container) return;
        
        const { columns, selectable } = this.options;
        
        this.container.innerHTML = `
            <div class="datatable-wrapper">
                ${this.options.searchable ? `
                    <div class="datatable-toolbar">
                        <div class="datatable-search">
                            <input type="text" placeholder="${i18n.t('common.search')}" 
                                class="form-control" id="dt-search-${this.container.id}">
                        </div>
                        <div class="datatable-actions">
                            <button class="btn btn-sm btn-outline" onclick="this.closest('.datatable-wrapper').dataTable.refresh()">
                                ${i18n.t('common.refresh')}
                            </button>
                        </div>
                    </div>
                ` : ''}
                <div class="datatable-container">
                    <table class="datatable">
                        <thead>
                            <tr>
                                ${selectable ? `<th class="dt-select"><input type="checkbox" class="select-all"></th>` : ''}
                                ${columns.map(col => `
                                    <th class="${col.sortable !== false ? 'sortable' : ''}" 
                                        data-column="${col.key}"
                                        style="${col.width ? `width: ${col.width}` : ''}">
                                        ${col.title}
                                        ${col.sortable !== false ? '<span class="sort-icon"></span>' : ''}
                                    </th>
                                `).join('')}
                            </tr>
                        </thead>
                        <tbody class="datatable-body">
                        </tbody>
                    </table>
                </div>
                <div class="datatable-footer">
                    <div class="datatable-info"></div>
                    <div class="datatable-pagination"></div>
                </div>
            </div>
        `;
        
        // Store reference
        this.container.querySelector('.datatable-wrapper').dataTable = this;
        
        this.tbody = this.container.querySelector('.datatable-body');
        this.pagination = this.container.querySelector('.datatable-pagination');
        this.info = this.container.querySelector('.datatable-info');
        
        this.loadData();
    }

    bindEvents() {
        // Search
        const searchInput = this.container.querySelector(`#dt-search-${this.container.id}`);
        if (searchInput) {
            searchInput.addEventListener('input', debounce((e) => {
                this.searchQuery = e.target.value;
                this.options.currentPage = 1;
                this.loadData();
            }, 300));
        }
        
        // Sort
        this.container.querySelectorAll('th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const column = th.dataset.column;
                if (this.options.sortColumn === column) {
                    this.options.sortOrder = this.options.sortOrder === 'asc' ? 'desc' : 'asc';
                } else {
                    this.options.sortColumn = column;
                    this.options.sortOrder = 'asc';
                }
                this.loadData();
                this.updateSortIndicators();
            });
        });
        
        // Select all
        const selectAll = this.container.querySelector('.select-all');
        if (selectAll) {
            selectAll.addEventListener('change', (e) => {
                this.toggleSelectAll(e.target.checked);
            });
        }
    }

    async loadData() {
        this.showLoading();
        
        try {
            let data;
            
            if (this.options.fetchData) {
                const response = await this.options.fetchData({
                    page: this.options.currentPage,
                    pageSize: this.options.pageSize,
                    sortColumn: this.options.sortColumn,
                    sortOrder: this.options.sortOrder,
                    search: this.searchQuery
                });
                
                data = response.data || response;
                this.totalItems = response.total || data.length;
                this.totalPages = Math.ceil(this.totalItems / this.options.pageSize);
            } else {
                data = this.options.data;
                
                // Filter
                if (this.searchQuery) {
                    data = data.filter(item => {
                        return this.options.columns.some(col => {
                            const value = this.getNestedValue(item, col.key);
                            return String(value).toLowerCase().includes(this.searchQuery.toLowerCase());
                        });
                    });
                }
                
                // Sort
                if (this.options.sortColumn) {
                    data = [...data].sort((a, b) => {
                        const aVal = this.getNestedValue(a, this.options.sortColumn);
                        const bVal = this.getNestedValue(b, this.options.sortColumn);
                        const cmp = aVal > bVal ? 1 : aVal < bVal ? -1 : 0;
                        return this.options.sortOrder === 'asc' ? cmp : -cmp;
                    });
                }
                
                this.filteredData = data;
                this.totalItems = data.length;
                this.totalPages = Math.ceil(this.totalItems / this.options.pageSize);
                
                // Paginate
                const start = (this.options.currentPage - 1) * this.options.pageSize;
                data = data.slice(start, start + this.options.pageSize);
            }
            
            this.renderRows(data);
            this.renderPagination();
            this.renderInfo();
        } catch (error) {
            this.showError(error.message);
        }
    }

    renderRows(data) {
        if (!data || data.length === 0) {
            this.tbody.innerHTML = `
                <tr class="empty-row">
                    <td colspan="${this.options.columns.length + (this.options.selectable ? 1 : 0)}">
                        ${this.options.emptyText}
                    </td>
                </tr>
            `;
            return;
        }
        
        this.tbody.innerHTML = data.map((item, index) => {
            const rowClass = this.options.onRowClick ? 'clickable' : '';
            const selectedClass = this.selectedIds.has(item.id) ? 'selected' : '';
            
            return `
                <tr class="${rowClass} ${selectedClass}" data-id="${item.id}" data-index="${index}">
                    ${this.options.selectable ? `
                        <td class="dt-select">
                            <input type="checkbox" class="row-select" 
                                ${this.selectedIds.has(item.id) ? 'checked' : ''}
                                onchange="this.closest('.datatable-wrapper').dataTable.toggleSelect(${item.id}, this.checked)">
                        </td>
                    ` : ''}
                    ${this.options.columns.map(col => {
                        let value = this.getNestedValue(item, col.key);
                        
                        if (col.render) {
                            value = col.render(value, item, index);
                        } else if (col.format) {
                            value = this.formatValue(value, col.format);
                        }
                        
                        return `<td class="${col.class || ''}">${value ?? '-'}</td>`;
                    }).join('')}
                </tr>
            `;
        }).join('');
        
        // Row click handler
        if (this.options.onRowClick) {
            this.tbody.querySelectorAll('tr[data-id]').forEach(row => {
                row.addEventListener('click', (e) => {
                    if (e.target.closest('.dt-select')) return;
                    const id = row.dataset.id;
                    const item = data.find(d => String(d.id) === id);
                    this.options.onRowClick(item, row);
                });
            });
        }
    }

    renderPagination() {
        if (this.totalPages <= 1) {
            this.pagination.innerHTML = '';
            return;
        }
        
        const { currentPage } = this.options;
        let pages = [];
        
        // Build page numbers
        if (this.totalPages <= 7) {
            pages = Array.from({ length: this.totalPages }, (_, i) => i + 1);
        } else {
            if (currentPage <= 3) {
                pages = [1, 2, 3, 4, '...', this.totalPages];
            } else if (currentPage >= this.totalPages - 2) {
                pages = [1, '...', this.totalPages - 3, this.totalPages - 2, this.totalPages - 1, this.totalPages];
            } else {
                pages = [1, '...', currentPage - 1, currentPage, currentPage + 1, '...', this.totalPages];
            }
        }
        
        this.pagination.innerHTML = `
            <button class="page-btn" ${currentPage === 1 ? 'disabled' : ''} 
                onclick="this.closest('.datatable-wrapper').dataTable.goToPage(${currentPage - 1})">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M15 18l-6-6 6-6"/>
                </svg>
            </button>
            ${pages.map(p => {
                if (p === '...') {
                    return '<span class="page-ellipsis">...</span>';
                }
                return `
                    <button class="page-btn ${p === currentPage ? 'active' : ''}"
                        onclick="this.closest('.datatable-wrapper').dataTable.goToPage(${p})">
                        ${p}
                    </button>
                `;
            }).join('')}
            <button class="page-btn" ${currentPage === this.totalPages ? 'disabled' : ''}
                onclick="this.closest('.datatable-wrapper').dataTable.goToPage(${currentPage + 1})">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M9 18l6-6-6-6"/>
                </svg>
            </button>
        `;
    }

    renderInfo() {
        const start = (this.options.currentPage - 1) * this.options.pageSize + 1;
        const end = Math.min(start + this.options.pageSize - 1, this.totalItems);
        
        this.info.innerHTML = i18n.t('common.showing', {
            start,
            end,
            total: this.totalItems
        });
    }

    goToPage(page) {
        if (page < 1 || page > this.totalPages) return;
        this.options.currentPage = page;
        this.loadData();
    }

    toggleSelect(id, selected) {
        if (selected) {
            this.selectedIds.add(id);
        } else {
            this.selectedIds.delete(id);
        }
        
        this.updateSelectAllState();
        
        if (this.options.onSelect) {
            this.options.onSelect(Array.from(this.selectedIds));
        }
    }

    toggleSelectAll(selected) {
        const checkboxes = this.tbody.querySelectorAll('.row-select');
        checkboxes.forEach(cb => {
            const id = parseInt(cb.closest('tr').dataset.id);
            cb.checked = selected;
            if (selected) {
                this.selectedIds.add(id);
            } else {
                this.selectedIds.delete(id);
            }
        });
        
        if (this.options.onSelect) {
            this.options.onSelect(Array.from(this.selectedIds));
        }
    }

    updateSelectAllState() {
        const selectAll = this.container.querySelector('.select-all');
        if (!selectAll) return;
        
        const checkboxes = this.tbody.querySelectorAll('.row-select');
        const checkedCount = this.tbody.querySelectorAll('.row-select:checked').length;
        
        selectAll.checked = checkboxes.length > 0 && checkedCount === checkboxes.length;
        selectAll.indeterminate = checkedCount > 0 && checkedCount < checkboxes.length;
    }

    updateSortIndicators() {
        this.container.querySelectorAll('th.sortable').forEach(th => {
            th.classList.remove('sort-asc', 'sort-desc');
            if (th.dataset.column === this.options.sortColumn) {
                th.classList.add(`sort-${this.options.sortOrder}`);
            }
        });
    }

    getNestedValue(obj, key) {
        return key.split('.').reduce((o, k) => o?.[k], obj);
    }

    formatValue(value, format) {
        switch (format) {
            case 'date':
                return formatDate(value);
            case 'datetime':
                return formatDateTime(value);
            case 'bytes':
                return formatBytes(value);
            case 'number':
                return formatNumber(value);
            case 'currency':
                return formatCurrency(value);
            default:
                return value;
        }
    }

    showLoading() {
        this.tbody.innerHTML = `
            <tr class="loading-row">
                <td colspan="${this.options.columns.length + (this.options.selectable ? 1 : 0)}">
                    <div class="spinner"></div>
                    ${this.options.loadingText}
                </td>
            </tr>
        `;
    }

    showError(message) {
        this.tbody.innerHTML = `
            <tr class="error-row">
                <td colspan="${this.options.columns.length + (this.options.selectable ? 1 : 0)}">
                    <div class="error-message">${message}</div>
                </td>
            </tr>
        `;
    }

    refresh() {
        this.loadData();
    }

    setData(data) {
        this.options.data = data;
        this.options.currentPage = 1;
        this.loadData();
    }

    getSelected() {
        return Array.from(this.selectedIds);
    }

    clearSelection() {
        this.selectedIds.clear();
        this.toggleSelectAll(false);
    }
}

// ============================================================================
// FORM BUILDER
// ============================================================================

class FormBuilder {
    constructor(options = {}) {
        this.fields = options.fields || [];
        this.values = options.values || {};
        this.errors = {};
        this.onSubmit = options.onSubmit || null;
        this.onChange = options.onChange || null;
        this.validators = options.validators || {};
    }

    render() {
        return `
            <form class="form-builder" onsubmit="return false;">
                ${this.fields.map(field => this.renderField(field)).join('')}
            </form>
        `;
    }

    renderField(field) {
        const value = this.values[field.name] ?? field.default ?? '';
        const error = this.errors[field.name];
        const errorClass = error ? 'has-error' : '';
        const required = field.required ? 'required' : '';
        
        let input = '';
        
        switch (field.type) {
            case 'text':
            case 'email':
            case 'password':
            case 'number':
            case 'tel':
            case 'url':
                input = `
                    <input type="${field.type}" id="${field.name}" name="${field.name}"
                        class="form-control ${errorClass}" value="${this.escapeHtml(value)}"
                        placeholder="${field.placeholder || ''}" ${required}
                        ${field.min !== undefined ? `min="${field.min}"` : ''}
                        ${field.max !== undefined ? `max="${field.max}"` : ''}
                        ${field.step !== undefined ? `step="${field.step}"` : ''}
                        ${field.disabled ? 'disabled' : ''}
                        ${field.readonly ? 'readonly' : ''}>
                `;
                break;
                
            case 'textarea':
                input = `
                    <textarea id="${field.name}" name="${field.name}"
                        class="form-control ${errorClass}" rows="${field.rows || 3}"
                        placeholder="${field.placeholder || ''}" ${required}
                        ${field.disabled ? 'disabled' : ''}
                        ${field.readonly ? 'readonly' : ''}>${this.escapeHtml(value)}</textarea>
                `;
                break;
                
            case 'select':
                input = `
                    <select id="${field.name}" name="${field.name}"
                        class="form-control ${errorClass}" ${required}
                        ${field.disabled ? 'disabled' : ''}>
                        ${field.placeholder ? `<option value="">${field.placeholder}</option>` : ''}
                        ${(field.options || []).map(opt => {
                            const optValue = typeof opt === 'object' ? opt.value : opt;
                            const optLabel = typeof opt === 'object' ? opt.label : opt;
                            const selected = optValue === value ? 'selected' : '';
                            return `<option value="${optValue}" ${selected}>${optLabel}</option>`;
                        }).join('')}
                    </select>
                `;
                break;
                
            case 'checkbox':
                input = `
                    <label class="checkbox-label">
                        <input type="checkbox" id="${field.name}" name="${field.name}"
                            ${value ? 'checked' : ''} ${field.disabled ? 'disabled' : ''}>
                        <span class="checkbox-text">${field.checkboxLabel || ''}</span>
                    </label>
                `;
                break;
                
            case 'switch':
                input = `
                    <label class="switch">
                        <input type="checkbox" id="${field.name}" name="${field.name}"
                            ${value ? 'checked' : ''} ${field.disabled ? 'disabled' : ''}>
                        <span class="slider"></span>
                    </label>
                `;
                break;
                
            case 'radio':
                input = `
                    <div class="radio-group">
                        ${(field.options || []).map(opt => {
                            const optValue = typeof opt === 'object' ? opt.value : opt;
                            const optLabel = typeof opt === 'object' ? opt.label : opt;
                            const checked = optValue === value ? 'checked' : '';
                            return `
                                <label class="radio-label">
                                    <input type="radio" name="${field.name}" value="${optValue}" ${checked}>
                                    <span class="radio-text">${optLabel}</span>
                                </label>
                            `;
                        }).join('')}
                    </div>
                `;
                break;
                
            case 'file':
                input = `
                    <input type="file" id="${field.name}" name="${field.name}"
                        class="form-control ${errorClass}"
                        ${field.accept ? `accept="${field.accept}"` : ''}
                        ${field.multiple ? 'multiple' : ''}>
                `;
                break;
                
            case 'tags':
                input = `
                    <div class="tags-input" id="${field.name}-tags">
                        <div class="tags-list">
                            ${(Array.isArray(value) ? value : []).map(tag => `
                                <span class="tag">${tag}<button type="button" class="tag-remove">&times;</button></span>
                            `).join('')}
                        </div>
                        <input type="text" class="tag-input" placeholder="${field.placeholder || i18n.t('common.addTag')}">
                        <input type="hidden" id="${field.name}" name="${field.name}" value="${JSON.stringify(value || [])}">
                    </div>
                `;
                break;
                
            case 'datetime':
                input = `
                    <input type="datetime-local" id="${field.name}" name="${field.name}"
                        class="form-control ${errorClass}" value="${value}"
                        ${required} ${field.disabled ? 'disabled' : ''}>
                `;
                break;
                
            case 'color':
                input = `
                    <div class="color-input">
                        <input type="color" id="${field.name}" name="${field.name}" value="${value || '#000000'}">
                        <input type="text" class="form-control" value="${value || '#000000'}" 
                            pattern="^#[0-9A-Fa-f]{6}$" maxlength="7">
                    </div>
                `;
                break;
                
            case 'range':
                input = `
                    <div class="range-input">
                        <input type="range" id="${field.name}" name="${field.name}"
                            value="${value}" min="${field.min || 0}" max="${field.max || 100}"
                            step="${field.step || 1}">
                        <span class="range-value">${value}</span>
                    </div>
                `;
                break;
                
            case 'hidden':
                return `<input type="hidden" id="${field.name}" name="${field.name}" value="${value}">`;
                
            case 'divider':
                return `<hr class="form-divider">`;
                
            case 'heading':
                return `<h4 class="form-heading">${field.label}</h4>`;
                
            case 'html':
                return field.content;
        }
        
        return `
            <div class="form-group ${errorClass}" data-field="${field.name}">
                ${field.label ? `
                    <label for="${field.name}">
                        ${field.label}
                        ${field.required ? '<span class="required">*</span>' : ''}
                    </label>
                ` : ''}
                ${input}
                ${field.hint ? `<small class="form-hint">${field.hint}</small>` : ''}
                ${error ? `<small class="form-error">${error}</small>` : ''}
            </div>
        `;
    }

    escapeHtml(str) {
        if (str === null || str === undefined) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    getFormData(form) {
        const formData = new FormData(form);
        const data = {};
        
        for (const [key, value] of formData.entries()) {
            const field = this.fields.find(f => f.name === key);
            
            if (field?.type === 'checkbox' || field?.type === 'switch') {
                data[key] = form.querySelector(`[name="${key}"]`).checked;
            } else if (field?.type === 'number') {
                data[key] = value ? parseFloat(value) : null;
            } else if (field?.type === 'tags') {
                try {
                    data[key] = JSON.parse(value);
                } catch {
                    data[key] = [];
                }
            } else {
                data[key] = value;
            }
        }
        
        return data;
    }

    validate(data) {
        this.errors = {};
        
        for (const field of this.fields) {
            const value = data[field.name];
            
            // Required validation
            if (field.required && (value === '' || value === null || value === undefined)) {
                this.errors[field.name] = i18n.t('validation.required');
                continue;
            }
            
            // Type-specific validation
            if (value && field.type === 'email' && !is.email(value)) {
                this.errors[field.name] = i18n.t('validation.email');
            }
            
            if (value && field.type === 'url' && !is.url(value)) {
                this.errors[field.name] = i18n.t('validation.url');
            }
            
            if (field.type === 'number') {
                if (field.min !== undefined && value < field.min) {
                    this.errors[field.name] = i18n.t('validation.min', { min: field.min });
                }
                if (field.max !== undefined && value > field.max) {
                    this.errors[field.name] = i18n.t('validation.max', { max: field.max });
                }
            }
            
            if (field.minLength && value && value.length < field.minLength) {
                this.errors[field.name] = i18n.t('validation.minLength', { min: field.minLength });
            }
            
            if (field.maxLength && value && value.length > field.maxLength) {
                this.errors[field.name] = i18n.t('validation.maxLength', { max: field.maxLength });
            }
            
            if (field.pattern && value && !new RegExp(field.pattern).test(value)) {
                this.errors[field.name] = field.patternMessage || i18n.t('validation.pattern');
            }
            
            // Custom validators
            if (this.validators[field.name]) {
                const error = this.validators[field.name](value, data);
                if (error) {
                    this.errors[field.name] = error;
                }
            }
        }
        
        return Object.keys(this.errors).length === 0;
    }

    showErrors(container) {
        for (const [fieldName, error] of Object.entries(this.errors)) {
            const group = container.querySelector(`[data-field="${fieldName}"]`);
            if (group) {
                group.classList.add('has-error');
                let errorEl = group.querySelector('.form-error');
                if (!errorEl) {
                    errorEl = document.createElement('small');
                    errorEl.className = 'form-error';
                    group.appendChild(errorEl);
                }
                errorEl.textContent = error;
            }
        }
    }

    clearErrors(container) {
        container.querySelectorAll('.form-group.has-error').forEach(group => {
            group.classList.remove('has-error');
            const errorEl = group.querySelector('.form-error');
            if (errorEl) errorEl.remove();
        });
    }
}

// ============================================================================
// CHARTS (Using Chart.js wrapper)
// ============================================================================

class MXUIChart {
    constructor(canvas, options = {}) {
        this.canvas = typeof canvas === 'string' ? document.getElementById(canvas) : canvas;
        this.ctx = this.canvas?.getContext('2d');
        this.chart = null;
        this.options = options;
        
        if (this.ctx) {
            this.init();
        }
    }

    init() {
        const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
        const textColor = isDark ? '#a0aec0' : '#4a5568';
        const gridColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
        
        const defaultOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: textColor }
                }
            },
            scales: this.options.type !== 'pie' && this.options.type !== 'doughnut' ? {
                x: {
                    grid: { color: gridColor },
                    ticks: { color: textColor }
                },
                y: {
                    grid: { color: gridColor },
                    ticks: { color: textColor }
                }
            } : {}
        };
        
        // Check if Chart.js is loaded
        if (typeof Chart === 'undefined') {
            console.error('Chart.js not loaded');
            return;
        }
        
        this.chart = new Chart(this.ctx, {
            type: this.options.type || 'line',
            data: this.options.data || { labels: [], datasets: [] },
            options: { ...defaultOptions, ...this.options.options }
        });
    }

    update(data) {
        if (!this.chart) return;
        
        this.chart.data = data;
        this.chart.update();
    }

    destroy() {
        if (this.chart) {
            this.chart.destroy();
            this.chart = null;
        }
    }

    static createLineChart(canvas, labels, datasets, options = {}) {
        return new MXUIChart(canvas, {
            type: 'line',
            data: {
                labels,
                datasets: datasets.map((ds, i) => ({
                    label: ds.label,
                    data: ds.data,
                    borderColor: ds.color || `hsl(${i * 60}, 70%, 50%)`,
                    backgroundColor: ds.backgroundColor || `hsla(${i * 60}, 70%, 50%, 0.1)`,
                    fill: ds.fill ?? true,
                    tension: 0.4
                }))
            },
            options
        });
    }

    static createBarChart(canvas, labels, datasets, options = {}) {
        return new MXUIChart(canvas, {
            type: 'bar',
            data: {
                labels,
                datasets: datasets.map((ds, i) => ({
                    label: ds.label,
                    data: ds.data,
                    backgroundColor: ds.color || `hsl(${i * 60}, 70%, 50%)`,
                    borderRadius: 4
                }))
            },
            options
        });
    }

    static createDoughnutChart(canvas, labels, data, colors, options = {}) {
        return new MXUIChart(canvas, {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{
                    data,
                    backgroundColor: colors,
                    borderWidth: 0
                }]
            },
            options: {
                cutout: '70%',
                ...options
            }
        });
    }
}

// ============================================================================
// QR CODE GENERATOR
// ============================================================================

class QRGenerator {
    static generate(text, options = {}) {
        const size = options.size || 200;
        const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=${size}x${size}&data=${encodeURIComponent(text)}`;
        return qrUrl;
    }

    static render(container, text, options = {}) {
        const element = typeof container === 'string' ? document.getElementById(container) : container;
        if (!element) return;
        
        const img = document.createElement('img');
        img.src = this.generate(text, options);
        img.alt = 'QR Code';
        img.className = 'qr-code';
        
        element.innerHTML = '';
        element.appendChild(img);
        
        return img;
    }
}

// ============================================================================
// CLIPBOARD
// ============================================================================

class Clipboard {
    static async copy(text) {
        try {
            await navigator.clipboard.writeText(text);
            Notify.success(i18n.t('common.copied'));
            return true;
        } catch (error) {
            // Fallback for older browsers
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            
            try {
                document.execCommand('copy');
                Notify.success(i18n.t('common.copied'));
                return true;
            } catch (e) {
                Notify.error(i18n.t('common.copyFailed'));
                return false;
            } finally {
                document.body.removeChild(textarea);
            }
        }
    }
}

// ============================================================================
// DROPDOWN MENUS
// ============================================================================

class Dropdown {
    static init() {
        document.addEventListener('click', (e) => {
            // Close all dropdowns when clicking outside
            if (!e.target.closest('.dropdown')) {
                document.querySelectorAll('.dropdown.open').forEach(dd => {
                    dd.classList.remove('open');
                });
            }
        });
    }

    static toggle(element) {
        const dropdown = element.closest('.dropdown');
        const isOpen = dropdown.classList.contains('open');
        
        // Close all other dropdowns
        document.querySelectorAll('.dropdown.open').forEach(dd => {
            if (dd !== dropdown) dd.classList.remove('open');
        });
        
        dropdown.classList.toggle('open', !isOpen);
    }
}

// Initialize dropdown
Dropdown.init();

// ============================================================================
// TOOLTIP
// ============================================================================

class Tooltip {
    static show(element, text, position = 'top') {
        const tooltip = document.createElement('div');
        tooltip.className = `tooltip tooltip-${position}`;
        tooltip.textContent = text;
        
        document.body.appendChild(tooltip);
        
        const rect = element.getBoundingClientRect();
        const tooltipRect = tooltip.getBoundingClientRect();
        
        let top, left;
        
        switch (position) {
            case 'top':
                top = rect.top - tooltipRect.height - 8;
                left = rect.left + (rect.width - tooltipRect.width) / 2;
                break;
            case 'bottom':
                top = rect.bottom + 8;
                left = rect.left + (rect.width - tooltipRect.width) / 2;
                break;
            case 'left':
                top = rect.top + (rect.height - tooltipRect.height) / 2;
                left = rect.left - tooltipRect.width - 8;
                break;
            case 'right':
                top = rect.top + (rect.height - tooltipRect.height) / 2;
                left = rect.right + 8;
                break;
        }
        
        tooltip.style.top = `${top}px`;
        tooltip.style.left = `${left}px`;
        tooltip.classList.add('show');
        
        element._tooltip = tooltip;
    }

    static hide(element) {
        if (element._tooltip) {
            element._tooltip.remove();
            element._tooltip = null;
        }
    }

    static init() {
        document.querySelectorAll('[data-tooltip]').forEach(el => {
            el.addEventListener('mouseenter', () => {
                Tooltip.show(el, el.dataset.tooltip, el.dataset.tooltipPosition);
            });
            el.addEventListener('mouseleave', () => {
                Tooltip.hide(el);
            });
        });
    }
}

// ============================================================================
// LOADING OVERLAY
// ============================================================================

class Loading {
    static show(message = '') {
        let overlay = document.getElementById('loading-overlay');
        
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'loading-overlay';
            overlay.className = 'loading-overlay';
            overlay.innerHTML = `
                <div class="loading-content">
                    <div class="spinner-large"></div>
                    <p class="loading-message">${message || i18n.t('common.loading')}</p>
                </div>
            `;
            document.body.appendChild(overlay);
        } else {
            overlay.querySelector('.loading-message').textContent = message || i18n.t('common.loading');
        }
        
        overlay.classList.add('show');
    }

    static hide() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) {
            overlay.classList.remove('show');
        }
    }

    static setMessage(message) {
        const el = document.querySelector('#loading-overlay .loading-message');
        if (el) el.textContent = message;
    }
}

// ============================================================================
// FILE UPLOAD
// ============================================================================

class FileUpload {
    constructor(element, options = {}) {
        this.element = typeof element === 'string' ? document.querySelector(element) : element;
        this.options = {
            accept: options.accept || '*',
            multiple: options.multiple || false,
            maxSize: options.maxSize || 10 * 1024 * 1024, // 10MB
            onSelect: options.onSelect || null,
            onUpload: options.onUpload || null,
            onError: options.onError || null,
            ...options
        };
        
        this.files = [];
        this.init();
    }

    init() {
        this.element.innerHTML = `
            <div class="file-upload-area" id="file-upload-area">
                <input type="file" class="file-input" 
                    accept="${this.options.accept}"
                    ${this.options.multiple ? 'multiple' : ''}>
                <div class="file-upload-content">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M17 8l-5-5-5 5M12 3v12"/>
                    </svg>
                    <p>${i18n.t('upload.dragDrop')}</p>
                    <button type="button" class="btn btn-outline btn-sm">${i18n.t('upload.browse')}</button>
                </div>
                <div class="file-preview"></div>
            </div>
        `;
        
        this.area = this.element.querySelector('.file-upload-area');
        this.input = this.element.querySelector('.file-input');
        this.preview = this.element.querySelector('.file-preview');
        
        this.bindEvents();
    }

    bindEvents() {
        // Click to browse
        this.area.addEventListener('click', (e) => {
            if (!e.target.closest('.file-preview-item')) {
                this.input.click();
            }
        });
        
        // File input change
        this.input.addEventListener('change', (e) => {
            this.handleFiles(e.target.files);
        });
        
        // Drag & drop
        this.area.addEventListener('dragover', (e) => {
            e.preventDefault();
            this.area.classList.add('dragover');
        });
        
        this.area.addEventListener('dragleave', () => {
            this.area.classList.remove('dragover');
        });
        
        this.area.addEventListener('drop', (e) => {
            e.preventDefault();
            this.area.classList.remove('dragover');
            this.handleFiles(e.dataTransfer.files);
        });
    }

    handleFiles(fileList) {
        const files = Array.from(fileList);
        
        for (const file of files) {
            // Check size
            if (file.size > this.options.maxSize) {
                if (this.options.onError) {
                    this.options.onError(new Error(i18n.t('upload.tooLarge', { 
                        name: file.name, 
                        max: formatBytes(this.options.maxSize) 
                    })));
                }
                continue;
            }
            
            if (!this.options.multiple) {
                this.files = [file];
            } else {
                this.files.push(file);
            }
        }
        
        this.renderPreview();
        
        if (this.options.onSelect) {
            this.options.onSelect(this.files);
        }
    }

    renderPreview() {
        this.preview.innerHTML = this.files.map((file, index) => `
            <div class="file-preview-item">
                ${file.type.startsWith('image/') 
                    ? `<img src="${URL.createObjectURL(file)}" alt="${file.name}">`
                    : `<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
                        <polyline points="14 2 14 8 20 8"/>
                    </svg>`
                }
                <div class="file-info">
                    <span class="file-name">${file.name}</span>
                    <span class="file-size">${formatBytes(file.size)}</span>
                </div>
                <button type="button" class="file-remove" onclick="event.stopPropagation(); this.closest('.file-upload-area').fileUpload.removeFile(${index})">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M18 6L6 18M6 6l12 12"/>
                    </svg>
                </button>
            </div>
        `).join('');
        
        // Store reference
        this.area.fileUpload = this;
    }

    removeFile(index) {
        this.files.splice(index, 1);
        this.renderPreview();
        
        if (this.options.onSelect) {
            this.options.onSelect(this.files);
        }
    }

    getFiles() {
        return this.files;
    }

    clear() {
        this.files = [];
        this.input.value = '';
        this.preview.innerHTML = '';
    }
}

// ============================================================================
// EXPORTS
// ============================================================================

window.Modal = Modal;
window.DataTable = DataTable;
window.FormBuilder = FormBuilder;
window.MXUIChart = MXUIChart;
window.QRGenerator = QRGenerator;
window.Clipboard = Clipboard;
window.Dropdown = Dropdown;
window.Tooltip = Tooltip;
window.Loading = Loading;
window.FileUpload = FileUpload;
