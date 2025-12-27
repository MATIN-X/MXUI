/**
 * MXUI Panel - Main Application JavaScript
 * Version: 2.0.0
 */

'use strict';

// ============================================================================
// GLOBAL STATE
// ============================================================================

const APP = {
    currentPage: 'home',
    user: null,
    isOwner: false,
    isLoading: false,
    charts: {},
    intervals: {},
    lang: 'fa',
    theme: 'dark',
    wsConnection: null
};

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    init();
});

async function init() {
    try {
        // Load settings
        loadSettings();

        // Check authentication
        if (!auth.isAuthenticated()) {
            window.location.href = 'login.html';
            return;
        }

        // Get user info
        const user = auth.getUser();
        if (!user) {
            await refreshUserInfo();
        } else {
            APP.user = user;
            APP.isOwner = user.role === 'owner';
        }

        // Setup UI
        setupUI();

        // Setup event listeners
        setupEventListeners();

        // Load initial page
        navigateTo(APP.currentPage);

        // Setup real-time updates
        setupRealTimeUpdates();

        // Hide preloader
        setTimeout(() => {
            document.getElementById('preloader').classList.add('hidden');
        }, 500);

    } catch (error) {
        console.error('Initialization failed:', error);
        showToast('خطا در بارگذاری پنل', 'error');
    }
}

function loadSettings() {
    APP.lang = localStorage.getItem('mxui_lang') || 'fa';
    APP.theme = localStorage.getItem('mxui_theme') || 'dark';
    APP.currentPage = localStorage.getItem('mxui_page') || 'home';

    // Apply theme
    document.body.classList.toggle('light', APP.theme === 'light');

    // Apply language direction
    document.documentElement.dir = APP.lang === 'fa' ? 'rtl' : 'ltr';
    document.documentElement.lang = APP.lang;
}

async function refreshUserInfo() {
    try {
        const response = await api.admins.me();
        APP.user = response;
        APP.isOwner = response.role === 'owner';
        auth.setUser(response);
    } catch (error) {
        console.error('Failed to get user info:', error);
        auth.logout(false);
    }
}

// ============================================================================
// UI SETUP
// ============================================================================

function setupUI() {
    updateProfileUI();
    updateRoleBasedUI();
}

function updateProfileUI() {
    const user = APP.user;
    if (!user) return;

    const initial = user.username ? user.username[0].toUpperCase() : 'A';

    // Desktop profile
    const profileAvatar = document.getElementById('profileAvatar');
    const profileAvatarLg = document.getElementById('profileAvatarLg');
    const profileName = document.getElementById('profileName');
    const profileRole = document.getElementById('profileRole');

    if (profileAvatar) profileAvatar.textContent = initial;
    if (profileAvatarLg) profileAvatarLg.textContent = initial;
    if (profileName) profileName.textContent = user.username;
    if (profileRole) profileRole.textContent = getRoleLabel(user.role);

    // Mobile profile
    const mobileProfileAvatar = document.getElementById('mobileProfileAvatar');
    const mobileProfileName = document.getElementById('mobileProfileName');
    const mobileProfileRole = document.getElementById('mobileProfileRole');

    if (mobileProfileAvatar) mobileProfileAvatar.textContent = initial;
    if (mobileProfileName) mobileProfileName.textContent = user.username;
    if (mobileProfileRole) mobileProfileRole.textContent = getRoleLabel(user.role);
}

function updateRoleBasedUI() {
    const ownerElements = document.querySelectorAll('.owner-only');
    ownerElements.forEach(el => {
        el.style.display = APP.isOwner ? '' : 'none';
    });
}

function getRoleLabel(role) {
    const labels = {
        'owner': 'مالک',
        'admin': 'ادمین',
        'reseller': 'نماینده فروش'
    };
    return labels[role] || role;
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

function setupEventListeners() {
    // Navigation - Sidebar
    document.querySelectorAll('.sidebar .nav-item[data-page]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            navigateTo(page);
        });
    });

    // Navigation - Bottom Nav
    document.querySelectorAll('.bottom-nav-item[data-page]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            navigateTo(page);
            closeMobileSidebar();
        });
    });

    // Mobile menu button
    document.getElementById('mobileMenuBtn')?.addEventListener('click', toggleMobileSidebar);

    // Sidebar toggle
    document.getElementById('sidebarToggle')?.addEventListener('click', toggleSidebar);

    // Sidebar overlay
    document.getElementById('sidebarOverlay')?.addEventListener('click', closeMobileSidebar);

    // Theme toggle
    document.getElementById('themeToggle')?.addEventListener('click', toggleTheme);

    // Language select
    document.getElementById('langSelect')?.addEventListener('change', (e) => {
        changeLanguage(e.target.value);
    });

    // Refresh button
    document.getElementById('refreshBtn')?.addEventListener('click', refreshCurrentPage);

    // Profile dropdown
    document.getElementById('profileBtn')?.addEventListener('click', toggleProfileMenu);

    // Close profile menu on outside click
    document.addEventListener('click', (e) => {
        const dropdown = document.getElementById('profileDropdown');
        if (dropdown && !dropdown.contains(e.target)) {
            dropdown.classList.remove('active');
        }
    });

    // Modal close
    document.getElementById('modalOverlay')?.addEventListener('click', (e) => {
        if (e.target === e.currentTarget) {
            closeModal();
        }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyboardShortcuts);
}

function handleKeyboardShortcuts(e) {
    // ESC to close modal
    if (e.key === 'Escape') {
        closeModal();
    }

    // Ctrl+K for search (future feature)
    if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        // Open search
    }
}

// ============================================================================
// NAVIGATION
// ============================================================================

function navigateTo(page) {
    // Check permission
    const ownerOnlyPages = ['admins', 'core', 'nodes', 'panel', 'template', 'message', 'bot', 'ai', 'database'];
    if (ownerOnlyPages.includes(page) && !APP.isOwner) {
        showToast('شما دسترسی به این بخش ندارید', 'error');
        return;
    }

    APP.currentPage = page;
    localStorage.setItem('mxui_page', page);

    // Update navigation active state
    updateNavigationState(page);

    // Update page title
    updatePageTitle(page);

    // Load page content
    loadPageContent(page);
}

function updateNavigationState(page) {
    // Sidebar
    document.querySelectorAll('.sidebar .nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });

    // Bottom nav
    document.querySelectorAll('.bottom-nav-item').forEach(item => {
        item.classList.toggle('active', item.dataset.page === page);
    });
}

function updatePageTitle(page) {
    const titles = {
        'home': 'خانه',
        'users': 'کاربران',
        'admins': 'ادمین‌ها',
        'core': 'تنظیمات هسته',
        'nodes': 'نودها',
        'panel': 'تنظیمات پنل',
        'template': 'قالب‌ها',
        'message': 'پیام‌ها',
        'bot': 'ربات فروش',
        'ai': 'هوش مصنوعی',
        'database': 'دیتابیس',
        'profile-mobile': 'پروفایل'
    };

    const title = titles[page] || page;
    document.getElementById('pageTitle').textContent = title;
    document.title = `${title} - MXUI Panel`;
}

function loadPageContent(page) {
    const container = document.getElementById('pageContainer');
    const template = document.getElementById(`tpl-${page}`);

    if (!template) {
        container.innerHTML = `<div class="page-content fade-in">
            <div class="card glass">
                <div class="card-body text-center">
                    <p class="text-muted">صفحه در حال توسعه است...</p>
                </div>
            </div>
        </div>`;
        return;
    }

    container.innerHTML = '';
    container.appendChild(template.content.cloneNode(true));

    // Update role-based visibility
    updateRoleBasedUI();

    // Initialize page
    initializePage(page);
}

async function initializePage(page) {
    switch (page) {
        case 'home':
            await loadDashboardData();
            initTrafficChart();
            break;
        case 'users':
            await loadUsers();
            if (APP.isOwner) loadAdminFilter();
            break;
        case 'admins':
            await loadAdmins();
            break;
        case 'core':
            await loadCoreSettings();
            break;
        case 'nodes':
            await loadNodes();
            break;
        case 'panel':
            await loadPanelSettings();
            break;
        case 'template':
            // Templates loaded on demand
            break;
        case 'message':
            await loadSentMessages();
            break;
        case 'bot':
            await loadBotSettings();
            await loadPlans();
            break;
        case 'ai':
            await loadAISettings();
            break;
        case 'database':
            await loadBackups();
            break;
        case 'profile-mobile':
            loadMobileProfile();
            break;
    }
}

function refreshCurrentPage() {
    initializePage(APP.currentPage);
    showToast('بروزرسانی شد', 'success');
}

// ============================================================================
// SIDEBAR & MOBILE MENU
// ============================================================================

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('collapsed');
    localStorage.setItem('mxui_sidebar', sidebar.classList.contains('collapsed') ? 'collapsed' : 'expanded');
}

function toggleMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    sidebar.classList.toggle('mobile-open');
    overlay.classList.toggle('active');
}

function closeMobileSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebarOverlay');
    sidebar.classList.remove('mobile-open');
    overlay.classList.remove('active');
}

// ============================================================================
// THEME & LANGUAGE
// ============================================================================

function toggleTheme() {
    APP.theme = APP.theme === 'dark' ? 'light' : 'dark';
    document.body.classList.toggle('light', APP.theme === 'light');
    localStorage.setItem('mxui_theme', APP.theme);
}

function changeLanguage(lang) {
    APP.lang = lang;
    localStorage.setItem('mxui_lang', lang);
    document.documentElement.dir = lang === 'fa' ? 'rtl' : 'ltr';
    document.documentElement.lang = lang;
    // Reload translations
    // loadTranslations(lang);
}

// ============================================================================
// PROFILE MENU
// ============================================================================

function toggleProfileMenu() {
    const dropdown = document.getElementById('profileDropdown');
    dropdown.classList.toggle('active');
}

function openSettings() {
    navigateTo('panel');
    document.getElementById('profileDropdown')?.classList.remove('active');
}

function logout() {
    if (confirm('آیا مطمئن هستید که می‌خواهید خارج شوید؟')) {
        auth.logout();
    }
}

// ============================================================================
// DASHBOARD DATA
// ============================================================================

async function loadDashboardData() {
    try {
        // Load stats
        const [stats, systemInfo] = await Promise.all([
            api.analytics.getDashboardStats(),
            APP.isOwner ? api.system.getStats() : Promise.resolve(null)
        ]);

        // Update stats cards
        updateElement('statTotalUsers', stats.total_users || 0);
        updateElement('statActiveUsers', stats.active_users || 0);
        updateElement('statOnlineUsers', `${stats.online_users || 0} آنلاین`);
        updateElement('statTotalTraffic', formatBytes(stats.total_traffic || 0));
        updateElement('statUpload', formatBytes(stats.upload || 0));
        updateElement('statDownload', formatBytes(stats.download || 0));
        updateElement('statNodes', `${stats.online_nodes || 1}/${stats.total_nodes || 1}`);
        updateElement('statNewUsers', `+${stats.new_users_today || 0} امروز`);

        // Profile stats
        updateElement('profileUsers', APP.user?.users_count || 0);
        updateElement('profileTraffic', formatBytes(APP.user?.traffic_used || 0));
        updateElement('mobileProfileUsers', APP.user?.users_count || 0);
        updateElement('mobileProfileTraffic', formatBytes(APP.user?.traffic_used || 0));

        // System info (owner only)
        if (systemInfo && APP.isOwner) {
            updateSystemStats(systemInfo);
        }

        // Load nodes status
        if (APP.isOwner) {
            loadNodesStatus();
        }

    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

function updateSystemStats(info) {
    // CPU
    const cpuPercent = info.cpu_percent || 0;
    updateElement('sysCpu', `${cpuPercent.toFixed(1)}%`);
    updateProgressBar('sysCpuBar', cpuPercent);

    // RAM
    const ramUsed = info.memory_used || 0;
    const ramTotal = info.memory_total || 1;
    const ramPercent = (ramUsed / ramTotal) * 100;
    updateElement('sysRam', `${formatBytes(ramUsed)} / ${formatBytes(ramTotal)}`);
    updateProgressBar('sysRamBar', ramPercent);

    // Disk
    const diskUsed = info.disk_used || 0;
    const diskTotal = info.disk_total || 1;
    const diskPercent = (diskUsed / diskTotal) * 100;
    updateElement('sysDisk', `${formatBytes(diskUsed)} / ${formatBytes(diskTotal)}`);
    updateProgressBar('sysDiskBar', diskPercent);

    // Network
    const netUp = info.network_up || 0;
    const netDown = info.network_down || 0;
    const networkHtml = `<span class="up">↑ ${formatBytesSpeed(netUp)}</span> <span class="down">↓ ${formatBytesSpeed(netDown)}</span>`;
    document.getElementById('sysNetwork').innerHTML = networkHtml;

    // IPs
    updateElement('sysIpv4', info.ipv4 || '---');
    updateElement('sysIpv6', info.ipv6 || '---');

    // Core status
    updateElement('coreStatusText', info.core_running ? 'در حال اجرا' : 'متوقف');
    updateElement('coreVersion', info.core_version || 'Xray');
    updateElement('coreUptime', formatUptime(info.uptime || 0));

    const coreDot = document.querySelector('.core-dot');
    if (coreDot) {
        coreDot.classList.toggle('running', info.core_running);
        coreDot.classList.toggle('stopped', !info.core_running);
    }
}

async function loadNodesStatus() {
    try {
        const nodes = await api.nodes.getAllStatus();
        const container = document.getElementById('nodesStatus');
        if (!container) return;

        if (!nodes || nodes.length === 0) {
            container.innerHTML = `
                <div class="node-item">
                    <div class="node-status online"></div>
                    <div class="node-info">
                        <div class="node-name">Master Node</div>
                        <div class="node-meta">لوکال - پیش‌فرض</div>
                    </div>
                    <span class="badge success">آنلاین</span>
                </div>`;
            return;
        }

        container.innerHTML = nodes.map(node => `
            <div class="node-item">
                <div class="node-status ${node.status === 'online' ? 'online' : 'offline'}"></div>
                <div class="node-info">
                    <div class="node-name">${escapeHtml(node.name)}</div>
                    <div class="node-meta">${node.address} - ${node.users_count || 0} کاربر</div>
                </div>
                <span class="badge ${node.status === 'online' ? 'success' : 'danger'}">
                    ${node.status === 'online' ? 'آنلاین' : 'آفلاین'}
                </span>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load nodes status:', error);
    }
}

// ============================================================================
// TRAFFIC CHART
// ============================================================================

function initTrafficChart() {
    const canvas = document.getElementById('trafficChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    // Destroy existing chart
    if (APP.charts.traffic) {
        APP.charts.traffic.destroy();
    }

    APP.charts.traffic = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'آپلود',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: true,
                    tension: 0.4
                },
                {
                    label: 'دانلود',
                    data: [],
                    borderColor: '#3b82f6',
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index'
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        color: 'rgba(255, 255, 255, 0.7)',
                        usePointStyle: true
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.5)'
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.05)'
                    },
                    ticks: {
                        color: 'rgba(255, 255, 255, 0.5)',
                        callback: (value) => formatBytes(value)
                    }
                }
            }
        }
    });

    // Load initial data
    updateChart('day');
}

async function updateChart(period) {
    try {
        const data = await api.analytics.getTrafficAnalytics(period);

        if (APP.charts.traffic && data) {
            APP.charts.traffic.data.labels = data.labels || [];
            APP.charts.traffic.data.datasets[0].data = data.upload || [];
            APP.charts.traffic.data.datasets[1].data = data.download || [];
            APP.charts.traffic.update();
        }
    } catch (error) {
        console.error('Failed to update chart:', error);
    }
}

// ============================================================================
// USERS MANAGEMENT
// ============================================================================

let usersPage = 1;
let usersPerPage = 10;

async function loadUsers() {
    try {
        const search = document.getElementById('userSearch')?.value || '';
        const adminId = document.getElementById('adminFilter')?.value || '';
        const status = document.getElementById('statusFilter')?.value || '';

        const filters = {};
        if (status) filters.status = status;
        if (adminId && APP.isOwner) filters.admin_id = adminId;

        const response = await api.users.list({
            page: usersPage,
            perPage: usersPerPage,
            search,
            filters
        });

        renderUsersTable(response.data);
        renderPagination('usersPagination', response, (page) => {
            usersPage = page;
            loadUsers();
        });

        // Update count badge
        updateElement('usersCount', response.total);

    } catch (error) {
        console.error('Failed to load users:', error);
        showToast('خطا در بارگذاری کاربران', 'error');
    }
}

function renderUsersTable(users) {
    const tbody = document.getElementById('usersTableBody');
    if (!tbody) return;

    if (!users || users.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">کاربری یافت نشد</td></tr>`;
        return;
    }

    tbody.innerHTML = users.map(user => `
        <tr>
            <td>
                <div class="user-cell">
                    <strong>${escapeHtml(user.username)}</strong>
                    ${user.note ? `<small class="text-muted">${escapeHtml(user.note)}</small>` : ''}
                </div>
            </td>
            <td>
                <span class="badge ${getStatusBadgeClass(user.status)}">${getStatusLabel(user.status)}</span>
            </td>
            <td>
                <div class="traffic-cell">
                    <div class="progress" style="width: 100px; height: 6px;">
                        <div class="progress-bar ${getTrafficBarClass(user)}" style="width: ${getTrafficPercent(user)}%"></div>
                    </div>
                    <small>${formatBytes(user.used_traffic)} / ${user.data_limit ? formatBytes(user.data_limit) : '∞'}</small>
                </div>
            </td>
            <td>
                <small>${user.expire ? formatDate(user.expire) : 'نامحدود'}</small>
            </td>
            <td>
                <span class="badge ${user.online ? 'success' : ''}">${user.online_count || 0}</span>
            </td>
            <td class="owner-only" style="${APP.isOwner ? '' : 'display:none'}">
                <small>${escapeHtml(user.admin_username || '-')}</small>
            </td>
            <td>
                <div class="btn-group">
                    <button class="btn btn-icon btn-sm" onclick="showUserSub('${user.id}')" title="لینک ساب">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/>
                            <path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/>
                        </svg>
                    </button>
                    <button class="btn btn-icon btn-sm" onclick="showUserIPs('${user.id}')" title="IP های آنلاین">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"/>
                            <line x1="2" y1="12" x2="22" y2="12"/>
                            <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/>
                        </svg>
                    </button>
                    <button class="btn btn-icon btn-sm" onclick="editUser('${user.id}')" title="ویرایش">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
                            <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
                        </svg>
                    </button>
                    <button class="btn btn-icon btn-sm btn-danger" onclick="deleteUser('${user.id}')" title="حذف">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="3 6 5 6 21 6"/>
                            <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                        </svg>
                    </button>
                </div>
            </td>
        </tr>
    `).join('');
}

function getStatusBadgeClass(status) {
    const classes = {
        'active': 'success',
        'expired': 'danger',
        'limited': 'warning',
        'disabled': 'danger',
        'on_hold': 'info'
    };
    return classes[status] || '';
}

function getStatusLabel(status) {
    const labels = {
        'active': 'فعال',
        'expired': 'منقضی',
        'limited': 'محدود',
        'disabled': 'غیرفعال',
        'on_hold': 'انتظار'
    };
    return labels[status] || status;
}

function getTrafficBarClass(user) {
    if (!user.data_limit) return '';
    const percent = (user.used_traffic / user.data_limit) * 100;
    if (percent >= 90) return 'danger';
    if (percent >= 70) return 'warning';
    return '';
}

function getTrafficPercent(user) {
    if (!user.data_limit) return 0;
    return Math.min(100, (user.used_traffic / user.data_limit) * 100);
}

async function loadAdminFilter() {
    try {
        const admins = await api.admins.list({ perPage: 100 });
        const select = document.getElementById('adminFilter');
        if (!select) return;

        select.innerHTML = '<option value="">همه ادمین‌ها</option>';
        admins.data.forEach(admin => {
            select.innerHTML += `<option value="${admin.id}">${escapeHtml(admin.username)}</option>`;
        });
    } catch (error) {
        console.error('Failed to load admin filter:', error);
    }
}

function filterUsers() {
    usersPage = 1;
    loadUsers();
}

function openAddUserModal() {
    openModal('افزودن کاربر', `
        <form id="addUserForm" onsubmit="handleAddUser(event)">
            <div class="form-group">
                <label class="form-label">نام کاربری *</label>
                <input type="text" class="form-control" name="username" required>
            </div>
            <div class="form-group">
                <label class="form-label">تگ ساب‌اسکریپشن</label>
                <input type="text" class="form-control" name="sub_tag" placeholder="برای نمایش در کلاینت">
            </div>
            <div class="form-group">
                <label class="form-label">تاریخ انقضا (روز)</label>
                <input type="number" class="form-control" name="expire_days" value="30" min="0">
            </div>
            <div class="form-group">
                <label class="form-label">حجم ترافیک (GB)</label>
                <input type="number" class="form-control" name="data_limit_gb" value="0" min="0">
                <small class="text-muted">0 = نامحدود</small>
            </div>
            <div class="form-group">
                <label class="form-label">محدودیت کاربر همزمان</label>
                <input type="number" class="form-control" name="ip_limit" value="0" min="0">
                <small class="text-muted">0 = نامحدود</small>
            </div>
            <div class="form-group">
                <div class="form-switch">
                    <label class="switch">
                        <input type="checkbox" name="on_hold">
                        <span class="slider"></span>
                    </label>
                    <span>شروع بعد از اولین اتصال (On Hold)</span>
                </div>
            </div>
            <div class="form-group">
                <label class="form-label">یادداشت</label>
                <textarea class="form-control" name="note" rows="2"></textarea>
            </div>
        </form>
    `, [
        { text: 'انصراف', onclick: 'closeModal()' },
        { text: 'ایجاد', class: 'btn-primary', onclick: 'document.getElementById("addUserForm").requestSubmit()' }
    ]);
}

async function handleAddUser(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);

    const userData = {
        username: formData.get('username'),
        sub_tag: formData.get('sub_tag'),
        expire: formData.get('expire_days') ? parseInt(formData.get('expire_days')) * 86400 + Math.floor(Date.now() / 1000) : 0,
        data_limit: parseInt(formData.get('data_limit_gb') || 0) * 1024 * 1024 * 1024,
        ip_limit: parseInt(formData.get('ip_limit') || 0),
        on_hold: formData.get('on_hold') === 'on',
        note: formData.get('note')
    };

    try {
        await api.users.create(userData);
        showToast('کاربر با موفقیت ایجاد شد', 'success');
        closeModal();
        loadUsers();
    } catch (error) {
        showToast(error.message || 'خطا در ایجاد کاربر', 'error');
    }
}

async function showUserSub(userId) {
    try {
        const sub = await api.users.getSubscriptionLink(userId);
        openModal('لینک ساب‌اسکریپشن', `
            <div class="form-group">
                <label class="form-label">لینک ساب</label>
                <div class="d-flex gap-2">
                    <input type="text" class="form-control" value="${sub.link}" readonly id="subLink">
                    <button class="btn" onclick="copyText(document.getElementById('subLink').value)">کپی</button>
                </div>
            </div>
            <div class="form-group">
                <label class="form-label">QR Code</label>
                <div class="text-center">
                    <img src="${sub.qr_code}" alt="QR Code" style="max-width: 200px;">
                </div>
            </div>
        `);
    } catch (error) {
        showToast('خطا در دریافت لینک', 'error');
    }
}

async function showUserIPs(userId) {
    try {
        const ips = await api.users.getOnlineIPs(userId);
        const ipList = ips.length > 0
            ? ips.map(ip => `<div class="ip-box"><span class="ip-value">${ip}</span></div>`).join('')
            : '<p class="text-muted text-center">هیچ IP آنلاینی وجود ندارد</p>';

        openModal('IP های آنلاین', ipList);
    } catch (error) {
        showToast('خطا در دریافت IP ها', 'error');
    }
}

async function editUser(userId) {
    try {
        const user = await api.users.get(userId);
        openModal('ویرایش کاربر', `
            <form id="editUserForm" onsubmit="handleEditUser(event, '${userId}')">
                <div class="form-group">
                    <label class="form-label">نام کاربری</label>
                    <input type="text" class="form-control" name="username" value="${escapeHtml(user.username)}" required>
                </div>
                <div class="form-group">
                    <label class="form-label">تگ ساب‌اسکریپشن</label>
                    <input type="text" class="form-control" name="sub_tag" value="${escapeHtml(user.sub_tag || '')}">
                </div>
                <div class="form-group">
                    <label class="form-label">تاریخ انقضا</label>
                    <input type="datetime-local" class="form-control" name="expire" value="${user.expire ? new Date(user.expire * 1000).toISOString().slice(0, 16) : ''}">
                </div>
                <div class="form-group">
                    <label class="form-label">حجم ترافیک (GB)</label>
                    <input type="number" class="form-control" name="data_limit_gb" value="${user.data_limit ? Math.round(user.data_limit / (1024 * 1024 * 1024)) : 0}" min="0">
                </div>
                <div class="form-group">
                    <label class="form-label">محدودیت کاربر همزمان</label>
                    <input type="number" class="form-control" name="ip_limit" value="${user.ip_limit || 0}" min="0">
                </div>
                <div class="form-group">
                    <label class="form-label">وضعیت</label>
                    <select class="form-select" name="status">
                        <option value="active" ${user.status === 'active' ? 'selected' : ''}>فعال</option>
                        <option value="disabled" ${user.status === 'disabled' ? 'selected' : ''}>غیرفعال</option>
                        <option value="on_hold" ${user.status === 'on_hold' ? 'selected' : ''}>انتظار</option>
                    </select>
                </div>
                <div class="form-group">
                    <label class="form-label">یادداشت</label>
                    <textarea class="form-control" name="note" rows="2">${escapeHtml(user.note || '')}</textarea>
                </div>
            </form>
        `, [
            { text: 'انصراف', onclick: 'closeModal()' },
            { text: 'ریست ترافیک', class: 'btn-warning', onclick: `resetUserTraffic('${userId}')` },
            { text: 'ذخیره', class: 'btn-primary', onclick: 'document.getElementById("editUserForm").requestSubmit()' }
        ]);
    } catch (error) {
        showToast('خطا در دریافت اطلاعات کاربر', 'error');
    }
}

async function handleEditUser(e, userId) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);

    const expireDate = formData.get('expire');
    const userData = {
        username: formData.get('username'),
        sub_tag: formData.get('sub_tag'),
        expire: expireDate ? Math.floor(new Date(expireDate).getTime() / 1000) : 0,
        data_limit: parseInt(formData.get('data_limit_gb') || 0) * 1024 * 1024 * 1024,
        ip_limit: parseInt(formData.get('ip_limit') || 0),
        status: formData.get('status'),
        note: formData.get('note')
    };

    try {
        await api.users.update(userId, userData);
        showToast('کاربر با موفقیت ویرایش شد', 'success');
        closeModal();
        loadUsers();
    } catch (error) {
        showToast(error.message || 'خطا در ویرایش کاربر', 'error');
    }
}

async function resetUserTraffic(userId) {
    if (!confirm('آیا مطمئن هستید؟')) return;
    try {
        await api.users.resetTraffic(userId);
        showToast('ترافیک ریست شد', 'success');
        closeModal();
        loadUsers();
    } catch (error) {
        showToast('خطا در ریست ترافیک', 'error');
    }
}

async function deleteUser(userId) {
    if (!confirm('آیا مطمئن هستید که می‌خواهید این کاربر را حذف کنید؟')) return;
    try {
        await api.users.delete(userId);
        showToast('کاربر حذف شد', 'success');
        loadUsers();
    } catch (error) {
        showToast('خطا در حذف کاربر', 'error');
    }
}

async function exportUsers() {
    try {
        await api.users.export('csv');
        showToast('فایل در حال دانلود...', 'success');
    } catch (error) {
        showToast('خطا در دانلود فایل', 'error');
    }
}

// ============================================================================
// ADMINS MANAGEMENT
// ============================================================================

async function loadAdmins() {
    try {
        const response = await api.admins.list({ perPage: 50 });
        renderAdminsTable(response.data);
    } catch (error) {
        console.error('Failed to load admins:', error);
        showToast('خطا در بارگذاری ادمین‌ها', 'error');
    }
}

function renderAdminsTable(admins) {
    const tbody = document.getElementById('adminsTableBody');
    if (!tbody) return;

    if (!admins || admins.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">ادمینی یافت نشد</td></tr>`;
        return;
    }

    tbody.innerHTML = admins.map(admin => `
        <tr>
            <td><strong>${escapeHtml(admin.username)}</strong></td>
            <td><span class="badge ${admin.role === 'owner' ? 'info' : ''}">${getRoleLabel(admin.role)}</span></td>
            <td>${admin.users_count || 0}</td>
            <td>${formatBytes(admin.traffic_this_month || 0)}</td>
            <td>${formatBytes(admin.traffic_total || 0)}</td>
            <td><span class="badge ${admin.is_active ? 'success' : 'danger'}">${admin.is_active ? 'فعال' : 'غیرفعال'}</span></td>
            <td>
                ${admin.role !== 'owner' ? `
                    <button class="btn btn-icon btn-sm" onclick="editAdmin('${admin.id}')" title="ویرایش">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
                            <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
                        </svg>
                    </button>
                    <button class="btn btn-icon btn-sm btn-danger" onclick="deleteAdmin('${admin.id}')" title="حذف">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <polyline points="3 6 5 6 21 6"/>
                            <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                        </svg>
                    </button>
                ` : '<span class="text-muted">-</span>'}
            </td>
        </tr>
    `).join('');
}

function openAddAdminModal() {
    openModal('افزودن ادمین', `
        <form id="addAdminForm" onsubmit="handleAddAdmin(event)">
            <div class="form-group">
                <label class="form-label">نام کاربری *</label>
                <input type="text" class="form-control" name="username" required>
            </div>
            <div class="form-group">
                <label class="form-label">رمز عبور *</label>
                <input type="password" class="form-control" name="password" required>
            </div>
            <div class="form-group">
                <label class="form-label">نقش</label>
                <select class="form-select" name="role">
                    <option value="reseller">نماینده فروش</option>
                    <option value="admin">ادمین</option>
                </select>
            </div>
            <div class="form-group">
                <label class="form-label">محدودیت ترافیک ماهانه (GB)</label>
                <input type="number" class="form-control" name="traffic_limit" value="0" min="0">
                <small class="text-muted">0 = نامحدود</small>
            </div>
            <div class="form-group">
                <label class="form-label">محدودیت تعداد کاربر</label>
                <input type="number" class="form-control" name="user_limit" value="0" min="0">
                <small class="text-muted">0 = نامحدود</small>
            </div>
        </form>
    `, [
        { text: 'انصراف', onclick: 'closeModal()' },
        { text: 'ایجاد', class: 'btn-primary', onclick: 'document.getElementById("addAdminForm").requestSubmit()' }
    ]);
}

async function handleAddAdmin(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);

    const adminData = {
        username: formData.get('username'),
        password: formData.get('password'),
        role: formData.get('role'),
        traffic_limit: parseInt(formData.get('traffic_limit') || 0) * 1024 * 1024 * 1024,
        user_limit: parseInt(formData.get('user_limit') || 0)
    };

    try {
        await api.admins.create(adminData);
        showToast('ادمین با موفقیت ایجاد شد', 'success');
        closeModal();
        loadAdmins();
    } catch (error) {
        showToast(error.message || 'خطا در ایجاد ادمین', 'error');
    }
}

async function editAdmin(adminId) {
    try {
        const admin = await api.admins.get(adminId);
        openModal('ویرایش ادمین', `
            <form id="editAdminForm" onsubmit="handleEditAdmin(event, '${adminId}')">
                <div class="form-group">
                    <label class="form-label">نام کاربری</label>
                    <input type="text" class="form-control" name="username" value="${escapeHtml(admin.username)}" required>
                </div>
                <div class="form-group">
                    <label class="form-label">رمز عبور جدید</label>
                    <input type="password" class="form-control" name="password" placeholder="خالی بگذارید برای عدم تغییر">
                </div>
                <div class="form-group">
                    <label class="form-label">محدودیت ترافیک ماهانه (GB)</label>
                    <input type="number" class="form-control" name="traffic_limit" value="${admin.traffic_limit ? Math.round(admin.traffic_limit / (1024 * 1024 * 1024)) : 0}" min="0">
                </div>
                <div class="form-group">
                    <label class="form-label">محدودیت تعداد کاربر</label>
                    <input type="number" class="form-control" name="user_limit" value="${admin.user_limit || 0}" min="0">
                </div>
                <div class="form-group">
                    <div class="form-switch">
                        <label class="switch">
                            <input type="checkbox" name="is_active" ${admin.is_active ? 'checked' : ''}>
                            <span class="slider"></span>
                        </label>
                        <span>فعال</span>
                    </div>
                </div>
            </form>
        `, [
            { text: 'انصراف', onclick: 'closeModal()' },
            { text: 'ذخیره', class: 'btn-primary', onclick: 'document.getElementById("editAdminForm").requestSubmit()' }
        ]);
    } catch (error) {
        showToast('خطا در دریافت اطلاعات ادمین', 'error');
    }
}

async function handleEditAdmin(e, adminId) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);

    const adminData = {
        username: formData.get('username'),
        traffic_limit: parseInt(formData.get('traffic_limit') || 0) * 1024 * 1024 * 1024,
        user_limit: parseInt(formData.get('user_limit') || 0),
        is_active: formData.get('is_active') === 'on'
    };

    const password = formData.get('password');
    if (password) {
        adminData.password = password;
    }

    try {
        await api.admins.update(adminId, adminData);
        showToast('ادمین با موفقیت ویرایش شد', 'success');
        closeModal();
        loadAdmins();
    } catch (error) {
        showToast(error.message || 'خطا در ویرایش ادمین', 'error');
    }
}

async function deleteAdmin(adminId) {
    if (!confirm('آیا مطمئن هستید که می‌خواهید این ادمین را حذف کنید؟')) return;
    try {
        await api.admins.delete(adminId);
        showToast('ادمین حذف شد', 'success');
        loadAdmins();
    } catch (error) {
        showToast('خطا در حذف ادمین', 'error');
    }
}

// ============================================================================
// CORE SETTINGS
// ============================================================================

async function loadCoreSettings() {
    // Load protocols, inbounds, outbounds, etc.
    // This is a placeholder - implement based on your API
}

async function restartCore() {
    if (!confirm('آیا مطمئن هستید؟')) return;
    try {
        await api.core.restart();
        showToast('هسته در حال ریستارت...', 'success');
    } catch (error) {
        showToast('خطا در ریستارت هسته', 'error');
    }
}

async function stopCore() {
    if (!confirm('آیا مطمئن هستید؟ این کار همه اتصالات را قطع می‌کند.')) return;
    try {
        await api.core.stop();
        showToast('هسته متوقف شد', 'success');
    } catch (error) {
        showToast('خطا در توقف هسته', 'error');
    }
}

function showLogs() {
    // Show logs modal
    openModal('لاگ سیستم', `
        <div class="log-container" id="modalLogs" style="max-height: 400px;">
            <div class="log-empty">در حال بارگذاری...</div>
        </div>
    `);
    loadLogs();
}

async function loadLogs() {
    try {
        const logs = await api.core.getLogs({ lines: 100 });
        const container = document.getElementById('modalLogs');
        if (!container) return;

        if (!logs || logs.length === 0) {
            container.innerHTML = '<div class="log-empty">بدون لاگ</div>';
            return;
        }

        container.innerHTML = logs.map(log => `
            <div class="log-entry">
                <span class="log-time">${log.time}</span>
                <span class="log-level ${log.level}">${log.level}</span>
                <span class="log-message">${escapeHtml(log.message)}</span>
            </div>
        `).join('');
    } catch (error) {
        console.error('Failed to load logs:', error);
    }
}

async function saveRoutingSettings() {
    const settings = {
        dns_server: document.getElementById('dnsServer')?.value,
        dns_strategy: document.getElementById('dnsStrategy')?.value,
        blocked_sites: document.getElementById('blockedSites')?.value.split('\n').filter(s => s.trim()),
        direct_sites: document.getElementById('directSites')?.value.split('\n').filter(s => s.trim()),
        blocked_ports: document.getElementById('blockedPorts')?.value.split(',').filter(p => p.trim())
    };

    try {
        await api.routing.updateDNS(settings);
        showToast('تنظیمات ذخیره شد', 'success');
    } catch (error) {
        showToast('خطا در ذخیره تنظیمات', 'error');
    }
}

async function saveWarpSettings() {
    const settings = {
        enabled: document.getElementById('warpEnabled')?.checked,
        license_key: document.getElementById('warpLicense')?.value
    };

    try {
        await api.routing.updateWarpSettings(settings);
        showToast('تنظیمات WARP ذخیره شد', 'success');
    } catch (error) {
        showToast('خطا در ذخیره تنظیمات WARP', 'error');
    }
}

// ============================================================================
// NODES MANAGEMENT
// ============================================================================

async function loadNodes() {
    try {
        const response = await api.nodes.list({ perPage: 50 });
        renderNodesGrid(response.data);
    } catch (error) {
        console.error('Failed to load nodes:', error);
    }
}

function renderNodesGrid(nodes) {
    const container = document.getElementById('nodesGrid');
    if (!container) return;

    // Always show master node
    let html = `
        <div class="node-card glass">
            <div class="node-header">
                <div class="node-status online"></div>
                <div class="node-name">Master Node</div>
            </div>
            <div class="node-body">
                <div class="node-stat">
                    <span class="label">آدرس</span>
                    <span class="value">localhost</span>
                </div>
                <div class="node-stat">
                    <span class="label">وضعیت</span>
                    <span class="value badge success">آنلاین</span>
                </div>
            </div>
        </div>
    `;

    if (nodes && nodes.length > 0) {
        html += nodes.map(node => `
            <div class="node-card glass">
                <div class="node-header">
                    <div class="node-status ${node.status === 'online' ? 'online' : 'offline'}"></div>
                    <div class="node-name">${escapeHtml(node.name)}</div>
                    <div class="node-actions">
                        <button class="btn btn-icon btn-sm" onclick="editNode('${node.id}')">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
                                <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
                            </svg>
                        </button>
                    </div>
                </div>
                <div class="node-body">
                    <div class="node-stat">
                        <span class="label">آدرس</span>
                        <span class="value">${escapeHtml(node.address)}</span>
                    </div>
                    <div class="node-stat">
                        <span class="label">کاربران</span>
                        <span class="value">${node.users_count || 0}</span>
                    </div>
                    <div class="node-stat">
                        <span class="label">پینگ</span>
                        <span class="value">${node.ping || '--'} ms</span>
                    </div>
                </div>
            </div>
        `).join('');
    }

    container.innerHTML = html;
}

function openAddNodeModal() {
    openModal('افزودن نود', `
        <form id="addNodeForm" onsubmit="handleAddNode(event)">
            <div class="form-group">
                <label class="form-label">نام نود *</label>
                <input type="text" class="form-control" name="name" required>
            </div>
            <div class="form-group">
                <label class="form-label">آدرس سرور *</label>
                <input type="text" class="form-control" name="address" placeholder="IP یا دامنه" required>
            </div>
            <div class="form-group">
                <label class="form-label">پورت API</label>
                <input type="number" class="form-control" name="api_port" value="62050">
            </div>
            <div class="form-group">
                <label class="form-label">لینک تانل (اختیاری)</label>
                <input type="text" class="form-control" name="tunnel_url" placeholder="wss://...">
            </div>
        </form>
    `, [
        { text: 'انصراف', onclick: 'closeModal()' },
        { text: 'افزودن', class: 'btn-primary', onclick: 'document.getElementById("addNodeForm").requestSubmit()' }
    ]);
}

async function handleAddNode(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);

    const nodeData = {
        name: formData.get('name'),
        address: formData.get('address'),
        api_port: parseInt(formData.get('api_port') || 62050),
        tunnel_url: formData.get('tunnel_url')
    };

    try {
        await api.nodes.create(nodeData);
        showToast('نود با موفقیت اضافه شد', 'success');
        closeModal();
        loadNodes();
    } catch (error) {
        showToast(error.message || 'خطا در افزودن نود', 'error');
    }
}

// ============================================================================
// PANEL SETTINGS
// ============================================================================

async function loadPanelSettings() {
    try {
        const settings = await api.settings.getPanelSettings();

        document.getElementById('panelPort').value = settings.panel_port || 8443;
        document.getElementById('panelPath').value = settings.panel_path || '/dashboard';
        document.getElementById('subUrl').value = settings.sub_url || '';
        document.getElementById('subPort').value = settings.sub_port || 443;

        // Backup bot settings
        document.getElementById('backupBotToken').value = settings.backup_bot_token || '';
        document.getElementById('backupBotAdmin').value = settings.backup_bot_admin || '';
        document.getElementById('autoBackupEnabled').checked = settings.auto_backup || false;
    } catch (error) {
        console.error('Failed to load panel settings:', error);
    }
}

async function savePanelSettings() {
    const settings = {
        panel_port: parseInt(document.getElementById('panelPort')?.value || 8443),
        panel_path: document.getElementById('panelPath')?.value || '/dashboard',
        sub_port: parseInt(document.getElementById('subPort')?.value || 443)
    };

    try {
        await api.settings.updatePanelSettings(settings);
        showToast('تنظیمات پنل ذخیره شد', 'success');
    } catch (error) {
        showToast('خطا در ذخیره تنظیمات', 'error');
    }
}

async function saveBackupBotSettings() {
    const settings = {
        backup_bot_token: document.getElementById('backupBotToken')?.value,
        backup_bot_admin: document.getElementById('backupBotAdmin')?.value,
        auto_backup: document.getElementById('autoBackupEnabled')?.checked
    };

    try {
        await api.settings.updateTelegramSettings(settings);
        showToast('تنظیمات ربات ذخیره شد', 'success');
    } catch (error) {
        showToast('خطا در ذخیره تنظیمات', 'error');
    }
}

async function testBackupBot() {
    try {
        await api.settings.testTelegram();
        showToast('اتصال موفق!', 'success');
    } catch (error) {
        showToast('خطا در اتصال به ربات', 'error');
    }
}

// ============================================================================
// BACKUP & RESTORE
// ============================================================================

async function createBackup() {
    try {
        showToast('در حال ایجاد بکاپ...', 'info');
        await api.backup.create();
        showToast('بکاپ ایجاد شد', 'success');
        if (APP.currentPage === 'database') {
            loadBackups();
        }
    } catch (error) {
        showToast('خطا در ایجاد بکاپ', 'error');
    }
}

async function createFullBackup() {
    await createBackup();
}

async function restoreBackup(file) {
    if (!file) return;
    if (!confirm('آیا مطمئن هستید؟ این کار داده‌های فعلی را جایگزین می‌کند.')) return;

    try {
        showToast('در حال بازیابی...', 'info');
        await api.backup.upload(file);
        showToast('بکاپ با موفقیت بازیابی شد. پنل در حال ریستارت...', 'success');
        setTimeout(() => location.reload(), 3000);
    } catch (error) {
        showToast('خطا در بازیابی بکاپ', 'error');
    }
}

async function restoreFromFile(file) {
    await restoreBackup(file);
}

async function loadBackups() {
    try {
        const backups = await api.backup.list();
        const tbody = document.getElementById('backupsTableBody');
        if (!tbody) return;

        if (!backups || backups.length === 0) {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">بکاپی وجود ندارد</td></tr>`;
            return;
        }

        tbody.innerHTML = backups.map(backup => `
            <tr>
                <td>${formatDateTime(backup.created_at)}</td>
                <td>${formatBytes(backup.size)}</td>
                <td><span class="badge">${backup.type || 'کامل'}</span></td>
                <td>
                    <button class="btn btn-sm" onclick="downloadBackup('${backup.id}')">دانلود</button>
                    <button class="btn btn-sm btn-danger" onclick="deleteBackup('${backup.id}')">حذف</button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Failed to load backups:', error);
    }
}

async function downloadBackup(backupId) {
    try {
        await api.backup.download(backupId);
    } catch (error) {
        showToast('خطا در دانلود بکاپ', 'error');
    }
}

async function deleteBackup(backupId) {
    if (!confirm('آیا مطمئن هستید؟')) return;
    try {
        await api.backup.delete(backupId);
        showToast('بکاپ حذف شد', 'success');
        loadBackups();
    } catch (error) {
        showToast('خطا در حذف بکاپ', 'error');
    }
}

// Import from other panels
async function importFromPanel() {
    const panelType = document.getElementById('importPanelType')?.value;
    const fileInput = document.getElementById('importDbFile');
    const file = fileInput?.files[0];

    if (!panelType) {
        showToast('لطفاً نوع پنل را انتخاب کنید', 'warning');
        return;
    }
    if (!file) {
        showToast('لطفاً فایل دیتابیس را انتخاب کنید', 'warning');
        return;
    }

    try {
        showToast('در حال ایمپورت...', 'info');

        const formData = new FormData();
        formData.append('file', file);
        formData.append('panel_type', panelType);

        const response = await http.upload('/import', formData);

        if (response.errors && response.errors.length > 0) {
            showToast(`ایمپورت با ${response.errors.length} خطا انجام شد`, 'warning');
            console.log('Import errors:', response.errors);
        } else {
            showToast(`${response.imported_count || 0} کاربر ایمپورت شد`, 'success');
        }
    } catch (error) {
        showToast(error.message || 'خطا در ایمپورت', 'error');
    }
}

// ============================================================================
// MESSAGE & NOTIFICATIONS
// ============================================================================

async function loadSentMessages() {
    try {
        // Load sent messages from API
        const messages = await http.get('/messages');
        renderSentMessages(messages);
    } catch (error) {
        console.error('Failed to load messages:', error);
    }
}

function renderSentMessages(messages) {
    const container = document.getElementById('sentMessagesList');
    if (!container) return;

    if (!messages || messages.length === 0) {
        container.innerHTML = '<p class="text-center text-muted">پیامی ارسال نشده است</p>';
        return;
    }

    container.innerHTML = messages.map(msg => `
        <div class="message-item glass">
            <div class="message-header">
                <strong>${escapeHtml(msg.title)}</strong>
                <small>${formatDateTime(msg.created_at)}</small>
            </div>
            <div class="message-body">${escapeHtml(msg.content)}</div>
            <div class="message-footer">
                <small class="text-muted">ارسال به: ${msg.recipients}</small>
            </div>
        </div>
    `).join('');
}

async function sendMessage() {
    const recipients = document.getElementById('messageRecipients')?.value;
    const title = document.getElementById('messageTitle')?.value;
    const content = document.getElementById('messageContent')?.value;

    if (!title || !content) {
        showToast('عنوان و متن پیام الزامی است', 'warning');
        return;
    }

    try {
        await http.post('/messages', { recipients, title, content });
        showToast('پیام ارسال شد', 'success');
        document.getElementById('messageTitle').value = '';
        document.getElementById('messageContent').value = '';
        loadSentMessages();
    } catch (error) {
        showToast('خطا در ارسال پیام', 'error');
    }
}

// ============================================================================
// BOT MANAGEMENT
// ============================================================================

async function loadBotSettings() {
    try {
        const settings = await api.settings.getTelegramSettings();
        document.getElementById('salesBotToken').value = settings.sales_bot_token || '';
        document.getElementById('salesBotAdmins').value = settings.sales_bot_admins || '';
        document.getElementById('salesBotEnabled').checked = settings.sales_bot_enabled || false;
    } catch (error) {
        console.error('Failed to load bot settings:', error);
    }
}

async function loadPlans() {
    try {
        const plans = await api.payment.getPlans();
        renderPlansTable(plans);
    } catch (error) {
        console.error('Failed to load plans:', error);
    }
}

function renderPlansTable(plans) {
    const tbody = document.getElementById('plansTableBody');
    if (!tbody) return;

    if (!plans || plans.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">پلنی وجود ندارد</td></tr>`;
        return;
    }

    tbody.innerHTML = plans.map(plan => `
        <tr>
            <td>${escapeHtml(plan.name)}</td>
            <td>${plan.days}</td>
            <td>${plan.data_gb}</td>
            <td>${plan.price.toLocaleString()} تومان</td>
            <td><span class="badge ${plan.is_trial ? 'warning' : ''}">${plan.is_trial ? 'تست' : 'خیر'}</span></td>
            <td>
                <button class="btn btn-icon btn-sm" onclick="editPlan('${plan.id}')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/>
                        <path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/>
                    </svg>
                </button>
                <button class="btn btn-icon btn-sm btn-danger" onclick="deletePlan('${plan.id}')">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <polyline points="3 6 5 6 21 6"/>
                        <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/>
                    </svg>
                </button>
            </td>
        </tr>
    `).join('');
}

async function saveSalesBotSettings() {
    const settings = {
        sales_bot_token: document.getElementById('salesBotToken')?.value,
        sales_bot_admins: document.getElementById('salesBotAdmins')?.value,
        sales_bot_enabled: document.getElementById('salesBotEnabled')?.checked
    };

    try {
        await api.settings.updateTelegramSettings(settings);
        showToast('تنظیمات ربات ذخیره شد', 'success');
    } catch (error) {
        showToast('خطا در ذخیره تنظیمات', 'error');
    }
}

async function testSalesBot() {
    try {
        await api.settings.testTelegram();
        showToast('اتصال موفق!', 'success');
    } catch (error) {
        showToast('خطا در اتصال به ربات', 'error');
    }
}

// ============================================================================
// AI INTEGRATION
// ============================================================================

async function loadAISettings() {
    try {
        const settings = await api.settings.getAISettings();
        document.getElementById('aiService').value = settings.service || 'openai';
        document.getElementById('aiApiKey').value = settings.api_key || '';
        document.getElementById('aiEnabled').checked = settings.enabled || false;
    } catch (error) {
        console.error('Failed to load AI settings:', error);
    }
}

async function saveAISettings() {
    const settings = {
        service: document.getElementById('aiService')?.value,
        api_key: document.getElementById('aiApiKey')?.value,
        enabled: document.getElementById('aiEnabled')?.checked
    };

    try {
        await api.settings.updateAISettings(settings);
        showToast('تنظیمات AI ذخیره شد', 'success');
    } catch (error) {
        showToast('خطا در ذخیره تنظیمات', 'error');
    }
}

async function testAI() {
    try {
        await api.settings.testAI();
        showToast('اتصال موفق!', 'success');
    } catch (error) {
        showToast('خطا در اتصال به AI', 'error');
    }
}

async function sendAIMessage() {
    const input = document.getElementById('aiInput');
    const message = input?.value.trim();
    if (!message) return;

    // Add user message to chat
    addAIMessage(message, 'user');
    input.value = '';

    try {
        const response = await http.post('/ai/chat', { message });
        addAIMessage(response.reply, 'bot');
    } catch (error) {
        addAIMessage('متأسفم، خطایی رخ داد. لطفاً دوباره تلاش کنید.', 'bot');
    }
}

function addAIMessage(content, type) {
    const container = document.getElementById('aiMessages');
    if (!container) return;

    const messageDiv = document.createElement('div');
    messageDiv.className = `ai-message ${type}`;
    messageDiv.innerHTML = `<div class="message-content">${escapeHtml(content)}</div>`;
    container.appendChild(messageDiv);
    container.scrollTop = container.scrollHeight;
}

async function aiAutoFix() {
    try {
        showToast('در حال تحلیل سیستم...', 'info');
        const result = await api.system.autoFix();
        showToast(result.message || 'عملیات انجام شد', 'success');
    } catch (error) {
        showToast('خطا در عملیات', 'error');
    }
}

async function aiOptimize() {
    addAIMessage('لطفاً تنظیمات سیستم را بررسی کرده و پیشنهادات بهینه‌سازی را ارائه بده.', 'user');
    try {
        const response = await http.post('/ai/optimize');
        addAIMessage(response.suggestions, 'bot');
    } catch (error) {
        addAIMessage('متأسفم، خطایی رخ داد.', 'bot');
    }
}

async function aiObfuscate() {
    addAIMessage('بهترین تنظیمات مخفی‌سازی و Obfuscation را برای محیط فعلی پیشنهاد بده.', 'user');
    try {
        const response = await http.post('/ai/obfuscate');
        addAIMessage(response.suggestions, 'bot');
    } catch (error) {
        addAIMessage('متأسفم، خطایی رخ داد.', 'bot');
    }
}

// ============================================================================
// TEMPLATE MANAGEMENT
// ============================================================================

let selectedTemplateType = null;

function selectTemplate(type) {
    selectedTemplateType = type;
    document.getElementById('templateEditor').style.display = 'block';
    loadTemplateContent(type);
}

async function loadTemplateContent(type) {
    try {
        const template = await api.templates.getSubscriptionTemplate();
        document.getElementById('templateCode').value = template.html || '';
    } catch (error) {
        console.error('Failed to load template:', error);
    }
}

function loadTemplateFile(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
        document.getElementById('templateCode').value = e.target.result;
    };
    reader.readAsText(file);
}

async function saveTemplate() {
    const code = document.getElementById('templateCode')?.value;
    if (!code) {
        showToast('کد قالب نمی‌تواند خالی باشد', 'warning');
        return;
    }

    try {
        await api.templates.updateSubscriptionTemplate({ html: code });
        showToast('قالب ذخیره شد', 'success');
    } catch (error) {
        showToast('خطا در ذخیره قالب', 'error');
    }
}

function previewTemplate() {
    const code = document.getElementById('templateCode')?.value;
    const win = window.open('', '_blank');
    win.document.write(code);
}

// ============================================================================
// MOBILE PROFILE
// ============================================================================

function loadMobileProfile() {
    const user = APP.user;
    if (!user) return;

    updateElement('mobileProfileUsers', user.users_count || 0);
    updateElement('mobileProfileTraffic', formatBytes(user.traffic_used || 0));
    updateElement('mobileProfileDays', user.active_days || 0);
}

function openChangePasswordModal() {
    openModal('تغییر رمز عبور', `
        <form id="changePasswordForm" onsubmit="handleChangePassword(event)">
            <div class="form-group">
                <label class="form-label">رمز عبور فعلی</label>
                <input type="password" class="form-control" name="current_password" required>
            </div>
            <div class="form-group">
                <label class="form-label">رمز عبور جدید</label>
                <input type="password" class="form-control" name="new_password" required minlength="6">
            </div>
            <div class="form-group">
                <label class="form-label">تکرار رمز عبور جدید</label>
                <input type="password" class="form-control" name="confirm_password" required minlength="6">
            </div>
        </form>
    `, [
        { text: 'انصراف', onclick: 'closeModal()' },
        { text: 'تغییر', class: 'btn-primary', onclick: 'document.getElementById("changePasswordForm").requestSubmit()' }
    ]);
}

async function handleChangePassword(e) {
    e.preventDefault();
    const form = e.target;
    const formData = new FormData(form);

    const newPassword = formData.get('new_password');
    const confirmPassword = formData.get('confirm_password');

    if (newPassword !== confirmPassword) {
        showToast('رمز عبور جدید با تکرار آن مطابقت ندارد', 'error');
        return;
    }

    try {
        await auth.changePassword(
            formData.get('current_password'),
            newPassword,
            confirmPassword
        );
        showToast('رمز عبور تغییر کرد', 'success');
        closeModal();
    } catch (error) {
        showToast(error.message || 'خطا در تغییر رمز عبور', 'error');
    }
}

// ============================================================================
// POWER ACTIONS
// ============================================================================

async function restartPanel() {
    if (!confirm('آیا مطمئن هستید که می‌خواهید پنل را ریستارت کنید؟')) return;
    try {
        await api.system.restartService('mxui');
        showToast('پنل در حال ریستارت...', 'success');
    } catch (error) {
        showToast('خطا در ریستارت پنل', 'error');
    }
}

async function restartServer() {
    if (!confirm('آیا مطمئن هستید که می‌خواهید سرور را ریستارت کنید؟ این کار همه اتصالات را قطع می‌کند.')) return;
    try {
        await api.system.reboot();
        showToast('سرور در حال ریستارت...', 'success');
    } catch (error) {
        showToast('خطا در ریستارت سرور', 'error');
    }
}

async function refreshSystemStats() {
    try {
        const info = await api.system.getStats();
        updateSystemStats(info);
        showToast('بروزرسانی شد', 'success');
    } catch (error) {
        showToast('خطا در بروزرسانی', 'error');
    }
}

function clearLogs() {
    const container = document.getElementById('connectionLogs');
    if (container) {
        container.innerHTML = '<div class="log-empty">بدون لاگ</div>';
    }
}

// ============================================================================
// REAL-TIME UPDATES
// ============================================================================

function setupRealTimeUpdates() {
    // Update dashboard every 30 seconds
    APP.intervals.dashboard = setInterval(() => {
        if (APP.currentPage === 'home') {
            loadDashboardData();
        }
    }, 30000);

    // Setup WebSocket connection
    setupWebSocket();
}

function setupWebSocket() {
    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${location.host}/ws`;

    try {
        APP.wsConnection = new WebSocket(wsUrl);

        APP.wsConnection.onopen = () => {
            console.log('WebSocket connected');
        };

        APP.wsConnection.onmessage = (event) => {
            handleWebSocketMessage(JSON.parse(event.data));
        };

        APP.wsConnection.onclose = () => {
            console.log('WebSocket disconnected');
            // Reconnect after 5 seconds
            setTimeout(setupWebSocket, 5000);
        };

        APP.wsConnection.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    } catch (error) {
        console.error('Failed to setup WebSocket:', error);
    }
}

function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'stats_update':
            if (APP.currentPage === 'home') {
                updateElement('statOnlineUsers', `${data.online_users} آنلاین`);
            }
            break;
        case 'notification':
            showToast(data.message, data.level || 'info');
            document.getElementById('notificationDot')?.classList.add('active');
            break;
        case 'user_connected':
        case 'user_disconnected':
            // Update user list if on users page
            if (APP.currentPage === 'users') {
                loadUsers();
            }
            break;
    }
}

// ============================================================================
// MODAL
// ============================================================================

function openModal(title, content, buttons = []) {
    const overlay = document.getElementById('modalOverlay');
    const container = document.getElementById('modalContainer');

    let buttonsHtml = '';
    if (buttons.length > 0) {
        buttonsHtml = `<div class="modal-footer">
            ${buttons.map(btn => `
                <button class="btn ${btn.class || ''}" onclick="${btn.onclick}">${btn.text}</button>
            `).join('')}
        </div>`;
    }

    container.innerHTML = `
        <div class="modal-header">
            <h3 class="modal-title">${title}</h3>
            <button class="modal-close" onclick="closeModal()">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        </div>
        <div class="modal-body">${content}</div>
        ${buttonsHtml}
    `;

    overlay.classList.add('active');
}

function closeModal() {
    document.getElementById('modalOverlay')?.classList.remove('active');
}

// ============================================================================
// TOAST NOTIFICATIONS
// ============================================================================

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            ${getToastIcon(type)}
        </svg>
        <span>${message}</span>
    `;

    container.appendChild(toast);

    // Remove after 4 seconds
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(-20px)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

function getToastIcon(type) {
    const icons = {
        success: '<polyline points="20 6 9 17 4 12"/>',
        error: '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>',
        warning: '<path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
        info: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>'
    };
    return icons[type] || icons.info;
}

// ============================================================================
// PAGINATION
// ============================================================================

function renderPagination(containerId, data, callback) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const { page, lastPage, total } = data;
    if (lastPage <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = '';

    // Previous button
    html += `<button class="pagination-btn" ${page <= 1 ? 'disabled' : ''} onclick="(${callback})(${page - 1})">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="9 18 15 12 9 6"/>
        </svg>
    </button>`;

    // Page numbers
    const start = Math.max(1, page - 2);
    const end = Math.min(lastPage, page + 2);

    if (start > 1) {
        html += `<button class="pagination-btn" onclick="(${callback})(1)">1</button>`;
        if (start > 2) html += `<span class="pagination-ellipsis">...</span>`;
    }

    for (let i = start; i <= end; i++) {
        html += `<button class="pagination-btn ${i === page ? 'active' : ''}" onclick="(${callback})(${i})">${i}</button>`;
    }

    if (end < lastPage) {
        if (end < lastPage - 1) html += `<span class="pagination-ellipsis">...</span>`;
        html += `<button class="pagination-btn" onclick="(${callback})(${lastPage})">${lastPage}</button>`;
    }

    // Next button
    html += `<button class="pagination-btn" ${page >= lastPage ? 'disabled' : ''} onclick="(${callback})(${page + 1})">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <polyline points="15 18 9 12 15 6"/>
        </svg>
    </button>`;

    container.innerHTML = html;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function updateElement(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function updateProgressBar(id, percent) {
    const el = document.getElementById(id);
    if (el) {
        el.style.width = `${Math.min(100, percent)}%`;
        // Change color based on value
        if (percent >= 90) {
            el.classList.add('danger');
            el.classList.remove('warning');
        } else if (percent >= 70) {
            el.classList.add('warning');
            el.classList.remove('danger');
        } else {
            el.classList.remove('warning', 'danger');
        }
    }
}

function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function formatBytesSpeed(bytes) {
    if (bytes < 1024) return bytes + ' B/s';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB/s';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB/s';
}

function formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${days} روز ${hours} ساعت ${minutes} دقیقه`;
}

function formatDate(timestamp) {
    if (!timestamp) return '-';
    const date = new Date(timestamp * 1000);
    return new Intl.DateTimeFormat('fa-IR', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    }).format(date);
}

function formatDateTime(timestamp) {
    if (!timestamp) return '-';
    const date = new Date(timestamp * 1000);
    return new Intl.DateTimeFormat('fa-IR', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    }).format(date);
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('کپی شد', 'success');
    }).catch(() => {
        // Fallback
        const input = document.createElement('input');
        input.value = text;
        document.body.appendChild(input);
        input.select();
        document.execCommand('copy');
        document.body.removeChild(input);
        showToast('کپی شد', 'success');
    });
}

// ============================================================================
// PWA & SERVICE WORKER
// ============================================================================

if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
        navigator.serviceWorker.register('sw.js')
            .then(reg => console.log('SW registered:', reg.scope))
            .catch(err => console.log('SW registration failed:', err));
    });
}
