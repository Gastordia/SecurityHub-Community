// Main Application Logic
class DocumentationApp {
    constructor() {
        this.endpoints = [];
        this.currentSection = null;
        this.darkMode = localStorage.getItem('darkMode') === 'true';
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadEndpoints();
        this.applyTheme();
        this.renderNavigation();
        this.renderContent('intro');
    }

    setupEventListeners() {
        // Search functionality
        const searchInput = document.getElementById('searchInput');
        searchInput.addEventListener('input', (e) => this.handleSearch(e.target.value));

        // Navigation clicks
        document.addEventListener('click', (e) => {
            if (e.target.matches('.nav-menu a')) {
                e.preventDefault();
                const section = e.target.getAttribute('data-section');
                this.renderContent(section);
                this.updateActiveNav(e.target);
            }
        });

        // Toggle sidebar on mobile
        document.getElementById('toggleSidebar')?.addEventListener('click', () => {
            document.getElementById('sidebar').classList.toggle('open');
        });

        // Dark mode toggle
        document.getElementById('toggleDarkMode')?.addEventListener('click', () => {
            this.toggleDarkMode();
        });

        // Print button
        document.getElementById('printBtn')?.addEventListener('click', () => {
            window.print();
        });
    }

    loadEndpoints() {
        // Parse endpoints from data
        if (typeof ENDPOINT_DATA !== 'undefined') {
            this.endpoints = ENDPOINT_DATA;
        }
    }

    renderNavigation() {
        const navMenu = document.getElementById('navMenu');
        const endpointList = document.getElementById('endpointList');
        
        if (!endpointList) return;

        // Group endpoints by category
        const categories = this.groupEndpointsByCategory();
        
        Object.entries(categories).forEach(([category, endpoints]) => {
            const categorySection = document.createElement('div');
            categorySection.className = 'nav-section';
            
            const categoryTitle = document.createElement('h3');
            categoryTitle.textContent = this.getCategoryName(category);
            categorySection.appendChild(categoryTitle);
            
            const categoryList = document.createElement('ul');
            
            endpoints.forEach((endpoint, index) => {
                const listItem = document.createElement('li');
                const link = document.createElement('a');
                link.href = `#${endpoint.id}`;
                link.setAttribute('data-section', endpoint.id);
                link.textContent = `${endpoint.number} ${endpoint.name}`;
                
                if (index === 0) {
                    link.classList.add('active');
                }
                
                listItem.appendChild(link);
                categoryList.appendChild(listItem);
            });
            
            categorySection.appendChild(categoryList);
            endpointList.appendChild(categorySection);
        });
    }

    groupEndpointsByCategory() {
        const categories = {};
        
        this.endpoints.forEach(endpoint => {
            const category = endpoint.category || 'other';
            if (!categories[category]) {
                categories[category] = [];
            }
            categories[category].push(endpoint);
        });
        
        return categories;
    }

    getCategoryName(category) {
        const names = {
            'core': 'Core Vulnerability DB',
            'upload': 'Upload & Parser',
            'asset': 'Asset Intelligence',
            'threat': 'Threat Intelligence',
            'correlation': 'Correlation Engine',
            'profiling': 'Dynamic Profiling',
            'fusion': 'Intelligence Fusion',
            'intelligence': 'Enhanced Intelligence'
        };
        return names[category] || category;
    }

    renderContent(section) {
        const contentBody = document.getElementById('contentBody');
        if (!contentBody) return;

        if (section === 'intro') {
            contentBody.innerHTML = this.renderIntro();
        } else if (section === 'assessment') {
            contentBody.innerHTML = this.renderAssessment();
        } else {
            const endpoint = this.endpoints.find(e => e.id === section);
            if (endpoint) {
                contentBody.innerHTML = this.renderEndpoint(endpoint);
            }
        }

        // Update page title
        const pageTitle = document.getElementById('pageTitle');
        if (pageTitle) {
            if (section === 'assessment') {
                pageTitle.textContent = 'Functionality Assessment';
            } else if (section === 'intro') {
                pageTitle.textContent = 'Vulnerability Endpoints Documentation';
            } else {
                const endpoint = this.endpoints.find(e => e.id === section);
                if (endpoint) {
                    pageTitle.textContent = `${endpoint.number} ${endpoint.name}`;
                }
            }
        }
    }

    renderIntro() {
        return `
            <div class="assessment-section">
                <h2>Welcome to SecurityHub Documentation</h2>
                <p style="color: var(--text-secondary); margin-bottom: 1.5rem;">
                    Comprehensive documentation for all vulnerability management endpoints in SecurityHub.
                </p>
                <div class="assessment-grid">
                    <div class="stat-card">
                        <h3 style="color: var(--primary-color);">63</h3>
                        <p>Total Endpoints</p>
                    </div>
                    <div class="stat-card">
                        <h3 style="color: var(--success-color);">25</h3>
                        <p>Fully Functional</p>
                    </div>
                    <div class="stat-card">
                        <h3 style="color: var(--warning-color);">30</h3>
                        <p>With Issues</p>
                    </div>
                    <div class="stat-card">
                        <h3 style="color: var(--danger-color);">8</h3>
                        <p>Dependency Issues</p>
                    </div>
                </div>
                <div style="margin-top: 2rem;">
                    <h3 style="margin-bottom: 1rem;">Quick Navigation</h3>
                    <p style="color: var(--text-secondary);">
                        Use the sidebar to navigate through all endpoint categories. Each endpoint includes:
                    </p>
                    <ul style="margin-top: 1rem; margin-left: 1.5rem; color: var(--text-secondary);">
                        <li>Endpoint details and HTTP methods</li>
                        <li>Functionality description</li>
                        <li>Implementation details</li>
                        <li>Dependencies and requirements</li>
                        <li>Status and known issues</li>
                    </ul>
                </div>
            </div>
        `;
    }

    renderEndpoint(endpoint) {
        const method = endpoint.method?.toUpperCase() || 'GET';
        const statusClass = this.getStatusClass(endpoint.status);
        const statusText = this.getStatusText(endpoint.status);

        return `
            <div class="endpoint-card">
                <div class="endpoint-header">
                    <div class="endpoint-title">
                        <h3>
                            <span class="method ${method.toLowerCase()}">${method}</span>
                            ${endpoint.name}
                        </h3>
                        <div class="endpoint-path">${endpoint.path}</div>
                    </div>
                    <span class="status-badge ${statusClass}">
                        <i class="fas ${this.getStatusIcon(endpoint.status)}"></i>
                        ${statusText}
                    </span>
                </div>

                <div class="endpoint-section">
                    <h4>What it does</h4>
                    <p>${endpoint.description || 'No description available.'}</p>
                </div>

                <div class="endpoint-section">
                    <h4>How it works</h4>
                    <ol>
                        ${endpoint.howItWorks?.map(step => `<li>${step}</li>`).join('') || '<li>No implementation details available.</li>'}
                    </ol>
                </div>

                <div class="endpoint-section">
                    <h4>Dependencies</h4>
                    <div class="dependencies-list">
                        ${this.renderDependencies(endpoint.dependencies)}
                    </div>
                </div>

                <div class="endpoint-section">
                    <h4>Functionality Status</h4>
                    <p>${endpoint.status || 'Status unknown'}</p>
                    ${endpoint.issues?.length ? `
                        <div class="issue-list">
                            ${endpoint.issues.map(issue => `
                                <div class="issue-item">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    <span><strong>${issue.type}:</strong> ${issue.message}</span>
                                </div>
                            `).join('')}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    renderDependencies(dependencies) {
        if (!dependencies || dependencies.length === 0) {
            return '<span class="dependency-tag">No dependencies</span>';
        }

        return dependencies.map(dep => {
            const icon = this.getDependencyIcon(dep.type);
            return `
                <span class="dependency-tag">
                    <i class="fas ${icon}"></i>
                    ${dep.name}
                </span>
            `;
        }).join('');
    }

    getDependencyIcon(type) {
        const icons = {
            'model': 'fa-database',
            'service': 'fa-cogs',
            'serializer': 'fa-code',
            'cache': 'fa-memory',
            'external': 'fa-cloud'
        };
        return icons[type] || 'fa-circle';
    }

    getStatusClass(status) {
        if (!status) return 'dependency-issues';
        if (status.includes('FULLY FUNCTIONAL')) return 'fully-functional';
        if (status.includes('FUNCTIONAL') || status.includes('ISSUE')) return 'functional-issues';
        return 'dependency-issues';
    }

    getStatusText(status) {
        if (!status) return 'Unknown';
        if (status.includes('FULLY FUNCTIONAL')) return 'Fully Functional';
        if (status.includes('FUNCTIONAL')) return 'Functional with Issues';
        return 'Dependency Issues';
    }

    getStatusIcon(status) {
        if (!status) return 'fa-question-circle';
        if (status.includes('FULLY FUNCTIONAL')) return 'fa-check-circle';
        if (status.includes('FUNCTIONAL')) return 'fa-exclamation-circle';
        return 'fa-times-circle';
    }

    renderAssessment() {
        return `
            <div class="assessment-section">
                <h2>Functionality Assessment</h2>
                <p style="color: var(--text-secondary); margin-bottom: 2rem;">
                    Comprehensive analysis of endpoint functionality, security issues, and recommendations.
                </p>

                <div class="issue-category">
                    <h3>Security Issues (High Priority)</h3>
                    <ul>
                        <li><strong>IDOR Vulnerabilities:</strong> 15+ endpoints lack proper tenant scoping</li>
                        <li><strong>Missing Tenant Scoping:</strong> 20+ endpoints show data across tenants</li>
                        <li><strong>Legacy Scope Field:</strong> Core endpoints use deprecated scope field</li>
                    </ul>
                </div>

                <div class="issue-category">
                    <h3>Architectural Issues (Medium Priority)</h3>
                    <ul>
                        <li><strong>Service Layer Inconsistency:</strong> Multiple profiling approaches</li>
                        <li><strong>Direct Model Access:</strong> Dashboard endpoints bypass service layer</li>
                        <li><strong>Missing Field Validation:</strong> Some endpoints reference non-existent fields</li>
                    </ul>
                </div>

                <div class="issue-category">
                    <h3>Dependency Issues (Medium Priority)</h3>
                    <ul>
                        <li><strong>Missing Service Methods:</strong> 20+ methods need verification</li>
                        <li><strong>External API Dependencies:</strong> CISA KEV, EPSS, NVD APIs required</li>
                        <li><strong>File Dependencies:</strong> CWE data file must exist</li>
                    </ul>
                </div>

                <div class="issue-category">
                    <h3>Performance Issues (Low Priority)</h3>
                    <ul>
                        <li><strong>No Pagination:</strong> getallVulndbdata returns all records</li>
                        <li><strong>Heavy Computation:</strong> Correlation/fusion endpoints need optimization</li>
                    </ul>
                </div>
            </div>
        `;
    }

    handleSearch(query) {
        const normalizedQuery = query.toLowerCase().trim();
        
        if (!normalizedQuery) {
            this.renderNavigation();
            return;
        }

        const filtered = this.endpoints.filter(endpoint => {
            return endpoint.name.toLowerCase().includes(normalizedQuery) ||
                   endpoint.path.toLowerCase().includes(normalizedQuery) ||
                   endpoint.description?.toLowerCase().includes(normalizedQuery);
        });

        // Update navigation with filtered results
        const navMenu = document.getElementById('navMenu');
        const endpointList = document.getElementById('endpointList');
        
        if (endpointList) {
            endpointList.innerHTML = '';
            
            if (filtered.length === 0) {
                endpointList.innerHTML = '<li style="padding: 1rem; color: var(--text-muted);">No endpoints found</li>';
            } else {
                filtered.forEach(endpoint => {
                    const listItem = document.createElement('li');
                    const link = document.createElement('a');
                    link.href = `#${endpoint.id}`;
                    link.setAttribute('data-section', endpoint.id);
                    link.textContent = `${endpoint.number} ${endpoint.name}`;
                    listItem.appendChild(link);
                    endpointList.appendChild(listItem);
                });
            }
        }
    }

    updateActiveNav(activeLink) {
        document.querySelectorAll('.nav-menu a').forEach(link => {
            link.classList.remove('active');
        });
        activeLink.classList.add('active');
    }

    toggleDarkMode() {
        this.darkMode = !this.darkMode;
        localStorage.setItem('darkMode', this.darkMode);
        this.applyTheme();
    }

    applyTheme() {
        const root = document.documentElement;
        if (this.darkMode) {
            root.setAttribute('data-theme', 'dark');
            document.getElementById('toggleDarkMode').innerHTML = '<i class="fas fa-sun"></i>';
        } else {
            root.removeAttribute('data-theme');
            document.getElementById('toggleDarkMode').innerHTML = '<i class="fas fa-moon"></i>';
        }
    }
}

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.app = new DocumentationApp();
});
