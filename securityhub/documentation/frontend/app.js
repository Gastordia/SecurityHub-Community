let apiData = null;
let filteredData = null;

// Load JSON data - supports both embedded JSON and fetch
function loadAPIData() {
    try {
        // First, try to use embedded JSON data (works with file:// protocol)
        if (window.API_REFERENCE_DATA) {
            apiData = window.API_REFERENCE_DATA;
            filteredData = apiData;
            updateHeaderInfo();
            initializeApp();
            return;
        }
        
        // Fallback: try to fetch from server (works with http:// protocol)
        // This is useful when serving via a web server and you want to always get the latest JSON
        if (window.location.protocol === 'http:' || window.location.protocol === 'https:') {
            fetch('../api-reference.json')
                .then(response => response.json())
                .then(data => {
                    apiData = data;
                    filteredData = apiData;
                    updateHeaderInfo();
                    initializeApp();
                })
                .catch(error => {
                    console.warn('Failed to fetch JSON, using embedded data if available:', error);
                    // If fetch fails but we have embedded data, use that
                    if (window.API_REFERENCE_DATA) {
                        apiData = window.API_REFERENCE_DATA;
                        filteredData = apiData;
                        updateHeaderInfo();
                        initializeApp();
                    } else {
                        document.getElementById('sectionsContainer').innerHTML = 
                            '<div class="error" style="padding: 40px; text-align: center; color: var(--danger-color);">' +
                            'Error loading API reference. Please ensure api-reference.json is available or use a local web server.<br><br>' +
                            'Run: <code style="background: #f1f5f9; padding: 5px 10px; border-radius: 4px;">python3 -m http.server 8000</code>' +
                            '</div>';
                    }
                });
        } else {
            // file:// protocol and no embedded data
            document.getElementById('sectionsContainer').innerHTML = 
                '<div class="error" style="padding: 40px; text-align: center; color: var(--danger-color);">' +
                'API data not found. Please ensure api-data.js is loaded or use a local web server.' +
                '</div>';
        }
    } catch (error) {
        console.error('Error loading API data:', error);
        document.getElementById('sectionsContainer').innerHTML = 
            '<div class="error" style="padding: 40px; text-align: center; color: var(--danger-color);">' +
            'Error loading API reference. Please check the console for details.' +
            '</div>';
    }
}

function updateHeaderInfo() {
    if (apiData && apiData.api) {
        document.getElementById('version').textContent = apiData.api.version;
        document.getElementById('baseUrl').textContent = apiData.api.baseUrl;
        document.getElementById('dateUpdated').textContent = apiData.api.dateUpdated;
    }
}

function initializeApp() {
    populateSectionFilter();
    renderSections();
    updateStats();
    setupEventListeners();
}

function populateSectionFilter() {
    const filter = document.getElementById('sectionFilter');
    Object.keys(apiData.sections).forEach(sectionKey => {
        const section = apiData.sections[sectionKey];
        const option = document.createElement('option');
        option.value = sectionKey;
        option.textContent = section.name;
        filter.appendChild(option);
    });
}

function renderSections() {
    const container = document.getElementById('sectionsContainer');
    container.innerHTML = '';
    
    let totalEndpoints = 0;
    
    Object.keys(filteredData.sections).forEach(sectionKey => {
        const section = filteredData.sections[sectionKey];
        const sectionElement = createSectionElement(sectionKey, section);
        container.appendChild(sectionElement);
        totalEndpoints += section.endpoints.length;
    });
    
    if (totalEndpoints === 0) {
        container.innerHTML = '<div class="no-results">No endpoints match your filters. Try adjusting your search criteria.</div>';
    }
}

function createSectionElement(sectionKey, section) {
    const sectionDiv = document.createElement('div');
    sectionDiv.className = 'section';
    sectionDiv.dataset.section = sectionKey;
    
    const header = document.createElement('div');
    header.className = 'section-header';
    header.innerHTML = `
        <div>
            <h2>${section.name}</h2>
            <p style="color: var(--text-secondary); font-size: 0.9rem; margin-top: 5px;">${section.description}</p>
        </div>
        <div class="section-info">
            <span class="section-count">${section.endpoints.length} endpoints</span>
            <span class="section-toggle">▼</span>
        </div>
    `;
    
    const content = document.createElement('div');
    content.className = 'section-content';
    
    section.endpoints.forEach(endpoint => {
        const endpointElement = createEndpointElement(endpoint);
        content.appendChild(endpointElement);
    });
    
    sectionDiv.appendChild(header);
    sectionDiv.appendChild(content);
    
    // Toggle collapse
    header.addEventListener('click', () => {
        const isCollapsed = content.classList.toggle('hidden');
        header.querySelector('.section-toggle').classList.toggle('collapsed', isCollapsed);
    });
    
    return sectionDiv;
}

function createEndpointElement(endpoint) {
    const endpointDiv = document.createElement('div');
    endpointDiv.className = 'endpoint';
    
    const methodsHTML = endpoint.methods.map(method => 
        `<span class="method-badge method-${method.toLowerCase()}">${method}</span>`
    ).join('');
    
    const authBadge = endpoint.authentication 
        ? '<span class="auth-badge auth-required">Auth Required</span>'
        : '<span class="auth-badge auth-not-required">No Auth</span>';
    
    let capabilitiesHTML = '';
    if (endpoint.capabilities) {
        if (typeof endpoint.capabilities === 'object' && !Array.isArray(endpoint.capabilities)) {
            // Method-specific capabilities
            const caps = Object.values(endpoint.capabilities).flat();
            capabilitiesHTML = caps.map(cap => `<span class="capability">${cap}</span>`).join('');
        } else if (Array.isArray(endpoint.capabilities)) {
            capabilitiesHTML = endpoint.capabilities.map(cap => `<span class="capability">${cap}</span>`).join('');
        }
    }
    
    let detailsHTML = '';
    
    if (endpoint.pathParams) {
        detailsHTML += `
            <div class="detail-group">
                <h4>Path Parameters</h4>
                <ul>
                    ${Object.entries(endpoint.pathParams).map(([key, value]) => 
                        `<li><strong>${key}:</strong> ${value}</li>`
                    ).join('')}
                </ul>
            </div>
        `;
    }
    
    if (endpoint.queryParams) {
        detailsHTML += `
            <div class="detail-group">
                <h4>Query Parameters</h4>
                <ul>
                    ${Object.entries(endpoint.queryParams).map(([key, value]) => 
                        `<li><strong>${key}:</strong> ${value}</li>`
                    ).join('')}
                </ul>
            </div>
        `;
    }
    
    if (endpoint.requestBody) {
        detailsHTML += `
            <div class="detail-group">
                <h4>Request Body</h4>
                <ul>
                    ${Object.entries(endpoint.requestBody).map(([key, value]) => 
                        `<li><strong>${key}:</strong> ${value}</li>`
                    ).join('')}
                </ul>
            </div>
        `;
    }
    
    if (endpoint.response) {
        detailsHTML += `
            <div class="detail-group">
                <h4>Response</h4>
                <ul>
                    ${Object.entries(endpoint.response).map(([key, value]) => 
                        `<li><strong>${key}:</strong> ${value}</li>`
                    ).join('')}
                </ul>
            </div>
        `;
    }
    
    if (capabilitiesHTML) {
        detailsHTML += `
            <div class="detail-group">
                <h4>Required Capabilities</h4>
                <div>${capabilitiesHTML}</div>
            </div>
        `;
    }
    
    endpointDiv.innerHTML = `
        <div class="endpoint-header">
            ${methodsHTML}
            <code class="endpoint-path">${endpoint.path}</code>
            ${authBadge}
        </div>
        <div class="endpoint-description">${endpoint.description}</div>
        ${detailsHTML ? `<div class="endpoint-details">${detailsHTML}</div>` : ''}
    `;
    
    return endpointDiv;
}

function updateStats() {
    let totalEndpoints = 0;
    let visibleEndpoints = 0;
    
    Object.values(filteredData.sections).forEach(section => {
        totalEndpoints += section.endpoints.length;
        visibleEndpoints += section.endpoints.length;
    });
    
    // Count all endpoints in original data
    let allEndpoints = 0;
    Object.values(apiData.sections).forEach(section => {
        allEndpoints += section.endpoints.length;
    });
    
    document.getElementById('totalEndpoints').textContent = allEndpoints;
    document.getElementById('totalSections').textContent = Object.keys(apiData.sections).length;
    document.getElementById('visibleEndpoints').textContent = visibleEndpoints;
}

function setupEventListeners() {
    const searchInput = document.getElementById('searchInput');
    const sectionFilter = document.getElementById('sectionFilter');
    const methodFilter = document.getElementById('methodFilter');
    const clearFilters = document.getElementById('clearFilters');
    
    searchInput.addEventListener('input', applyFilters);
    sectionFilter.addEventListener('change', applyFilters);
    methodFilter.addEventListener('change', applyFilters);
    clearFilters.addEventListener('click', () => {
        searchInput.value = '';
        sectionFilter.value = '';
        methodFilter.value = '';
        applyFilters();
    });
}

function applyFilters() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const sectionFilter = document.getElementById('sectionFilter').value;
    const methodFilter = document.getElementById('methodFilter').value;
    
    filteredData = {
        ...apiData,
        sections: {}
    };
    
    Object.keys(apiData.sections).forEach(sectionKey => {
        if (sectionFilter && sectionKey !== sectionFilter) {
            return;
        }
        
        const section = apiData.sections[sectionKey];
        const filteredEndpoints = section.endpoints.filter(endpoint => {
            // Search filter
            if (searchTerm) {
                const searchableText = [
                    endpoint.path,
                    endpoint.description,
                    ...endpoint.methods,
                    ...(endpoint.capabilities ? (Array.isArray(endpoint.capabilities) ? endpoint.capabilities : Object.values(endpoint.capabilities).flat()) : [])
                ].join(' ').toLowerCase();
                
                if (!searchableText.includes(searchTerm)) {
                    return false;
                }
            }
            
            // Method filter
            if (methodFilter && !endpoint.methods.includes(methodFilter)) {
                return false;
            }
            
            return true;
        });
        
        if (filteredEndpoints.length > 0) {
            filteredData.sections[sectionKey] = {
                ...section,
                endpoints: filteredEndpoints
            };
        }
    });
    
    renderSections();
    updateStats();
}

// Initialize on load
loadAPIData();

