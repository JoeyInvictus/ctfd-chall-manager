/**
 * Global Instance Panel - Shows instance info across all challenge pages in the same category
 * This script runs on all pages and manages the persistent floating panel
 */

(function() {
    'use strict';
    
    // Configuration
    const POLL_INTERVAL = 10000; // Poll every 10 seconds for instance updates
    const STORAGE_KEY = 'cm_active_instance';
    const WARNING_SHOWN_KEY = 'cm_warnings_shown';
    
    let pollTimer = null;
    let currentChallengeId = null;
    let currentCategory = null;
    
    // Initialize on page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
    
    function init() {
        // Check if we're on a challenge page
        const challengeWindow = document.querySelector('[data-challenge-id]');
        if (challengeWindow) {
            currentChallengeId = challengeWindow.getAttribute('data-challenge-id');
        }
        
        // Try to extract category from page
        const categoryElement = document.querySelector('.challenge-category, [data-challenge-category]');
        if (categoryElement) {
            currentCategory = categoryElement.textContent.trim() || categoryElement.getAttribute('data-challenge-category');
        }
        
        // Check for active instance
        const activeInstance = getActiveInstance();
        if (activeInstance && shouldShowPanel()) {
            createPersistentPanel(activeInstance);
            startPolling();
        }
    }
    
    function shouldShowPanel() {
        // Show panel ONLY on the main challenges page
        return window.location.pathname.includes('/challenges');
    }
    
    function getActiveInstance() {
        try {
            const data = localStorage.getItem(STORAGE_KEY);
            return data ? JSON.parse(data) : null;
        } catch (e) {
            console.error('Error reading instance data:', e);
            return null;
        }
    }
    
    function setActiveInstance(data) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
        } catch (e) {
            console.error('Error storing instance data:', e);
        }
    }
    
    function clearActiveInstance() {
        localStorage.removeItem(STORAGE_KEY);
        localStorage.removeItem(WARNING_SHOWN_KEY);
    }
    
    function getWarningsShown() {
        try {
            const data = localStorage.getItem(WARNING_SHOWN_KEY);
            return data ? JSON.parse(data) : { fifteen: false, ten: false, five: false };
        } catch (e) {
            return { fifteen: false, ten: false, five: false };
        }
    }
    
    function setWarningsShown(warnings) {
        try {
            localStorage.setItem(WARNING_SHOWN_KEY, JSON.stringify(warnings));
        } catch (e) {
            console.error('Error storing warnings:', e);
        }
    }
    
    function createPersistentPanel(instanceData) {
        // Check if panel already exists
        if (document.getElementById('cm-global-floating-panel')) {
            updatePanelContent(instanceData);
            return;
        }
        
        const panelHTML = `
        <div id="cm-global-floating-panel" style="position: fixed; bottom: 20px; right: 20px; z-index: 1050; width: 340px;">
            <div class="card shadow-lg" style="background-color: #1e1e1e; border: 1px solid #333; border-radius: 10px; overflow: hidden; box-shadow: 0 8px 16px rgba(0,0,0,0.5) !important;">
                <div class="card-header" style="background-color: #161616; border-bottom: 1px solid #2a2a2a; color: #fff; cursor: pointer; padding: 12px 16px;" onclick="window.cmGlobalPanel.toggle()">
                    <div class="d-flex justify-content-between align-items-center">
                        <div class="d-flex align-items-center" style="font-weight: 700; font-size: 15px;">
                            <i class="fas fa-server mr-2 text-primary"></i>
                            Lab Instance
                        </div>
                        <div class="d-flex align-items-center">
                            <span id="cm-global-header-time" class="mr-3 d-none" style="font-family: monospace; font-weight: bold; color: #ebb850; font-size: 14px;"></span>
                            <i id="cm-global-toggle-icon" class="fas fa-chevron-up mr-2" style="color: #888;"></i>
                            <button type="button" class="close ml-1" onclick="window.cmGlobalPanel.close(event)" aria-label="Close" style="color: #aaa; text-shadow: none; opacity: 1;">
                                <span aria-hidden="true">&times;</span>
                            </button>
                        </div>
                    </div>
                </div>
                <div id="cm-global-panel-body" class="card-body" style="padding: 16px; color: #efefef;">
                    <div id="cm-global-loading" class="d-none">
                        <p class="text-center mb-0" style="color: #888;">
                            <i class="fas fa-spinner fa-spin"></i> Loading...
                        </p>
                    </div>
                    
                    <div id="cm-global-content"></div>
                </div>
            </div>
        </div>
        
        <style>
            #cm-global-floating-panel.minimized #cm-global-panel-body {
                display: none;
            }
            .floating-btn-lab {
                border: none;
                border-radius: 6px;
                font-weight: 700;
                transition: transform 0.1s, opacity 0.2s;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 6px;
                padding: 8px 10px;
            }
            .floating-btn-lab:hover { opacity: 0.9; transform: translateY(-1px); }
            .floating-btn-lab:active { transform: translateY(0); }
            @media (max-width: 768px) {
                #cm-global-floating-panel {
                    width: calc(100% - 40px) !important;
                    bottom: 10px !important;
                    right: 10px !important;
                }
            }
        </style>
        `;
        
        document.body.insertAdjacentHTML('beforeend', panelHTML);
        updatePanelContent(instanceData);
    }
    
    function updatePanelContent(instanceData) {
        const contentDiv = document.getElementById('cm-global-content');
        if (!contentDiv) return;
        
        let { challengeId, connectionInfo, until, since, category, challengeName } = instanceData;
        
        // Calculate time remaining
        let countdownHTML = '';
        let warningHTML = '';
        let timeLeft = null;
        
        if (until) {
            const now = new Date();
            const untilDate = new Date(until);
            const diff = untilDate - now;
            
            if (diff > 0) {
                timeLeft = diff;
                countdownHTML = `
                    <div class="mb-3">
                        <strong class="d-block mb-1" style="color: #888; font-size: 12px; text-transform: uppercase;">Time Remaining:</strong>
                        <div id="cm-global-countdown" style="font-family: monospace; font-size: 1.2rem; font-weight: bold; color: #fff;">${formatCountdown(diff)}</div>
                    </div>
                `;
                
                // Check for expiration warnings
                const warnings = getWarningsShown();
                const FIFTEEN_MIN = 15 * 60 * 1000;
                const TEN_MIN = 10 * 60 * 1000;
                const FIVE_MIN = 5 * 60 * 1000;
                
                let warningMessage = '';
                let showNotification = false;
                
                if (diff <= FIVE_MIN && !warnings.five) {
                    warningMessage = `Your instance expires in ${Math.floor(diff / 60000)} minutes! Click Renew NOW!`;
                    warnings.five = true;
                    showNotification = true;
                } else if (diff <= TEN_MIN && !warnings.ten) {
                    warningMessage = `Your instance expires in ${Math.floor(diff / 60000)} minutes! Click Renew to add more time.`;
                    warnings.ten = true;
                    showNotification = true;
                } else if (diff <= FIFTEEN_MIN && !warnings.fifteen) {
                    warningMessage = `Your instance expires in ${Math.floor(diff / 60000)} minutes! Don't forget to renew.`;
                    warnings.fifteen = true;
                    showNotification = true;
                }
                
                if (showNotification) {
                    setWarningsShown(warnings);
                    showExpirationNotification(warningMessage);
                }
                
                if (diff <= FIFTEEN_MIN) {
                    warningHTML = `
                        <div class="alert alert-warning py-2 px-2 mb-3 small" role="alert" style="background-color: rgba(235, 184, 80, 0.1); border: 1px solid #ebb850; color: #ebb850;">
                            <i class="fas fa-exclamation-triangle mr-1"></i> ${warningMessage}
                        </div>
                    `;
                }
            }
        }
        
        // Update header time
        const headerTimeEl = document.getElementById('cm-global-header-time');
        if (headerTimeEl && timeLeft) {
            headerTimeEl.textContent = formatCountdown(timeLeft);
            headerTimeEl.classList.remove('d-none');
        } else if (headerTimeEl) {
            headerTimeEl.classList.add('d-none');
        }
        
        let categoryHTML = '';
        if (challengeName) {
            categoryHTML = `
                <div class="mb-3">
                    <strong class="d-block mb-1" style="color: #888; font-size: 12px; text-transform: uppercase;">Lab:</strong> 
                    <div style="font-size: 13px; font-weight: 500; color: #fff; word-wrap: break-word; overflow-wrap: break-word; white-space: normal; line-height: 1.4;">
                        ${challengeName}
                    </div>
                </div>
            `;
        }
        
        const html = `
            ${categoryHTML}
            ${warningHTML}
            ${countdownHTML}
            
            <div class="d-flex mt-3" style="gap: 10px;">
                <button type="button" class="flex-fill floating-btn-lab" style="background-color:#ebb850; color: #000;" onclick="window.cmGlobalPanel.renew()" title="Add more time">
                    <i class="fas fa-clock"></i> Renew
                </button>
                <button type="button" class="flex-fill floating-btn-lab" style="background-color:#479abf; color: #fff;" onclick="window.cmGlobalPanel.restart()" title="Restart instance">
                    <i class="fas fa-redo"></i> Restart
                </button>
                <button type="button" class="flex-fill floating-btn-lab" style="background-color:#b43c2c; color: #fff;" onclick="window.cmGlobalPanel.destroy()" title="Destroy instance">
                    <i class="fas fa-trash"></i> Destroy
                </button>
            </div>
        `;
        
        contentDiv.innerHTML = html;
        
        // Start countdown timer if we have time left
        if (timeLeft) {
            startCountdownTimer(timeLeft);
        }
    }
    
    function formatCountdown(ms) {
        const seconds = Math.floor((ms / 1000) % 60);
        const minutes = Math.floor((ms / (1000 * 60)) % 60);
        const hours = Math.floor((ms / (1000 * 60 * 60)) % 24);    
        const days = Math.floor(ms / (1000 * 60 * 60 * 24));
        
        let formatted = '';
        if (days > 0) formatted += days + 'd ';
        if (hours > 0) formatted += hours.toString().padStart(2, '0') + ':';
        if (minutes > 0 || hours > 0) formatted += minutes.toString().padStart(2, '0') + ':';
        formatted += seconds.toString().padStart(2, '0');
        
        return formatted;
    }
    
    function startCountdownTimer(initialTime) {
        // Clear existing timer
        if (window.cmGlobalCountdownTimer) {
            clearInterval(window.cmGlobalCountdownTimer);
        }
        
        const countdownEl = document.getElementById('cm-global-countdown');
        if (!countdownEl) return;
        
        const activeInstance = getActiveInstance();
        if (!activeInstance || !activeInstance.until) return;
        
        window.cmGlobalCountdownTimer = setInterval(() => {
            const now = new Date();
            const until = new Date(activeInstance.until);
            const diff = until - now;
            
            if (diff <= 0) {
                countdownEl.textContent = '00:00';
                const headerTimeEl = document.getElementById('cm-global-header-time');
                if (headerTimeEl) headerTimeEl.textContent = '00:00';
                clearInterval(window.cmGlobalCountdownTimer);
                // Refresh instance data
                pollInstanceStatus();
            } else {
                const formatted = formatCountdown(diff);
                countdownEl.textContent = formatted;
                const headerTimeEl = document.getElementById('cm-global-header-time');
                if (headerTimeEl) headerTimeEl.textContent = formatted;
            }
        }, 1000);
    }
    
    function showExpirationNotification(message) {
        // Use CTFd's notification system if available
        if (window.CTFd && window.CTFd._functions && window.CTFd._functions.events) {
            CTFd._functions.events.eventAlert({
                title: "Instance Expiring Soon!",
                html: message,
                icon: "warning"
            });
        } else {
            // Fallback to browser notification
            if ('Notification' in window && Notification.permission === 'granted') {
                new Notification('Lab Instance Expiring', {
                    body: message,
                    icon: '/themes/core/static/img/logo.png'
                });
            } else {
                alert(message);
            }
        }
    }
    
    function startPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
        }
        
        pollTimer = setInterval(() => {
            pollInstanceStatus();
        }, POLL_INTERVAL);
    }
    
    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }
    
    function pollInstanceStatus() {
        const activeInstance = getActiveInstance();
        if (!activeInstance) {
            stopPolling();
            removePanel();
            return;
        }
        
        const { challengeId } = activeInstance;
        
        const fetchFn = (window.CTFd && window.CTFd.fetch) ? window.CTFd.fetch : fetch;
        fetchFn(`/api/v1/plugins/ctfd-chall-manager/instance?challengeId=${challengeId}`, {
            method: 'GET',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.success && data.data) {
                const instanceData = data.data;
                
                // Check if instance still exists
                if (instanceData.starting || instanceData.connectionInfo || instanceData.since) {
                    // Update stored instance data
                    activeInstance.connectionInfo = instanceData.connectionInfo;
                    activeInstance.until = instanceData.until;
                    activeInstance.since = instanceData.since;
                    setActiveInstance(activeInstance);
                    
                    // Update panel
                    updatePanelContent(activeInstance);
                } else {
                    // Instance no longer exists
                    clearActiveInstance();
                    removePanel();
                    stopPolling();
                }
            } else {
                // Instance not found - might be destroyed
                clearActiveInstance();
                removePanel();
                stopPolling();
            }
        })
        .catch(error => {
            console.error('Error polling instance status:', error);
        });
    }
    
    function removePanel() {
        const panel = document.getElementById('cm-global-floating-panel');
        if (panel) {
            panel.remove();
        }
        if (window.cmGlobalCountdownTimer) {
            clearInterval(window.cmGlobalCountdownTimer);
        }
    }
    
    // Global panel controls
    window.cmGlobalPanel = {
        toggle: function() {
            const panel = document.getElementById('cm-global-floating-panel');
            const icon = document.getElementById('cm-global-toggle-icon');
            if (panel && icon) {
                panel.classList.toggle('minimized');
                icon.className = panel.classList.contains('minimized') ? 
                    'fas fa-chevron-down' : 'fas fa-chevron-up';
            }
        },
        
        close: function(event) {
            if (event) event.stopPropagation();
            removePanel();
            stopPolling();
            // Don't clear instance data - just hide the panel
            // User can still see it if they navigate to another challenge page
        },
        
        renew: function() {
            const activeInstance = getActiveInstance();
            if (!activeInstance) return;
            
            const btn = event.target.closest('button');
            const originalText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Renewing...';
            
            // Use CTFd.fetch if available for proper CSRF handling, otherwise use regular fetch
            const fetchFn = (window.CTFd && window.CTFd.fetch) ? window.CTFd.fetch : fetch;
            
            fetchFn('/api/v1/plugins/ctfd-chall-manager/instance', {
                method: 'PATCH',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ challengeId: activeInstance.challengeId })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Reset warning flags
                    setWarningsShown({ fifteen: false, ten: false, five: false });
                    
                    // If response includes updated instance data, use it immediately
                    if (data.data && data.data.until) {
                        const activeInstance = getActiveInstance();
                        if (activeInstance) {
                            activeInstance.until = data.data.until;
                            if (data.data.connectionInfo) {
                                activeInstance.connectionInfo = data.data.connectionInfo;
                            }
                            setActiveInstance(activeInstance);
                            updatePanelContent(activeInstance);
                        }
                    }
                    
                    // Also poll to ensure we're in sync
                    pollInstanceStatus();
                    
                    if (window.CTFd && window.CTFd._functions && window.CTFd._functions.events) {
                        CTFd._functions.events.eventAlert({
                            title: "Success",
                            html: "Your instance has been renewed!",
                            icon: "success"
                        });
                    }
                } else {
                    if (window.CTFd && window.CTFd._functions && window.CTFd._functions.events) {
                        CTFd._functions.events.eventAlert({
                            title: "Error",
                            html: data.message || "Failed to renew instance",
                            icon: "error"
                        });
                    }
                }
            })
            .catch(error => {
                console.error('Error renewing instance:', error);
            })
            .finally(() => {
                btn.disabled = false;
                btn.innerHTML = originalText;
            });
        },
        
        restart: function() {
            if (!confirm('Are you sure you want to restart your instance? This will destroy and recreate it.')) {
                return;
            }
            
            const btn = event.target.closest('button');
            const originalText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Restarting...';
            
            // Disable all buttons during restart
            document.querySelectorAll('#cm-global-panel-body button').forEach(b => b.disabled = true);
            
            const activeInstance = getActiveInstance();
            if (!activeInstance) return;
            
            const fetchFn = (window.CTFd && window.CTFd.fetch) ? window.CTFd.fetch : fetch;
            
            // First destroy
            fetchFn('/api/v1/plugins/ctfd-chall-manager/instance', {
                method: 'DELETE',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ challengeId: activeInstance.challengeId })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Then boot
                    return fetchFn('/api/v1/plugins/ctfd-chall-manager/instance', {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ challengeId: activeInstance.challengeId.toString() })
                    });
                } else {
                    throw new Error(data.message || 'Failed to destroy instance');
                }
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    // Update immediately if response includes instance data
                    if (data.data) {
                        const activeInstance = getActiveInstance();
                        if (activeInstance) {
                            Object.assign(activeInstance, data.data);
                            setActiveInstance(activeInstance);
                            updatePanelContent(activeInstance);
                        }
                    }
                    
                    // Also poll to ensure we're in sync
                    pollInstanceStatus();
                    
                    if (window.CTFd && window.CTFd._functions && window.CTFd._functions.events) {
                        CTFd._functions.events.eventAlert({
                            title: "Success",
                            html: "Your instance is being restarted!",
                            icon: "success"
                        });
                    }
                } else {
                    throw new Error(data.message || 'Failed to boot instance');
                }
            })
            .catch(error => {
                console.error('Error restarting instance:', error);
                if (window.CTFd && window.CTFd._functions && window.CTFd._functions.events) {
                    CTFd._functions.events.eventAlert({
                        title: "Error",
                        html: error.message,
                        icon: "error"
                    });
                }
            })
            .finally(() => {
                document.querySelectorAll('#cm-global-panel-body button').forEach(b => b.disabled = false);
            });
        },
        
        destroy: function() {
            if (!confirm('Are you sure you want to destroy your instance? Your Azure lab environment will be destroyed.')) {
                return;
            }
            
            const btn = event.target.closest('button');
            const originalText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Destroying...';
            
            const activeInstance = getActiveInstance();
            if (!activeInstance) return;
            
            const fetchFn = (window.CTFd && window.CTFd.fetch) ? window.CTFd.fetch : fetch;
            
            fetchFn('/api/v1/plugins/ctfd-chall-manager/instance', {
                method: 'DELETE',
                credentials: 'same-origin',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ challengeId: activeInstance.challengeId })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    clearActiveInstance();
                    removePanel();
                    stopPolling();
                    if (window.CTFd && window.CTFd._functions && window.CTFd._functions.events) {
                        CTFd._functions.events.eventAlert({
                            title: "Success",
                            html: "Your instance has been destroyed!",
                            icon: "success"
                        });
                    }
                } else {
                    if (window.CTFd && window.CTFd._functions && window.CTFd._functions.events) {
                        CTFd._functions.events.eventAlert({
                            title: "Error",
                            html: data.message || "Failed to destroy instance",
                            icon: "error"
                        });
                    }
                }
            })
            .catch(error => {
                console.error('Error destroying instance:', error);
            })
            .finally(() => {
                if(btn) {
                    btn.disabled = false;
                    btn.innerHTML = originalText;
                }
            });
        },
        
        // Method to update instance data from challenge page
        updateInstance: function(challengeId, category, instanceData) {
            const data = {
                challengeId: challengeId,
                category: category,
                challengeName: instanceData.challengeName || 'Lab Instance',
                connectionInfo: instanceData.connectionInfo,
                until: instanceData.until,
                since: instanceData.since
            };
            setActiveInstance(data);
            
            if (shouldShowPanel()) {
                createPersistentPanel(data);
                if (!pollTimer) {
                    startPolling();
                }
            }
        },
        
        // Method to clear instance (called when instance is destroyed)
        clearInstance: function() {
            clearActiveInstance();
            removePanel();
            stopPolling();
        }
    };
    
})();