CTFd._internal.challenge.data = undefined;
CTFd._internal.challenge.renderer = null;

CTFd._internal.challenge.preRender = function () {};
CTFd._internal.challenge.render = null;

CTFd._internal.challenge.postRender = function () {
    // Initialize our global deployment flag if it doesn't exist
    if (window.cm_is_deploying === undefined) {
        window.cm_is_deploying = false;
    }
    loadInfo();
    showFloatingPanel();
};

if (window.$ === undefined) window.$ = CTFd.lib.$;

// Track warning states to avoid duplicate notifications
window.cm_warning_shown = {
    fifteen: false,
    ten: false,
    five: false
};

function showFloatingPanel() {
    const panel = document.getElementById('cm-floating-panel');
    if (panel) panel.style.display = 'block';
}

function updateFloatingPanel(state, data = {}) {
    $('#cm-float-loading').hide();
    $('#cm-float-stopped').hide();
    $('#cm-float-starting').hide();
    $('#cm-float-running').hide();
    
    switch(state) {
        case 'loading': $('#cm-float-loading').show(); break;
        case 'stopped': $('#cm-float-stopped').show(); break;
        case 'starting': $('#cm-float-starting').show(); break;
        case 'running':
            $('#cm-float-running').show();
            if (data.countdown) $('#cm-float-countdown').text(data.countdown);
            if (data.connectionInfo) $('#cm-float-connection').text(data.connectionInfo);
            if (data.showWarning && data.warningMessage) {
                $('#cm-float-warning-message').text(data.warningMessage);
                $('#cm-float-expiration-warning').show();
            } else {
                $('#cm-float-expiration-warning').hide();
            }
            break;
    }
}

function checkExpirationWarnings(count_down_ms) {
    const minutes = Math.floor(count_down_ms / (1000 * 60));
    const FIFTEEN_MIN = 15 * 60 * 1000;
    const TEN_MIN = 10 * 60 * 1000;
    const FIVE_MIN = 5 * 60 * 1000;
    
    let showWarning = false;
    let warningMessage = '';
    
    if (count_down_ms <= FIFTEEN_MIN && count_down_ms > TEN_MIN && !window.cm_warning_shown.fifteen) {
        window.cm_warning_shown.fifteen = true;
        warningMessage = 'Your instance will expire in 15 minutes! Click Renew to add more time.';
        showWarning = true;
        CTFd._functions.events.eventAlert({ title: "Instance Expiring Soon", html: warningMessage, icon: "warning" });
    } else if (count_down_ms <= TEN_MIN && count_down_ms > FIVE_MIN && !window.cm_warning_shown.ten) {
        window.cm_warning_shown.ten = true;
        warningMessage = 'Your instance will expire in 10 minutes! Click Renew to add more time.';
        showWarning = true;
        CTFd._functions.events.eventAlert({ title: "Instance Expiring Soon", html: warningMessage, icon: "warning" });
    } else if (count_down_ms <= FIVE_MIN && count_down_ms > 0 && !window.cm_warning_shown.five) {
        window.cm_warning_shown.five = true;
        warningMessage = 'Your instance will expire in 5 minutes! Click Renew NOW to add more time.';
        showWarning = true;
        CTFd._functions.events.eventAlert({ title: "Instance Expiring VERY Soon!", html: warningMessage, icon: "error" });
    }
    
    if (count_down_ms <= FIFTEEN_MIN && count_down_ms > 0) {
        warningMessage = `Your instance expires in ${minutes} minute${minutes !== 1 ? 's' : ''}!`;
        showWarning = true;
    }
    
    if (showWarning) {
        $('#cm-warning-message').text(warningMessage);
        $('#cm-expiration-warning').show();
        $('#cm-float-warning-message').text(warningMessage);
        updateFloatingPanel('running', {
            showWarning: true,
            warningMessage: warningMessage,
            countdown: formatCountDown(count_down_ms),
            connectionInfo: $('#whale-challenge-lan-domain').text()
        });
    } else {
        $('#cm-expiration-warning').hide();
    }
}

function formatCountDown(countdown) {
    var seconds = Math.floor((countdown / 1000) % 60);
    var minutes = Math.floor((countdown / (1000 * 60)) % 60);
    var hours = Math.floor((countdown / (1000 * 60 * 60)) % 24);    
    var days = Math.floor((countdown / (1000 * 60 * 60 * 24 )) % 365);  

    var formattedCountdown = "";
    if (days > 0) formattedCountdown += days.toString() + "d ";
    if (hours > 0) formattedCountdown += hours.toString().padStart(2, '0') + ":";
    if (minutes > 0) formattedCountdown += minutes.toString().padStart(2, '0') + ":";
    
    formattedCountdown += seconds.toString().padStart(2, '0');        
    return formattedCountdown;
}

function loadInfo() {
    var challenge_id = CTFd._internal.challenge.data.id;
    var url = "/api/v1/plugins/ctfd-chall-manager/instance?challengeId=" + challenge_id;

    CTFd.fetch(url, {
        method: 'GET',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    }).then(function (response) {
        if (response.status === 429 || response.status === 403) return response.json();
        return response.json();
    }).then(function (response) {
        if (window.t !== undefined) {
            clearInterval(window.t);
            window.t = undefined;
        }

        if (response.success) {
            response = response.data;
        } else {
            CTFd._functions.events.eventAlert({ title: "Fail", html: response.message });
            return;
        }

        // Hide all panels initially
        $('#cm-panel-loading').hide();
        $('#cm-panel-until').hide(); 
        $('#whale-panel-starting').hide();
        $('#whale-panel-started').hide();
        $('#whale-panel-stopped').hide();
        $('#whale-challenge-lan-domain').html('');

        // 1. IS THE INSTANCE FULLY RUNNING?
        if (response && response.connectionInfo) {
            window.cm_is_deploying = false; // Deployment finished, clear the flag
            $('#whale-panel-started').show();
            
            // Update global persistent panel
            if (window.cmGlobalPanel) {
                const challengeCategory = CTFd._internal.challenge.data.category || 'Unknown';
                window.cmGlobalPanel.updateInstance(challenge_id, challengeCategory, response);
            }
            
            // --- FILTER SENSITIVE DATA ---
            let rawLines = response.connectionInfo.split('\n');
            let filteredLines = [];
            
            for (let line of rawLines) {
                let lowerLine = line.toLowerCase();
                
                // Skip empty lines to fix spacing
                if (line.trim() === '') continue; 
                
                // FILTER: Hide any lines containing 'username' or 'password' etc
                if (lowerLine.includes('username') || lowerLine.includes('password')) {
                    continue; 
                }
                
                filteredLines.push(line);
            }
            
            // Join the safe lines back together with HTML line breaks
            let cleanInfo = filteredLines.join('<br>');
            
            $('#whale-challenge-lan-domain').css({
                'color': 'var(--bs-body-color, inherit)', 
                'background': 'transparent',
                'padding': '0',
                'font-family': 'inherit',
                'font-size': '1rem'
            }).html(cleanInfo);
            
            // --- TIMER LOGIC ---
            var expireTime;
            if (response.until) {
                expireTime = new Date(response.until);
            } else {
                var createdAt = new Date(response.created_at || Date.now());
                var challengeTimeout = parseInt(CTFd._internal.challenge.data.timeout) || 3600; 
                var extraTime = parseInt(response.extra_time) || 0; 
                expireTime = new Date(createdAt.getTime() + ((challengeTimeout + extraTime) * 1000));
            }
            
            var count_down = expireTime - new Date();

            if (count_down > 0) {
                $('#whale-challenge-count-down').text(formatCountDown(count_down)); 
                $('#cm-panel-until').show();
                
                // Send the safe, filtered text to the floating panel too
                updateFloatingPanel('running', {
                    countdown: formatCountDown(count_down),
                    connectionInfo: filteredLines.join('\n') 
                });

                checkExpirationWarnings(count_down);

                window.t = setInterval(() => {
                    count_down = expireTime - new Date();
                    if (count_down <= 0) {
                        clearInterval(window.t);
                        loadInfo(); 
                    } else {
                        $('#whale-challenge-count-down').text(formatCountDown(count_down));
                        $('#cm-float-countdown').text(formatCountDown(count_down));
                        checkExpirationWarnings(count_down);
                    }
                }, 1000);
            } else {
                $('#whale-challenge-count-down').text("Expiring...");
            }

        // 2. IS THE INSTANCE CURRENTLY DEPLOYING?
        } else if (window.cm_is_deploying || (response && (response.starting || response.locked === true || (response.created_at && !response.connectionInfo)))) {
            $('#whale-panel-starting').show();
            
            let startMsg = response.starting || "Your instance is being deployed... Please wait. This usually takes 1-2 minutes.";
            
            // Show a nice loading message
            $('#whale-challenge-lan-domain').css({
                'color': '#17a2b8', 
                'font-weight': 'bold',
                'font-family': 'inherit',
                'background': 'transparent'
            }).text(startMsg);
            
            updateFloatingPanel('starting');
            
            // Poll Azure again in 5 seconds
            setTimeout(loadInfo, 5000);

        // 3. NO INSTANCE EXISTS (Stopped)
        } else {
            window.cm_is_deploying = false; // Failsafe
            $('#whale-panel-stopped').show();
            updateFloatingPanel('stopped');
        }
    });

    // Get remaining mana for user
    CTFd.fetch("/api/v1/plugins/ctfd-chall-manager/mana", {
        method: 'GET',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
    }).then(function (response) {
        if (response.status === 429 || response.status === 403) return response.json();
        return response.json();
    }).then(function (response) {
        if (response.success && response.data) {
            if (response.data.total == 0){
                $('.cm-panel-mana-cost-div').hide();
            } else {
                let remaining = response.data.total - response.data.used;
                $('#cm-challenge-mana-remaining').html(remaining);
            }
        }
    });
};

CTFd._internal.challenge.destroy = function() {
    return new Promise((resolve, reject) => {
        var challenge_id = CTFd._internal.challenge.data.id;
        var url = "/api/v1/plugins/ctfd-chall-manager/instance"

        $('#whale-button-destroy').text("Waiting...");
        $('#whale-button-destroy').prop('disabled', true);

        let params = { "challengeId": challenge_id };

        CTFd.fetch(url, {
            method: 'DELETE',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
            body: JSON.stringify(params)
        }).then(response => {
            return response.json();
        }).then(response => {
            if (response.success) {
                window.cm_is_deploying = false; // Reset deployment flag
                loadInfo();
                
                // Clear global persistent panel
                if (window.cmGlobalPanel) {
                    window.cmGlobalPanel.clearInstance();
                }
                
                CTFd._functions.events.eventAlert({ title: "Success", html: "Your instance has been destroyed!" });
                resolve();
            } else {
                CTFd._functions.events.eventAlert({ title: "Fail", html: response.message });
                reject(response.message);
            }
        }).catch(error => {
            reject(error);
        }).finally(() => {
            $('#whale-button-destroy').text("Destroy");
            $('#whale-button-destroy').prop('disabled', false);
        });
    });
};

CTFd._internal.challenge.renew = function () {
    var challenge_id = CTFd._internal.challenge.data.id;
    var url = "/api/v1/plugins/ctfd-chall-manager/instance";

    $('#whale-button-renew').text("Waiting...");
    $('#whale-button-renew').prop('disabled', true);

    var params = { "challengeId": challenge_id };

    CTFd.fetch(url, {
        method: 'PATCH',
        credentials: 'same-origin',
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify(params)
    }).then(function (response) {
        return response.json();
    }).then(function (response) {
        if (response.success) {
            window.cm_warning_shown = { fifteen: false, ten: false, five: false };
            loadInfo();
            CTFd._functions.events.eventAlert({ title: "Success", html: "Time successfully extended!" });
        } else {
            CTFd._functions.events.eventAlert({ title: "Fail", html: response.message });
        }
    }).finally(() => {
        $('#whale-button-renew').text("Renew");
        $('#whale-button-renew').prop('disabled', false);
    });
};

CTFd._internal.challenge.boot = function() {
    return new Promise((resolve, reject) => {
        var challenge_id = CTFd._internal.challenge.data.id;
        var url = "/api/v1/plugins/ctfd-chall-manager/instance";

        $('#whale-button-boot').text("Waiting...");
        $('#whale-button-boot').prop('disabled', true);

        var params = { "challengeId": challenge_id.toString() };

        CTFd.fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
            body: JSON.stringify(params)
        }).then(response => {
            return response.json();
        }).then(response => {
            if (response.success) {
                // Lock UI in Deploying state immediately
                window.cm_is_deploying = true;
                loadInfo();
                CTFd._functions.events.eventAlert({ title: "Success", html: "Your instance is being deployed!" });
                resolve();
            } else {
                CTFd._functions.events.eventAlert({ title: "Fail", html: response.message });
            }
        }).catch(error => {
            reject(error);
        }).finally(() => {
            $('#whale-button-boot').text("Launch an instance");
            $('#whale-button-boot').prop('disabled', false);
        });
    });
};

CTFd._internal.challenge.restart = function() {
    $('#whale-button-boot').prop('disabled', true);
    $('#whale-button-restart').prop('disabled', true);
    $('#whale-button-renew').prop('disabled', true);
    $('#whale-button-destroy').prop('disabled', true);
    
    CTFd._functions.events.eventAlert({
        title: "Restarting...",
        html: "We are destroying your old lab and provisioning a new one. This will take a few minutes.",
        icon: "info"
    });

    CTFd._internal.challenge.destroy().then(() => {
        // Show immediate visual feedback
        $('#whale-panel-stopped').hide();
        $('#whale-panel-started').hide();
        $('#whale-panel-starting').show();
        $('#whale-challenge-lan-domain').css({'color': '#17a2b8', 'font-weight': 'bold'}).text("Provisioning new lab environment... Please wait.");
        updateFloatingPanel('starting');
        
        // Wait 10 seconds for the backend to clear the state, then boot
        return new Promise(resolve => setTimeout(resolve, 10000)).then(() => {
             return CTFd._internal.challenge.boot();
        });
    }).then(() => {
        // Boot handles triggering loadInfo, but we set a safe poll just in case
        setTimeout(loadInfo, 5000);
    }).catch((error) => {
        console.error('Error during restart:', error);
    }).finally(() => {
        $('#whale-button-boot').prop('disabled', false);
        $('#whale-button-restart').prop('disabled', false);
        $('#whale-button-renew').prop('disabled', false);
        $('#whale-button-destroy').prop('disabled', false);
    });
}

CTFd._internal.challenge.submit = function(preview) {
    var challenge_id = parseInt($('#challenge-id').val())
    var submission = $('#challenge-input').val() 

    var body = {
        'challenge_id': challenge_id,
        'submission': submission,
    }
    var params = {}
    if (preview) params['preview'] = true

    return CTFd.api.post_challenge_attempt(params, body).then(function(response) {
        return response
    })
};