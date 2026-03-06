CTFd._internal.challenge.data = undefined

CTFd._internal.challenge.renderer = null;

CTFd._internal.challenge.preRender = function () {
}

CTFd._internal.challenge.render = null;

CTFd._internal.challenge.postRender = function () {
    loadInfo();
    // Show floating panel
    showFloatingPanel();
}

if (window.$ === undefined) window.$ = CTFd.lib.$;

// Track warning states to avoid duplicate notifications
window.cm_warning_shown = {
    fifteen: false,
    ten: false,
    five: false
};

// Show the floating panel
function showFloatingPanel() {
    const panel = document.getElementById('cm-floating-panel');
    if (panel) {
        panel.style.display = 'block';
    }
}

// Update floating panel state
function updateFloatingPanel(state, data = {}) {
    // Hide all states
    $('#cm-float-loading').hide();
    $('#cm-float-stopped').hide();
    $('#cm-float-starting').hide();
    $('#cm-float-running').hide();
    
    // Show requested state
    switch(state) {
        case 'loading':
            $('#cm-float-loading').show();
            break;
        case 'stopped':
            $('#cm-float-stopped').show();
            break;
        case 'starting':
            $('#cm-float-starting').show();
            break;
        case 'running':
            $('#cm-float-running').show();
            if (data.countdown) {
                $('#cm-float-countdown').text(data.countdown);
            }
            if (data.connectionInfo) {
                $('#cm-float-connection').text(data.connectionInfo);
            }
            // Handle expiration warning
            if (data.showWarning && data.warningMessage) {
                $('#cm-float-warning-message').text(data.warningMessage);
                $('#cm-float-expiration-warning').show();
            } else {
                $('#cm-float-expiration-warning').hide();
            }
            break;
    }
}

// Check and show expiration warnings
function checkExpirationWarnings(count_down_ms) {
    const minutes = Math.floor(count_down_ms / (1000 * 60));
    const FIFTEEN_MIN = 15 * 60 * 1000;
    const TEN_MIN = 10 * 60 * 1000;
    const FIVE_MIN = 5 * 60 * 1000;
    
    let showWarning = false;
    let warningMessage = '';
    
    // 15 minute warning
    if (count_down_ms <= FIFTEEN_MIN && count_down_ms > TEN_MIN && !window.cm_warning_shown.fifteen) {
        window.cm_warning_shown.fifteen = true;
        warningMessage = 'Your instance will expire in 15 minutes! Click Renew to add more time.';
        showWarning = true;
        CTFd._functions.events.eventAlert({
            title: "Instance Expiring Soon",
            html: warningMessage,
            icon: "warning"
        });
    }
    // 10 minute warning
    else if (count_down_ms <= TEN_MIN && count_down_ms > FIVE_MIN && !window.cm_warning_shown.ten) {
        window.cm_warning_shown.ten = true;
        warningMessage = 'Your instance will expire in 10 minutes! Click Renew to add more time.';
        showWarning = true;
        CTFd._functions.events.eventAlert({
            title: "Instance Expiring Soon",
            html: warningMessage,
            icon: "warning"
        });
    }
    // 5 minute warning
    else if (count_down_ms <= FIVE_MIN && count_down_ms > 0 && !window.cm_warning_shown.five) {
        window.cm_warning_shown.five = true;
        warningMessage = 'Your instance will expire in 5 minutes! Click Renew NOW to add more time.';
        showWarning = true;
        CTFd._functions.events.eventAlert({
            title: "Instance Expiring VERY Soon!",
            html: warningMessage,
            icon: "error"
        });
    }
    
    // Show persistent warning in panel when under 15 minutes
    if (count_down_ms <= FIFTEEN_MIN && count_down_ms > 0) {
        warningMessage = `Your instance expires in ${minutes} minute${minutes !== 1 ? 's' : ''}!`;
        showWarning = true;
    }
    
    // Update both inline and floating panels
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

    // Convert
    var seconds = Math.floor((countdown / 1000) % 60);
    var minutes = Math.floor((countdown / (1000 * 60)) % 60);
    var hours = Math.floor((countdown / (1000 * 60 * 60)) % 24);    
    var days = Math.floor((countdown / (1000 * 60 * 60 * 24 )) % 365);  

    // Build str
    var formattedCountdown = "" 
    
    if (days > 0) {
      formattedCountdown = formattedCountdown + days.toString() + "d " 
    }
    if (hours > 0 ){
      formattedCountdown = formattedCountdown + hours.toString().padStart(2, '0') + ":"
    }
    if (minutes > 0){
      formattedCountdown = formattedCountdown + minutes.toString().padStart(2, '0') + ":"
    }
    
    formattedCountdown = formattedCountdown + seconds.toString().padStart(2, '0');        

    return formattedCountdown;
}

function loadInfo() {
    var challenge_id = CTFd._internal.challenge.data.id;
    var url = "/api/v1/plugins/ctfd-chall-manager/instance?challengeId=" + challenge_id;


    CTFd.fetch(url, {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
    }).then(function (response) {
        
        if (response.status === 429) {
            // User was ratelimited but process response
            return response.json();
        }
        if (response.status === 403) {
            // User is not logged in or CTF is paused.
            return response.json();
        }
        return response.json();
    }).then(function (response) {
        if (window.t !== undefined) {
            clearInterval(window.t);
            window.t = undefined;
        }
        if (response.success) response = response.data;
        else CTFd._functions.events.eventAlert({
            title: "Fail",
            html: response.message,
        });
        $('#cm-panel-loading').hide();
        $('#cm-panel-until').hide(); 
        $('#whale-panel-starting').hide();
       
        if (response.since && response.until) { // if instance has an until
           
            // check instance is not expired
            var now = new Date();
            var until = new Date(response.until);
            
            console.log(now);
            console.log(until);
            
            var count_down = until - now;
            console.log(count_down);
            if (count_down > 0) {   // if the instance is not expired         
                
                $('#whale-panel-stopped').hide();
                $('#whale-panel-started').show();
                $('#whale-challenge-lan-domain').html(response.connectionInfo);                
                $('#whale-challenge-count-down').text(formatCountDown(count_down)); 
                $('#cm-panel-until').show();
                
                // Update floating panel
                updateFloatingPanel('running', {
                    countdown: formatCountDown(count_down),
                    connectionInfo: response.connectionInfo
                });

                // Check for expiration warnings
                checkExpirationWarnings(count_down);

                window.t = setInterval(() => {
                    count_down = until - new Date();
                    if (count_down <= 0) {
                        loadInfo();
                    }
                    $('#whale-challenge-count-down').text(formatCountDown(count_down));
                    
                    // Update floating panel countdown
                    $('#cm-float-countdown').text(formatCountDown(count_down));
                    
                    // Check for expiration warnings
                    checkExpirationWarnings(count_down);
                }, 1000);
            } else {
                $('#whale-panel-started').hide(); // hide the panel instance is up       
                $('#whale-panel-stopped').show(); // show the panel instance is down     
                $('#whale-challenge-lan-domain').html('');
                updateFloatingPanel('stopped');
            }
                    
        } else if (response.since) {    // if instance has no until
            $('#whale-panel-stopped').hide();
            $('#whale-panel-started').show();
            $('#whale-challenge-lan-domain').html(response.connectionInfo);
            updateFloatingPanel('running', {
                connectionInfo: response.connectionInfo
            });
        } else if (response.starting) {    // instance is starting         
            $('#whale-panel-stopped').hide();
            $('#whale-panel-started').hide();
            $('#whale-panel-starting').show();
            $('#whale-challenge-lan-domain').html(response.starting);
            updateFloatingPanel('starting');
            // Poll more frequently when starting
            setTimeout(loadInfo, 5000);
        } else { // if instance is expired or not created
            $('#whale-panel-started').hide(); // hide the panel instance is up       
            $('#whale-panel-stopped').show(); // show the panel instance is down     
            $('#whale-challenge-lan-domain').html('');
            updateFloatingPanel('stopped');
        }
 
        
    });

    // get renaming mana for user
    CTFd.fetch("/api/v1/plugins/ctfd-chall-manager/mana", {
        method: 'GET',
        credentials: 'same-origin',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
    }).then(function (response) {
        
        if (response.status === 429) {
            // User was ratelimited but process response
            return response.json();
        }
        if (response.status === 403) {
            // User is not logged in or CTF is paused.
            return response.json();
        }
        return response.json();
    }).then(function (response) {
        if (response.success) response = response.data;
        else CTFd._functions.events.eventAlert({
            title: "Fail",
            html: response.message,
        });
        return response
    }).then(function (response){
        if (response.total == 0){
            $('.cm-panel-mana-cost-div').hide();  // hide the mana cost div if mana is disabled
        }
        else {
            let remaining = response.total - response.used
            $('#cm-challenge-mana-remaining').html(remaining);
        }
    });
};

CTFd._internal.challenge.destroy = function() {
    return new Promise((resolve, reject) => {
        var challenge_id = CTFd._internal.challenge.data.id;
        var url = "/api/v1/plugins/ctfd-chall-manager/instance"

        $('#whale-button-destroy').text("Waiting...");
        $('#whale-button-destroy').prop('disabled', true);

        let params = {
            "challengeId": challenge_id,
        };
    

        CTFd.fetch(url, {
            method: 'DELETE',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(params)
        }).then(response => {
            if (response.status === 429 || response.status === 403) {
                return response.json();
            }
            return response.json();
        }).then(response => {
            if (response.success) {
                loadInfo();
                CTFd._functions.events.eventAlert({
                    title: "Success",
                    html: "Your instance has been destroyed!",
                });
                resolve();
            } else {
                CTFd._functions.events.eventAlert({
                    title: "Fail",
                    html: response.message,
                });
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

    var params = {
        "challengeId": challenge_id,
    };

    CTFd.fetch(url, {
        method: 'PATCH',
        credentials: 'same-origin',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(params)
    }).then(function (response) {
        if (response.status === 429) {
            // User was ratelimited but process response
            return response.json();
        }
        if (response.status === 403) {
            // User is not logged in or CTF is paused.
            return response.json();
        }
        return response.json();
    }).then(function (response) {
        if (response.success) {
            // Reset warning flags when instance is renewed
            window.cm_warning_shown = {
                fifteen: false,
                ten: false,
                five: false
            };
            loadInfo();
            CTFd._functions.events.eventAlert({
                title: "Success",
                html: response.data.message, // load custom message from api
            });
        } else {
            CTFd._functions.events.eventAlert({
                title: "Fail",
                html: response.message,
            });
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

        var params = {
            "challengeId": challenge_id.toString()
        };

        CTFd.fetch(url, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(params)
        }).then(response => {
            if (response.status === 429 || response.status === 403) {
                return response.json();
            }
            return response.json();
        }).then(response => {
            if (response.success) {
                loadInfo();
                CTFd._functions.events.eventAlert({
                    title: "Success",
                    html: "Your instance has been deployed!",
                });
                resolve();
            } else {
                CTFd._functions.events.eventAlert({
                    title: "Fail",
                    html: response.message,
                });
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
    
    // First, destroy the current challenge instance
    CTFd._internal.challenge.destroy().then(() => {
        // Then, boot a new challenge instance
        return CTFd._internal.challenge.boot();
    }).then(() => {
        // Finally, load the challenge info
        loadInfo();
        $('#whale-button-boot').prop('disabled', false);
        $('#whale-button-restart').prop('disabled', false);
        $('#whale-button-renew').prop('disabled', false);
        $('#whale-button-destroy').prop('disabled', false);
    }).catch((error) => {
        console.error('Error during restart:', error);
    });
    
}


// // Old behavior in plugin for theme compatibility
// https://github.com/ctfer-io/ctfd-chall-manager/issues/234
CTFd._internal.challenge.submit = function(preview) {
    var challenge_id = parseInt($('#challenge-id').val())
    var submission = $('#challenge-input').val() // id changed in newer version of CTFd (old: #submission-input)

    var body = {
        'challenge_id': challenge_id,
        'submission': submission,
    }
    var params = {}
    if (preview)
        params['preview'] = true

    return CTFd.api.post_challenge_attempt(params, body).then(function(response) {
        if (response.status === 429) {
            // User was ratelimited but process response
            return response
        }
        if (response.status === 403) {
            // User is not logged in or CTF is paused.
            return response
        }
        return response
    })
};