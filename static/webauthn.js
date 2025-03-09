/**
 * @file webauthn.js
 * @author Chris Becker, Jake McDowell, Jason Page
 * @date March 8, 2024
 * @description Core WebAuthn functionality for FIDO2 Chat System
 *              Handles registration, authentication, and key management
 */

/**
 * WebAuthn Client Handler v1.6.0
 * Optimized for cross-platform FIDO2 security key authentication with improved debugging
 */
const webAuthn = {
    version: '1.6.0',
    
    // Enable debug mode to see all logs
    debugMode: true,
    
    // Store current user ID when authenticated
    currentUserId: null,
    
    // Remember if a key was already registered
    lastKeyRegistration: {
        wasExistingKey: false,
        userId: null
    },
    
    // Simplified endpoint path function
    getEndpointPath: function(endpoint) {
        // Always use root path for simplicity and consistency
        return `/${endpoint}`;
    },
    
    // Enhanced logging with timestamps
    log: function(message, obj) {
        const timestamp = new Date().toISOString().substr(11, 8); // HH:MM:SS
        if (this.debugMode) {
            if (obj) {
                console.log(`%c WebAuthn [${timestamp}]: ${message}`, 'color: #4CAF50; font-weight: bold;', obj);
            } else {
                console.log(`%c WebAuthn [${timestamp}]: ${message}`, 'color: #4CAF50; font-weight: bold;');
            }
        }
    },
    
    // Error logging with more visibility
    logError: function(message, error) {
        const timestamp = new Date().toISOString().substr(11, 8);
        console.error(`%c WebAuthn ERROR [${timestamp}]: ${message}`, 'color: #f44336; font-weight: bold;', error);
    },
    
    // Warning logging
    logWarn: function(message, obj) {
        const timestamp = new Date().toISOString().substr(11, 8);
        console.warn(`%c WebAuthn WARNING [${timestamp}]: ${message}`, 'color: #FF9800; font-weight: bold;', obj || '');
    },
    
    // Info about device and environment
    logEnvironmentInfo: function() {
        const info = {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            vendor: navigator.vendor,
            webAuthnSupport: !!navigator.credentials && !!navigator.credentials.create,
            isIOS: this.isIOS(),
            isMac: /Mac/.test(navigator.platform),
            isChrome: /Chrome/.test(navigator.userAgent) && !/Edge/.test(navigator.userAgent),
            isFirefox: /Firefox/.test(navigator.userAgent),
            isSafari: /Safari/.test(navigator.userAgent) && !/Chrome/.test(navigator.userAgent),
            isSecureContext: window.isSecureContext
        };
        
        console.log("%c WebAuthn Environment", "color: #2196F3; font-weight: bold; font-size: 14px;");
        console.table(info);
        return info;
    },
    
    // Check if device is iOS (needed for special handling)
    isIOS: function() {
        return /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
    },
    
    // Base64URL to ArrayBuffer with more robust error handling
    base64urlToArrayBuffer: function(base64url) {
        this.log(`Converting base64url to ArrayBuffer:`, {
            value: base64url ? base64url.substring(0, 20) + "..." : "null",
            length: base64url?.length || 0
        });
        
        try {
            // Make sure we're working with a string
            if (typeof base64url !== 'string') {
                throw new Error(`Input must be a string but was ${typeof base64url}`);
            }
            
            // Add padding to make it a valid base64 string (required by atob)
            const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + padding;
            
            // Try to decode using the native atob function
            let binary;
            try {
                binary = atob(base64);
            } catch (e) {
                this.logError(`atob error: ${e.message}. Trying fallback approach...`, e);
                // Try a more forgiving approach by cleaning the string
                const cleanBase64 = base64.replace(/[^A-Za-z0-9\+\/\=]/g, '');
                binary = atob(cleanBase64);
            }
            
            const buffer = new ArrayBuffer(binary.length);
            const view = new Uint8Array(buffer);
            for (let i = 0; i < binary.length; i++) {
                view[i] = binary.charCodeAt(i);
            }
            this.log(`Conversion completed, buffer length: ${buffer.byteLength}`);
            return buffer;
        } catch (error) {
            this.logError(`Base64URL conversion failed`, error);
            throw error;
        }
    },
    
    // ArrayBuffer to Base64URL with improved error handling
    arrayBufferToBase64url: function(buffer) {
        this.log(`Converting ArrayBuffer to base64url, buffer length: ${buffer.byteLength}`);
        try {
            // Ensure we have a valid ArrayBuffer
            if (!(buffer instanceof ArrayBuffer)) {
                throw new Error('Input must be an ArrayBuffer');
            }
            
            const view = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < view.length; i++) {
                binary += String.fromCharCode(view[i]);
            }
            
            // Try to use btoa to encode to base64
            let base64;
            try {
                base64 = btoa(binary);
            } catch (e) {
                this.log(`btoa error: ${e.message}. Trying fallback approach...`);
                // For very long strings, use a chunked approach
                const chunks = [];
                for (let i = 0; i < binary.length; i += 1024) {
                    chunks.push(btoa(binary.slice(i, i + 1024)));
                }
                base64 = chunks.join('');
            }
            
            const base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            this.log(`Conversion result: ${base64url.substring(0, 20)}...`);
            return base64url;
        } catch (error) {
            this.log(`Error converting ArrayBuffer: ${error.message}`);
            throw error;
        }
    },
    
    // Show modal with message
    showModal: function(message) {
        this.log(`Showing modal: ${message}`);
        const modal = document.getElementById('auth-modal');
        const modalText = document.getElementById('modal-text');
        
        if (!modal) {
            this.log('ERROR: auth-modal element not found in DOM');
            alert(message); // Fallback to alert if modal not found
            return;
        }
        
        if (modalText) {
            modalText.textContent = message;
        } else {
            this.log('WARNING: modal-text element not found in DOM');
        }
        
        modal.style.display = 'block';
    },
    
    // Hide modal
    hideModal: function() {
        this.log('Hiding modal');
        const modal = document.getElementById('auth-modal');
        if (!modal) {
            this.log('ERROR: auth-modal element not found in DOM');
            return;
        }
        
        modal.style.display = 'none';
    },

    // Helper function for debugging fetch operations
    debugFetch: function(url, options, callback) {
        this.log(`Fetch request to ${url}`);
        this.log(`Fetch options: ${JSON.stringify(options)}`);
        
        // Track timing
        const startTime = Date.now();
        
        return fetch(url, options)
            .then(response => {
                const endTime = Date.now();
                this.log(`Fetch response from ${url} in ${endTime - startTime}ms`);
                this.log(`Response status: ${response.status} ${response.statusText}`);
                
                // Clone the response so we can both check it and return it
                const responseClone = response.clone();
                
                // Attempt to read the response body for debugging
                responseClone.text().then(text => {
                    try {
                        // Try to parse as JSON to make it readable
                        const json = JSON.parse(text);
                        this.log(`Response body (JSON): ${JSON.stringify(json)}`);
                    } catch (e) {
                        // If not JSON, just log the text (truncated if very long)
                        if (text.length > 500) {
                            this.log(`Response body (text, truncated): ${text.substring(0, 500)}...`);
                        } else {
                            this.log(`Response body (text): ${text}`);
                        }
                    }
                }).catch(err => {
                    this.log(`Error reading response body: ${err.message}`);
                });
                
                // Call the original callback with the original response
                return callback(response);
            })
            .catch(error => {
                this.log(`Fetch error for ${url}: ${error.message}`);
                throw error;
            });
    },

    // Register a new security key
    registerKey: function() {
        this.log('Starting registration process');
        this.logEnvironmentInfo();
        
        this.showModal('Please insert your security key and follow the browser instructions...');

        const isIOS = this.isIOS();
        const isMac = /Mac/.test(navigator.platform);
        
        if (isIOS) {
            this.log('iOS device detected, using iOS-specific settings');
        }
        
        if (isMac) {
            this.log('Mac device detected, using Mac-specific settings');
        }

        const registerOptionsUrl = this.getEndpointPath('register_options');
        this.log(`Using registration options URL: ${registerOptionsUrl}`);

        // Use debugFetch instead of regular fetch
        this.debugFetch(
            registerOptionsUrl, 
            {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ timestamp: Date.now() })
            },
            response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        this.logError(`Error response: ${text}`);
                        throw new Error(`Failed to get registration options (${response.status}): ${text}`);
                    });
                }
                return response.json();
            }
        )
        .then(options => {
            this.log(`Received registration options:`, options);
            
            // Debug the challenge format specifically
            this.log("Challenge details:", {
                value: options.challenge,
                type: typeof options.challenge,
                length: options.challenge?.length || 0
            });
            
            // Debug the authenticatorSelection settings
            this.log("AuthenticatorSelection settings:", options.authenticatorSelection);
            
            // Enhanced error handling and logging for challenge conversion
            try {
                // Make sure challenge is a string before conversion
                if (typeof options.challenge !== 'string') {
                    this.logWarn(`Challenge is not a string! Type: ${typeof options.challenge}`);
                    options.challenge = String(options.challenge);
                }
                
                this.log(`Converting challenge: ${options.challenge}`);
                options.challenge = this.base64urlToArrayBuffer(options.challenge);
                this.log(`Challenge converted successfully`);
            } catch (e) {
                this.logError(`Failed to convert challenge: ${e.message}`, e);
                throw new Error(`Challenge conversion failed: ${e.message}`);
            }
            
            // Enhanced handling for user.id
            if (options.user && options.user.id) {
                try {
                    if (typeof options.user.id !== 'string') {
                        this.logWarn(`User ID is not a string! Type: ${typeof options.user.id}`);
                        options.user.id = String(options.user.id);
                    }
                    
                    this.log('Converting user ID:', options.user.id);
                    options.user.id = this.base64urlToArrayBuffer(options.user.id);
                    this.log('User ID converted successfully');
                } catch (e) {
                    this.logError(`Failed to convert user.id: ${e.message}`, e);
                    throw new Error(`User ID conversion failed: ${e.message}`);
                }
            }
            
            if (options.excludeCredentials) {
                for (let i = 0; i < options.excludeCredentials.length; i++) {
                    options.excludeCredentials[i].id = this.base64urlToArrayBuffer(options.excludeCredentials[i].id);
                }
            }
            
            // Device-specific adjustments
            if (isMac) {
                this.log('Applying Mac-specific adjustments');
                // Accept Mac's defaults, but ensure residentKey is set correctly
                options.authenticatorSelection = options.authenticatorSelection || {};
                
                // Keep requireResidentKey true, but ensure residentKey is properly set
                if (options.authenticatorSelection.requireResidentKey) {
                    options.authenticatorSelection.residentKey = "required";
                }
                
                this.log('Adjusted options for Mac compatibility', options.authenticatorSelection);
            }
            
            this.log('Converted all fields, final options:', options);
            
            // Step 2: Create credentials using WebAuthn API
            this.log("Calling navigator.credentials.create");
            return navigator.credentials.create({
                publicKey: options
            }).catch(err => {
                this.logError('Credential creation failed', err);
                console.error('ERROR DETAILS:', {
                    name: err.name,
                    message: err.message,
                    code: err.code,
                    stack: err.stack
                });
                throw err;
            });
        })
        .then(credential => {
            this.log('Credential created successfully, preparing data for server');
            this.log("Raw credential object:", {
                id: credential.id,
                type: credential.type,
                rawId: new Uint8Array(credential.rawId).slice(0, 10), // Preview of the rawId
                responseKeys: Object.keys(credential.response)
            });
            
            // Prepare the credential data to send to server
            try {
                const credentialId = this.arrayBufferToBase64url(credential.rawId);
                const clientDataJSON = this.arrayBufferToBase64url(credential.response.clientDataJSON);
                const attestationObject = this.arrayBufferToBase64url(credential.response.attestationObject);
                
                this.log("Encoded credential data:", {
                    credentialId: credentialId.substring(0, 20) + "...",
                    clientDataJSONPreview: clientDataJSON.substring(0, 20) + "...",
                    attestationObjectPreview: attestationObject.substring(0, 20) + "..."
                });
                
                const registerCompleteUrl = this.getEndpointPath('register_complete');
                this.log(`Using register complete URL: ${registerCompleteUrl}`);
                
                // Step 3: Send credential data to server
                return fetch(registerCompleteUrl, {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        id: credentialId,
                        rawId: credentialId,
                        type: credential.type,
                        response: {
                            clientDataJSON: clientDataJSON,
                            attestationObject: attestationObject
                        }
                    })
                });
            } catch (error) {
                this.logError("Failed to process credential for submission", error);
                throw error;
            }
        })
        .then(response => {
            this.log(`Response status: ${response.status}`);
            if (!response.ok) {
                return response.text().then(text => {
                    this.log(`Error response: ${text}`);
                    throw new Error(`Failed to complete registration (${response.status}): ${text}`);
                });
            }
            return response.json();
        })
        .then(result => {
            this.log(`Registration complete, result:`, result);
            this.hideModal();
            
            // Check if this was an existing key (already registered)
            if (result.status === 'existing_key') {
                this.lastKeyRegistration = {
                    wasExistingKey: true,
                    userId: result.userId
                };
                
                // Update the UI to reflect the authenticated state with the existing user
                this.updateUI(true, result.userId);
                
                // Alert the user that this key was already registered
                alert('This security key is already registered and has been used to log in to your existing account.');
            } else {
                // New registration
                this.lastKeyRegistration = {
                    wasExistingKey: false,
                    userId: result.userId
                };
                
                // Update the UI to reflect the authenticated state
                this.updateUI(true, result.userId);
                
                // Alert the user
                alert('Security key registered successfully!');
            }
        })
        .catch(error => {
            this.log(`Registration error: ${error.message}`);
            this.hideModal();
            alert(`Registration failed: ${error.message}`);
        });
        
        return false; // Prevent form submission
    },

    // Login with a registered security key
    loginWithKey: function() {
        this.log('Starting login process');
        this.showModal('Please insert your security key and follow the browser instructions...');

        const isIOS = this.isIOS();
        if (isIOS) {
            this.log('iOS device detected, using iOS-specific login settings');
        }

        const loginOptionsUrl = this.getEndpointPath('login_options');
        this.log(`Using login options URL: ${loginOptionsUrl}`);

        // Step 1: Get login options from server
        this.debugFetch(
            loginOptionsUrl,
            {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ timestamp: Date.now() })
            },
            response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        this.log(`Error response: ${text}`);
                        throw new Error(`Failed to get login options (${response.status}): ${text}`);
                    });
                }
                return response.json();
            }
        )
        .then(options => {
            this.log(`Received login options:`, options);
            
            // Convert base64url encoded values to ArrayBuffer
            options.challenge = this.base64urlToArrayBuffer(options.challenge);
            
            if (options.allowCredentials) {
                this.log(`Found ${options.allowCredentials.length} allowCredentials`);
                for (let i = 0; i < options.allowCredentials.length; i++) {
                    options.allowCredentials[i].id = this.base64urlToArrayBuffer(options.allowCredentials[i].id);
                    this.log(`Converted credential ${i+1}: ${options.allowCredentials[i].id.byteLength} bytes`);
                }
            } else {
                this.log('No allowCredentials found in options');
            }
            
            // iOS-specific adjustments
            if (isIOS) {
                // For iOS, userVerification should be discouraged or preferred
                options.userVerification = 'discouraged';
                
                // Ensure timeout is reasonable
                options.timeout = 120000; // 2 minutes
                
                this.log('Adjusted options for iOS compatibility');
            }
            
            this.log('Converted challenge and credential IDs to ArrayBuffer, calling navigator.credentials.get()');
            
            // Step 2: Get credentials using WebAuthn API
            return navigator.credentials.get({
                publicKey: options
            });
        })
        .then(assertion => {
            this.log('Assertion received successfully, preparing data for server');
            
            // Prepare the assertion data to send to server
            const credentialId = this.arrayBufferToBase64url(assertion.rawId);
            const clientDataJSON = this.arrayBufferToBase64url(assertion.response.clientDataJSON);
            const authenticatorData = this.arrayBufferToBase64url(assertion.response.authenticatorData);
            const signature = this.arrayBufferToBase64url(assertion.response.signature);
            
            this.log(`Assertion credential ID: ${credentialId.substring(0, 20)}...`);

            const loginCompleteUrl = this.getEndpointPath('login_complete');
            this.log(`Using login complete URL: ${loginCompleteUrl}`);
            
            // Step 3: Send assertion to server
            return fetch(loginCompleteUrl, {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    id: credentialId,
                    rawId: credentialId,
                    type: assertion.type,
                    response: {
                        clientDataJSON: clientDataJSON,
                        authenticatorData: authenticatorData,
                        signature: signature,
                        userHandle: assertion.response.userHandle ? this.arrayBufferToBase64url(assertion.response.userHandle) : null
                    }
                })
            });
        })
        .then(response => {
            this.log(`Response status: ${response.status}`);
            if (!response.ok) {
                return response.text().then(text => {
                    this.log(`Error response: ${text}`);
                    throw new Error(`Failed to complete login (${response.status}): ${text}`);
                });
            }
            return response.json();
        })
        .then(result => {
            this.log(`Login complete, result:`, result);
            this.hideModal();
            
            // Update the UI to reflect the authenticated state
            this.updateUI(true, result.userId);
            
            // Store the user ID
            this.currentUserId = result.userId;
            
            // Alert the user
            alert('Login successful!');
        })
        .catch(error => {
            this.log(`Login error: ${error.message}`);
            this.hideModal();
            alert(`Login failed: ${error.message}`);
        });
        
        return false; // Prevent form submission
    },

    // Logout
    logout: function() {
        this.log('Logging out');
        
        const logoutUrl = this.getEndpointPath('logout');
        this.log(`Using logout URL: ${logoutUrl}`);
        
        fetch(logoutUrl, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ timestamp: Date.now() })
        })
        .then(response => {
            this.log(`Response status: ${response.status}`);
            if (!response.ok) {
                return response.text().then(text => {
                    this.log(`Error response: ${text}`);
                    throw new Error(`Failed to logout (${response.status}): ${text}`);
                });
            }
            return response.json();
        })
        .then(result => {
            this.log('Logout successful');
            
            // Clear stored user ID
            this.currentUserId = null;
            
            // Update UI
            this.updateUI(false);
        })
        .catch(error => {
            this.log(`Logout error: ${error.message}`);
            alert(`Logout failed: ${error.message}`);
        });
        
        return false; // Prevent form submission
    },

    // Update UI based on authentication status
    updateUI: function(isAuthenticated, userId) {
        this.log('Updating UI for authentication state:', isAuthenticated);
        
        const authSection = document.getElementById('auth-status');
        const messageList = document.getElementById('message-list');
        const chatForm = document.getElementById('chat-form');
        
        if (isAuthenticated) {
            // Store userId for later use
            this.currentUserId = userId;
            
            // Display user is authenticated along with their ID and username cycling button
            const displayUserId = userId ? userId.substring(0, 8) + '...' : 'Unknown';
            
            // Get current username from server
            fetch(this.getEndpointPath('auth_status'), {
                method: 'GET',
                credentials: 'include'
            })
            .then(response => response.json())
            .then(data => {
                const username = data.username || 'Anonymous';
                authSection.innerHTML = `
                    <p>You are authenticated!</p>
                    <div class="user-info">
                        <p class="user-info-display">
                            <span class="username-display">Username: <span class="username-value">${username}</span></span>
                            <span class="user-id-display">ID: <span class="user-id-value" title="${userId || ''}">${displayUserId}</span></span>
                        </p>
                        <button onclick="webAuthn.cycleUsername(); return false;" class="button cycle-username-button">🎲 New Random Username</button>
                    </div>
                    <button onclick="webAuthn.logout(); return false;" class="button logout-button">Logout</button>
                `;
            })
            .catch(error => {
                this.logError('Error fetching username:', error);
                // Fallback to just showing ID if username fetch fails
                authSection.innerHTML = `
                    <p>You are authenticated!</p>
                    <div class="user-info">
                        <p class="user-info-display">
                            <span class="user-id-display">ID: <span class="user-id-value" title="${userId || ''}">${displayUserId}</span></span>
                        </p>
                        <button onclick="webAuthn.cycleUsername(); return false;" class="button cycle-username-button">🎲 New Random Username</button>
                    </div>
                    <button onclick="webAuthn.logout(); return false;" class="button logout-button">Logout</button>
                `;
            });
            
            // Show only the message input interface
            if (chatForm) chatForm.style.display = 'flex';
            
            // Start polling for messages
            this.startMessagePolling();
            
            // Dispatch event that user is authenticated
            document.dispatchEvent(new CustomEvent('userAuthenticated', { 
                detail: { userId: userId }
            }));
        } else {
            // Display unauthenticated state with registration and login buttons
            authSection.innerHTML = `
                <p>You are not authenticated.</p>
                <div class="auth-buttons">
                    <button onclick="webAuthn.registerKey(); return false;" class="button register-button">Register Security Key</button>
                    <button onclick="webAuthn.loginWithKey(); return false;" class="button login-button">Login</button>
                </div>
            `;
            
            // Hide only the message input interface
            if (chatForm) chatForm.style.display = 'none';
            
            // Clear current user ID
            this.currentUserId = null;
            
            // Dispatch event that user logged out
            document.dispatchEvent(new CustomEvent('userLoggedOut'));
        }

        // Always show message list and start polling
        if (messageList) messageList.style.display = 'block';
        this.loadMessages();
    },

    // Cycle to a new random username
    cycleUsername: function() {
        this.log('Cycling username...');
        
        const cycleButton = document.querySelector('.cycle-username-button');
        if (cycleButton) {
            cycleButton.disabled = true;
            cycleButton.textContent = '🎲 Changing...';
        }
        
        fetch(this.getEndpointPath('cycle_username'), {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => {
                    throw new Error(`Failed to cycle username (${response.status}): ${text}`);
                });
            }
            return response.json();
        })
        .then(result => {
            this.log('Username updated successfully:', result);
            
            // Show a fun notification
            const notification = document.createElement('div');
            notification.className = 'username-notification';
            notification.textContent = `Your new username is: ${result.username}`;
            document.body.appendChild(notification);
            
            // Remove notification after 3 seconds
            setTimeout(() => {
                notification.remove();
            }, 3000);
            
            // Immediately load messages to show the new username
            this.loadMessages();
        })
        .catch(error => {
            this.logError('Error cycling username:', error);
            alert(`Failed to change username: ${error.message}`);
        })
        .finally(() => {
            if (cycleButton) {
                cycleButton.disabled = false;
                cycleButton.textContent = '🎲 New Random Username';
            }
        });
    },

    // Load messages from the server
    loadMessages: function() {
        this.log('Loading messages...');
        
        const getMessagesUrl = this.getEndpointPath('get_messages');
        
        return fetch(getMessagesUrl, {
            method: 'GET',
            credentials: 'include'
        })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => {
                    throw new Error(`Failed to load messages (${response.status}): ${text}`);
                });
            }
            return response.json();
        })
        .then(messages => {
            this.log(`Loaded ${messages.length} messages`);
            this.displayMessages(messages);
            return messages;
        })
        .catch(error => {
            this.logError('Error loading messages:', error);
            return [];
        });
    },
    
    // Display messages in the UI
    displayMessages: function(messages) {
        const messageList = document.getElementById('message-list');
        if (!messageList) return;

        // Clear existing messages
        messageList.innerHTML = '';

        if (messages.length === 0) {
            messageList.innerHTML = '<p class="no-messages">No messages yet. Login to start chatting!</p>';
            return;
        }

        messages.forEach(msg => {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message';
            
            // Create username element
            const usernameSpan = document.createElement('span');
            usernameSpan.className = 'username';
            usernameSpan.textContent = msg.username + (msg.user === this.currentUserId ? ' (You)' : '');
            
            // Create timestamp element
            const timeSpan = document.createElement('span');
            timeSpan.className = 'timestamp';
            timeSpan.textContent = new Date(msg.time).toLocaleTimeString();
            
            // Create message content element
            const contentDiv = document.createElement('div');
            contentDiv.className = 'message-content';
            
            // Check if message contains an image link starting with @
            const imageMatch = msg.message.match(/^@(https?:\/\/.*\.(?:gif|png|jpe?g))$/i);
            if (imageMatch) {
                // Create image element
                const img = document.createElement('img');
                img.src = imageMatch[1];
                img.alt = 'Chat Image';
                img.className = 'chat-image';
                // Add loading indicator
                img.onload = () => img.classList.add('loaded');
                img.onerror = () => {
                    img.style.display = 'none';
                    contentDiv.textContent = msg.message;
                };
                contentDiv.appendChild(img);
            } else {
                contentDiv.textContent = msg.message;
            }
            
            // Assemble message
            messageDiv.appendChild(usernameSpan);
            messageDiv.appendChild(timeSpan);
            messageDiv.appendChild(contentDiv);
            
            messageList.appendChild(messageDiv);
        });
        
        // Scroll to bottom
        messageList.scrollTop = messageList.scrollHeight;
    },
    
    // Helper to format time
    formatTime: function(timestamp) {
        if (!timestamp) return 'Unknown time';
        
        try {
            const date = new Date(timestamp);
            return date.toLocaleTimeString([], { 
                hour: '2-digit', 
                minute: '2-digit',
                hour12: true
            });
        } catch (e) {
            return timestamp; // Fallback to raw timestamp
        }
    },
    
    // Helper to escape HTML
    escapeHtml: function(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },
    
    // Message polling variables
    messagePollingInterval: null,
    
    // Start polling for messages
    startMessagePolling: function() {
        this.log('Starting message polling');
        
        // Clear any existing polling
        this.stopMessagePolling();
        
        // Load messages immediately
        this.loadMessages();
        
        // Set up polling every 5 seconds
        this.messagePollingInterval = setInterval(() => {
            this.loadMessages();
        }, 5000);
    },
    
    // Stop polling for messages
    stopMessagePolling: function() {
        if (this.messagePollingInterval) {
            this.log('Stopping message polling');
            clearInterval(this.messagePollingInterval);
            this.messagePollingInterval = null;
        }
    },
    
    // Send a message
    sendMessage: function(event) {
        if (event) event.preventDefault();
        
        const messageInput = document.getElementById('message-input');
        if (!messageInput) return;
        
        const message = messageInput.value.trim();
        if (!message) return;
        
        // Check if this is an image message
        let finalMessage = message;
        if (message.startsWith('/image ')) {
            // Convert /image command to @ format
            finalMessage = '@' + message.substring(7);
        }
        
        // Validate image links
        const imageMatch = finalMessage.match(/^@(https?:\/\/.*\.(?:gif|png|jpe?g))$/i);
        if (imageMatch) {
            // Pre-validate the image URL
            const img = new Image();
            img.onerror = () => {
                alert('Invalid image URL or unsupported format. Please check the URL and try again.');
                messageInput.value = '';
                return;
            };
            img.onload = () => {
                // Image is valid, proceed with sending
                this.submitMessage(finalMessage, messageInput);
            };
            img.src = imageMatch[1];
        } else {
            // Regular message, send immediately
            this.submitMessage(finalMessage, messageInput);
        }
        
        return false;
    },
    
    // Helper function to submit the message to the server
    submitMessage: function(message, messageInput) {
        this.debugFetch(
            this.getEndpointPath('send_message'),
            {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message })
            },
            response => {
                if (!response.ok) {
                    return response.text().then(text => {
                        this.log(`Error response: ${text}`);
                        throw new Error(`Failed to send message (${response.status}): ${text}`);
                    });
                }
                return response.json();
            }
        )
        .then(result => {
            this.log('Message sent successfully');
            messageInput.value = '';
            this.loadMessages();
        })
        .catch(error => {
            this.log(`Send message error: ${error.message}`);
            alert(`Failed to send message: ${error.message}`);
        });
    },
    
    // Check auth status and update UI accordingly
    checkAuthStatus: function() {
        this.log('Checking authentication status...');
        
        const authStatusUrl = this.getEndpointPath('auth_status');
        
        return fetch(authStatusUrl, {
            method: 'GET',
            credentials: 'include'
        })
        .then(response => response.json())
        .then(status => {
            this.log('Auth status received:', status);
            // Store the user ID for later use
            if (status.authenticated && status.userId) {
                this.currentUserId = status.userId;
            } else {
                this.currentUserId = null;
            }
            // Update the UI with the authentication status and user ID
            this.updateUI(status.authenticated, status.userId);
            return status;
        })
        .catch(error => {
            this.logError('Error checking auth status:', error);
            this.updateUI(false);
            return { authenticated: false };
        });
    },
    
    // Debug the current state of WebAuthn
    debugState: function() {
        console.log("%c WebAuthn Current State", "color: #9C27B0; font-weight: bold; font-size: 14px;");
        console.table({
            version: this.version,
            currentUserId: this.currentUserId,
            isAuthenticated: !!this.currentUserId,
            lastKeyRegistration: this.lastKeyRegistration,
            isPolling: !!this.messagePollingInterval
        });
        
        // Check if we have credentials in the window
        if (navigator.credentials && navigator.credentials.get) {
            console.log("%c WebAuthn API Available", "color: #4CAF50; font-weight: bold;");
        } else {
            console.log("%c WebAuthn API NOT Available", "color: #F44336; font-weight: bold;");
        }
        
        // Try to get server state
        fetch(this.getEndpointPath('debug_all'), {
            method: 'GET',
            credentials: 'include'
        })
        .then(response => response.json())
        .then(data => {
            console.log("%c Server State", "color: #2196F3; font-weight: bold; font-size: 14px;");
            console.log(data);
        })
        .catch(error => {
            console.error("Failed to fetch server state:", error);
        });
        
        return "Debug information printed to console";
    },
    
    // Check if external security keys are supported
    checkExternalKeySupport: async function() {
        try {
            // Try to create a credential with cross-platform requirement
            const supported = await navigator.credentials.create({
                publicKey: {
                    challenge: new Uint8Array(32),
                    rp: {
                        name: "FIDO2 Chat System",
                        id: window.location.hostname
                    },
                    user: {
                        id: new Uint8Array(16),
                        name: "test@test.com",
                        displayName: "Test User"
                    },
                    pubKeyCredParams: [{
                        type: "public-key",
                        alg: -7
                    }],
                    authenticatorSelection: {
                        authenticatorAttachment: "cross-platform",
                        requireResidentKey: true,
                        residentKey: "required",
                        userVerification: "discouraged"
                    },
                    timeout: 1  // Set a very short timeout as we just want to check support
                }
            }).then(() => true).catch(error => {
                // Check if the error indicates no available authenticator
                return !error.message.includes('available authenticator');
            });
            
            this.log(`External security key support: ${supported}`);
            return supported;
        } catch (error) {
            this.log('Error checking external key support:', error);
            return false;
        }
    },

    // Initialize the application
    init: async function() {
        this.log('Initializing WebAuthn client');
        
        // Log platform information
        const env = this.logEnvironmentInfo();
        
        // Check WebAuthn and external key support
        const webAuthnSupport = !!navigator.credentials && !!navigator.credentials.create;
        const externalKeySupport = await this.checkExternalKeySupport();
        
        if (webAuthnSupport && !externalKeySupport) {
            alert("This application requires a physical security key (like a YubiKey). " +
                  "Platform authenticators like Face ID, Touch ID, or Windows Hello are not supported.");
        }
        
        if (env.isIOS) {
            this.log('iOS-specific optimizations will be applied');
        }
        
        // Check authentication status on page load
        this.checkAuthStatus();
        
        // Setup event handlers for message sending
        const chatForm = document.getElementById('chat-form');
        if (chatForm) {
            chatForm.addEventListener('submit', (event) => {
                this.sendMessage(event);
            });
            this.log('Chat form submit handler attached');
        }
        
        const sendButton = document.getElementById('send-button');
        if (sendButton) {
            sendButton.addEventListener('click', () => {
                this.sendMessage();
            });
            this.log('Send button click handler attached');
        }
        
        // Add a debug button if in development
        if (this.debugMode && document.getElementById('auth-status')) {
            const debugButton = document.createElement('button');
            debugButton.textContent = 'Debug WebAuthn';
            debugButton.className = 'button debug-button';
            debugButton.style.backgroundColor = '#9C27B0';
            debugButton.style.marginTop = '10px';
            debugButton.onclick = () => { this.debugState(); return false; };
            
            document.getElementById('auth-status').appendChild(debugButton);
            this.log('Debug button added');
        }
        
        this.log('Initialization complete');
    }
};

// Add styles to the document
const styles = document.createElement('style');
styles.textContent = `
    .chat-image {
        max-width: 300px;
        max-height: 200px;
        border-radius: 8px;
        margin: 5px 0;
        opacity: 0;
        transition: opacity 0.3s ease;
        object-fit: contain;
    }
    
    .chat-image.loaded {
        opacity: 1;
    }
    
    .message {
        padding: 10px;
        margin: 5px 0;
        background: #f5f5f5;
        border-radius: 8px;
        word-wrap: break-word;
    }
    
    .username {
        font-weight: bold;
        color: #2196F3;
        margin-right: 8px;
    }
    
    .timestamp {
        color: #666;
        font-size: 0.8em;
    }
    
    .message-content {
        margin-top: 5px;
    }
    
    .no-messages {
        text-align: center;
        color: #666;
        padding: 20px;
    }
    
    #message-list {
        max-height: 500px;
        overflow-y: auto;
        padding: 10px;
    }
`;
document.head.appendChild(styles);

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    webAuthn.init();
});