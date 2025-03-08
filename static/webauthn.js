/**
 * WebAuthn Client Handler v1.5.0
 * Optimized for cross-platform FIDO2 security key authentication
 */
const webAuthn = {
    version: '1.5.0',
    
    // Enable debug mode to see all logs
    debugMode: true,
    
    // Simplified endpoint path function
    getEndpointPath: function(endpoint) {
        // Always use root path for simplicity and consistency
        return `/${endpoint}`;
    },
    
    // Enhanced logging function
    log: function(message, obj) {
        // Always log in debug mode
        if (this.debugMode || !window.location.href.includes('render-authentication-project.onrender.com') || 
            window.location.search.includes('debug=true')) {
            if (obj) {
                console.log(`%c WebAuthn [${this.version}]: ${message}`, 'color: #4CAF50; font-weight: bold;', obj);
            } else {
                console.log(`%c WebAuthn [${this.version}]: ${message}`, 'color: #4CAF50; font-weight: bold;');
            }
        }
    },
    
    // Error logging with more visibility
    logError: function(message, error) {
        console.error(`%c WebAuthn ERROR: ${message}`, 'color: #f44336; font-weight: bold;', error);
    },
    
    // Warning logging
    logWarn: function(message, obj) {
        console.warn(`%c WebAuthn WARNING: ${message}`, 'color: #FF9800; font-weight: bold;', obj || '');
    },
    
    // Check if device is iOS (needed for special handling)
    isIOS: function() {
        return /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
    },
    
    // Base64URL to ArrayBuffer with more robust error handling for Mac
    base64urlToArrayBuffer: function(base64url) {
        this.log(`Converting base64url to ArrayBuffer:`, base64url);
        console.log("DEBUG - Raw base64url data:", {
            value: base64url,
            type: typeof base64url,
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
            
            // Debug - log the exact string being passed to atob
            console.log("DEBUG - Processed base64 for atob:", {
                original: base64url,
                withPadding: base64,
                paddingAdded: padding.length
            });
            
            // Try to decode using the native atob function
            let binary;
            try {
                console.log("DEBUG - Calling atob with:", base64);
                binary = atob(base64);
                console.log("DEBUG - atob succeeded, result length:", binary.length);
            } catch (e) {
                this.logError(`atob error: ${e.message}. Trying fallback approach...`, e);
                // Try a more forgiving approach by cleaning the string
                const cleanBase64 = base64.replace(/[^A-Za-z0-9\+\/\=]/g, '');
                console.log("DEBUG - Fallback: cleaned base64:", cleanBase64);
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
            // Print detailed debugging info
            console.error('Base64URL Conversion Failure Details:', {
                input: base64url,
                inputType: typeof base64url,
                inputLength: base64url ? base64url.length : 0,
                error: error.message,
                stack: error.stack
            });
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
        console.log('DEBUG - Browser details:', {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            vendor: navigator.vendor,
            webAuthnSupport: !!navigator.credentials && !!navigator.credentials.create
        });
        
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
            console.log("DEBUG - Raw registration options:", JSON.parse(JSON.stringify(options)));
            
            // Debug the challenge format specifically
            console.log("DEBUG - Challenge details:", {
                value: options.challenge,
                type: typeof options.challenge,
                length: options.challenge?.length || 0
            });
            
            // Debug the user.id format
            if (options.user && options.user.id) {
                console.log("DEBUG - User ID details:", {
                    value: options.user.id,
                    type: typeof options.user.id,
                    length: options.user.id?.length || 0
                });
            }
            
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
            
            // Mac-specific adjustments
            if (isMac) {
                // macOS sometimes needs specific settings
                this.log('Applying Mac-specific adjustments');
                options.authenticatorSelection = options.authenticatorSelection || {};
                // Let's not be too restrictive on Mac
                options.authenticatorSelection.requireResidentKey = false;
                options.authenticatorSelection.userVerification = 'discouraged';
                
                this.log('Adjusted options for Mac compatibility', options.authenticatorSelection);
            }
            
            this.log('Converted all fields, final options:', options);
            
            // Step 2: Create credentials using WebAuthn API
            console.log("DEBUG - Calling navigator.credentials.create with:", JSON.parse(JSON.stringify({publicKey: options})));
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
            console.log("DEBUG - Raw credential object:", credential);
            
            // Prepare the credential data to send to server
            try {
                const credentialId = this.arrayBufferToBase64url(credential.rawId);
                const clientDataJSON = this.arrayBufferToBase64url(credential.response.clientDataJSON);
                const attestationObject = this.arrayBufferToBase64url(credential.response.attestationObject);
                
                console.log("DEBUG - Encoded credential data:", {
                    credentialId: credentialId,
                    clientDataJSON: clientDataJSON?.substring(0, 50) + "...",
                    attestationObjectPreview: attestationObject?.substring(0, 50) + "..."
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
            this.log(`Registration complete, result: ${JSON.stringify(result)}`);
            this.hideModal();
            
            // Update the UI to reflect the authenticated state
            this.updateUI(true, result.userId);
            
            // Alert the user
            alert('Security key registered successfully!');
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
            this.log(`Received login options: ${JSON.stringify(options).substring(0, 100)}...`);
            
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
            this.log(`Login complete, result: ${JSON.stringify(result)}`);
            this.hideModal();
            
            // Update the UI to reflect the authenticated state
            this.updateUI(true, result.userId);
            
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
            // Display user is authenticated along with their ID
            const displayUserId = userId ? userId.substring(0, 8) + '...' : 'Unknown';
            authSection.innerHTML = `
                <p>You are authenticated!</p>
                <p class="user-id-display">Your User ID: <span class="user-id-value" title="${userId || ''}">${displayUserId}</span></p>
                <button onclick="webAuthn.logout(); return false;" class="button logout-button">Logout</button>
            `;
            
            // Show the message interface
            messageList.style.display = 'block';
            chatForm.style.display = 'flex';
            
            // Load messages
            this.loadMessages();
            
            // Start polling for messages
            this.startMessagePolling();
        } else {
            // Display unauthenticated state with registration and login buttons
            authSection.innerHTML = `
                <p>You are not authenticated.</p>
                <div class="auth-buttons">
                    <button onclick="webAuthn.registerKey(); return false;" class="button register-button">Register Security Key</button>
                    <button onclick="webAuthn.loginWithKey(); return false;" class="button login-button">Login</button>
                </div>
            `;
            
            // Hide the message interface
            messageList.style.display = 'none';
            chatForm.style.display = 'none';
            
            // Stop polling for messages
            this.stopMessagePolling();
        }
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
        if (!messageList) {
            this.logError('Message list element not found');
            return;
        }
        
        // Clear current messages
        messageList.innerHTML = '';
        
        if (messages.length === 0) {
            // Show placeholder message
            const placeholder = document.createElement('div');
            placeholder.className = 'message-item system-message';
            placeholder.innerHTML = '<strong>System</strong>: No messages yet. Start chatting!';
            messageList.appendChild(placeholder);
            return;
        }
        
        // Add each message
        messages.forEach(message => {
            const messageElement = document.createElement('div');
            messageElement.className = 'message-item';
            
            // Check if this is the current user's message
            const isCurrentUser = this.currentUserId && message.user === this.currentUserId;
            if (isCurrentUser) {
                messageElement.classList.add('own-message');
            }
            
            // Format the user ID for display (either "You" or username or first 8 chars)
            let displayUser = isCurrentUser ? 'You' : (message.username || `User-${message.user.substring(0, 8)}`);
            
            // Format time if available
            let timeDisplay = '';
            if (message.time) {
                try {
                    const date = new Date(message.time);
                    timeDisplay = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                } catch (e) {
                    this.logError('Error formatting time:', e);
                }
            }
            
            messageElement.innerHTML = `
                <span class="message-user">${displayUser}</span>
                <span class="message-text">${this.escapeHtml(message.message)}</span>
                <span class="message-time">${timeDisplay}</span>
            `;
            
            messageList.appendChild(messageElement);
        });
        
        // Scroll to bottom
        messageList.scrollTop = messageList.scrollHeight;
    },
    
    // Helper to format time
    formatTime: function(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
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
        if (event) {
            event.preventDefault();
        }
        
        const messageInput = document.getElementById('message-input');
        const message = messageInput.value.trim();
        
        if (!message) {
            return;
        }
        
        this.log('Sending message:', message);
        
        const sendMessageUrl = this.getEndpointPath('send_message');
        
        // Show sending state
        messageInput.disabled = true;
        
        fetch(sendMessageUrl, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: message })
        })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => {
                    throw new Error(`Failed to send message (${response.status}): ${text}`);
                });
            }
            return response.json();
        })
        .then(result => {
            this.log('Message sent successfully:', result);
            messageInput.value = '';
            
            // Immediately load messages to show the new message
            this.loadMessages();
        })
        .catch(error => {
            this.logError('Error sending message:', error);
            alert(`Failed to send message: ${error.message}`);
        })
        .finally(() => {
            messageInput.disabled = false;
            messageInput.focus();
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
    
    // Initialize the application
    init: function() {
        this.log('Initializing WebAuthn client');
        
        // Log platform information
        const isIOS = this.isIOS();
        this.log(`Platform detection: iOS = ${isIOS}`);
        this.log(`User Agent: ${navigator.userAgent}`);
        
        if (isIOS) {
            this.log('iOS-specific optimizations will be applied');
        }
        
        // Log DOM availability for debugging
        this.log('DOM elements:');
        const elements = {
            'auth-status': document.getElementById('auth-status'),
            'status-message': document.getElementById('status-message'),
            'auth-modal': document.getElementById('auth-modal'),
            'modal': document.getElementById('modal'),
            'modal-text': document.getElementById('modal-text'),
            'modal-message': document.getElementById('modal-message'),
            'message-list': document.getElementById('message-list'),
            'messages': document.getElementById('messages'),
            'chat-form': document.getElementById('chat-form'),
            'message-input': document.getElementById('message-input'),
            'send-button': document.getElementById('send-button')
        };
        
        // Report which elements are missing
        Object.entries(elements).forEach(([name, element]) => {
            if (element) {
                this.log(`DOM element found: #${name}`);
            } else {
                this.log(`Note: DOM element not found: #${name}`);
            }
        });
        
        // Check authentication status on page load
        this.checkAuthStatus();
        
        // Setup event handlers for both UI styles
        const chatForm = elements['chat-form'];
        if (chatForm) {
            chatForm.addEventListener('submit', (event) => {
                this.sendMessage(event);
            });
            this.log('Chat form submit handler attached');
        }
        
        const sendButton = elements['send-button'];
        if (sendButton) {
            sendButton.addEventListener('click', () => {
                this.sendMessage();
            });
            this.log('Send button click handler attached');
        }
        
        this.log('Initialization complete');
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    const chatForm = document.getElementById('chat-form');
    if (chatForm) {
        chatForm.addEventListener('submit', function(event) {
            event.preventDefault();
            webAuthn.sendMessage();
        });
    }
    
    // Add custom CSS styles for user ID display
    const style = document.createElement('style');
    style.textContent = `
        .user-id-display {
            font-size: 0.9em;
            margin: 5px 0;
            color: #666;
        }
        .user-id-value {
            font-weight: bold;
            color: #4CAF50;
            cursor: help;
        }
        .auth-buttons {
            display: flex;
            gap: 10px;
            margin-top: 10px;
        }
        .button {
            padding: 8px 15px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .logout-button {
            background-color: #f44336;
        }
        .button:hover {
            opacity: 0.9;
        }
    `;
    document.head.appendChild(style);
    
    // Initialize
    webAuthn.checkAuthStatus();
});