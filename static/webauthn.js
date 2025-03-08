/**
 * WebAuthn Client Handler v1.4.3
 * Enhanced with iOS compatibility & routing fixes
 */
const webAuthn = {
    version: '1.4.3',
    
    // Determine correct API endpoint path
    getEndpointPath: function(endpoint) {
        this.log(`Finding path for endpoint: ${endpoint}`);
        
        // For maximum compatibility, try both static and root paths
        // Start with the simplest approach - direct root path
        const rootPath = `/${endpoint}`;
        
        // Then try '/static/' prefix which is needed in some environments
        const staticPath = `/static/${endpoint}`;
        
        // Testing code - try to fetch options from both paths to see which one works
        this.log(`Using root path: ${rootPath} (primary)`);
        
        // Show what we're choosing
        if (window.location.href.includes('render-authentication-project.onrender.com')) {
            this.log('Production environment detected');
        } else {
            this.log('Development environment detected');
        }
        
        // Always return root path first, we have alias routes set up
        return rootPath;
    },
    
    log: function(message) {
        console.log(`WebAuthn [${this.version}]: ${message}`);
    },
    
    // Detect iOS
    isIOS: function() {
        const ua = window.navigator.userAgent;
        const isIOS = /iPad|iPhone|iPod/.test(ua) || 
                     (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
        return isIOS;
    },
    
    // Base64URL to ArrayBuffer with iOS safety checks
    base64urlToArrayBuffer: function(base64url) {
        this.log(`Converting base64url to ArrayBuffer: ${base64url.substring(0, 20)}...`);
        try {
            const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/') + padding;
            const binary = atob(base64);
            const buffer = new ArrayBuffer(binary.length);
            const view = new Uint8Array(buffer);
            for (let i = 0; i < binary.length; i++) {
                view[i] = binary.charCodeAt(i);
            }
            this.log(`Conversion completed, buffer length: ${buffer.byteLength}`);
            return buffer;
        } catch (error) {
            this.log(`Error converting base64url: ${error.message}`);
            throw error;
        }
    },
    
    // ArrayBuffer to Base64URL with iOS safety
    arrayBufferToBase64url: function(buffer) {
        this.log(`Converting ArrayBuffer to base64url, buffer length: ${buffer.byteLength}`);
        try {
            const view = new Uint8Array(buffer);
            let binary = '';
            for (let i = 0; i < view.length; i++) {
                binary += String.fromCharCode(view[i]);
            }
            const base64 = btoa(binary);
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
        this.showModal('Please insert your security key and follow the browser instructions...');

        const isIOS = this.isIOS();
        if (isIOS) {
            this.log('iOS device detected, using iOS-specific settings');
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
                        this.log(`Error response: ${text}`);
                        throw new Error(`Failed to get registration options (${response.status}): ${text}`);
                    });
                }
                return response.json();
            }
        )
        .then(options => {
            this.log(`Received registration options: ${JSON.stringify(options)}`);
            
            // Convert base64url encoded values to ArrayBuffer as required by WebAuthn
            options.challenge = this.base64urlToArrayBuffer(options.challenge);
            
            if (options.user && options.user.id) {
                options.user.id = this.base64urlToArrayBuffer(options.user.id);
            }
            
            if (options.excludeCredentials) {
                for (let i = 0; i < options.excludeCredentials.length; i++) {
                    options.excludeCredentials[i].id = this.base64urlToArrayBuffer(options.excludeCredentials[i].id);
                }
            }
            
            // iOS-specific adjustments
            if (isIOS) {
                // Override any user verification and attachment settings for iOS
                options.authenticatorSelection = options.authenticatorSelection || {};
                options.authenticatorSelection.userVerification = 'discouraged';
                // Don't specify authenticatorAttachment for iOS - it causes issues
                delete options.authenticatorSelection.authenticatorAttachment;
                
                this.log('Adjusted options for iOS compatibility');
            }
            
            this.log('Converted challenge and IDs to ArrayBuffer, calling navigator.credentials.create()');
            
            // Step 2: Create credentials using WebAuthn API
            return navigator.credentials.create({
                publicKey: options
            });
        })
        .then(credential => {
            this.log('Credential created successfully, preparing data for server');
            
            // Prepare the credential data to send to server
            const credentialId = this.arrayBufferToBase64url(credential.rawId);
            const clientDataJSON = this.arrayBufferToBase64url(credential.response.clientDataJSON);
            const attestationObject = this.arrayBufferToBase64url(credential.response.attestationObject);
            
            this.log(`Credential ID: ${credentialId.substring(0, 20)}...`);
            
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
            this.updateUI(true);
            
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
            this.updateUI(true);
            
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

    // Update UI based on authentication state - with compatibility for different HTML templates
    updateUI: function(isAuthenticated) {
        this.log(`Updating UI, authenticated: ${isAuthenticated}`);
        
        // Look for any possible auth status element (handle both templates)
        let authDiv = document.getElementById('auth-status');
        
        // If auth-status not found, try the old element structure
        if (!authDiv) {
            const statusMessage = document.getElementById('status-message');
            if (statusMessage) {
                this.log('Found status-message element instead of auth-status, using legacy UI update');
                statusMessage.textContent = isAuthenticated ? 'You are authenticated!' : 'Not authenticated';
                
                // Handle button visibility in the old template
                const registerBtn = document.getElementById('register-button');
                const loginBtn = document.getElementById('login-button');
                const logoutBtn = document.getElementById('logout-button');
                
                if (registerBtn && loginBtn && logoutBtn) {
                    if (isAuthenticated) {
                        registerBtn.classList.add('hidden');
                        loginBtn.classList.add('hidden');
                        logoutBtn.classList.remove('hidden');
                    } else {
                        registerBtn.classList.remove('hidden');
                        loginBtn.classList.remove('hidden');
                        logoutBtn.classList.add('hidden');
                    }
                }
                
                // Chat elements in old template
                const messageInput = document.getElementById('message-input');
                const sendButton = document.getElementById('send-button');
                const messages = document.getElementById('messages');
                
                if (messageInput && sendButton) {
                    messageInput.disabled = !isAuthenticated;
                    sendButton.disabled = !isAuthenticated;
                }
                
                if (messages) {
                    // Clear loading message if authenticated
                    if (isAuthenticated) {
                        const loadingMsg = messages.querySelector('.message-loading');
                        if (loadingMsg) loadingMsg.style.display = 'none';
                    }
                }
                
                return; // Exit early as we've handled the old template
            }
            
            // If we can't find either element structure, log an error and exit
            this.log('ERROR: No authentication status elements found in DOM');
            return;
        }
        
        // If we get here, we found the auth-status element - standard template
        const chatForm = document.getElementById('chat-form');
        const messageList = document.getElementById('message-list');
        
        if (isAuthenticated) {
            // User is authenticated, show logout button and chat
            authDiv.innerHTML = `
                <p>You are authenticated!</p>
                <button onclick="webAuthn.logout(); return false;">Logout</button>
            `;
            
            if (chatForm) chatForm.style.display = 'block';
            if (messageList) messageList.style.display = 'block';
            
            // Start fetching messages
            this.startMessagePolling();
        } else {
            // User is not authenticated, show register and login buttons
            authDiv.innerHTML = `
                <p>You are not authenticated.</p>
                <button onclick="webAuthn.registerKey(); return false;">Register Security Key</button>
                <button onclick="webAuthn.loginWithKey(); return false;">Login</button>
            `;
            
            if (chatForm) chatForm.style.display = 'none';
            if (messageList) messageList.style.display = 'none';
            
            // Stop message polling
            this.stopMessagePolling();
        }
    },

    // Start message polling
    startMessagePolling: function() {
        this.log('Starting message polling');
        
        if (!this.messageInterval) {
            this.messageInterval = setInterval(() => {
                this.fetchMessages();
            }, 2000); // Poll every 2 seconds
        }
    },

    // Stop message polling
    stopMessagePolling: function() {
        this.log('Stopping message polling');
        
        if (this.messageInterval) {
            clearInterval(this.messageInterval);
            this.messageInterval = null;
        }
    },
    
    // Fetch chat messages
    fetchMessages: function() {
        const messagesUrl = this.getEndpointPath('get_messages');
        
        fetch(messagesUrl, {
            method: 'GET',
            credentials: 'include'
        })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => {
                    this.log(`Error response: ${text}`);
                    throw new Error(`Failed to fetch messages (${response.status}): ${text}`);
                });
            }
            return response.json();
        })
        .then(messages => {
            // Handle both message container types
            let messageContainer = document.getElementById('message-list');
            if (!messageContainer) {
                messageContainer = document.getElementById('messages');
            }
            
            if (!messageContainer) {
                this.log('WARNING: No message container found in DOM');
                return;
            }
            
            // Clear existing messages
            messageContainer.innerHTML = '';
            
            if (messages.length === 0) {
                // Add a placeholder message if no messages
                const placeholder = document.createElement('div');
                placeholder.className = messageContainer.id === 'messages' ? 'message' : 'message-item';
                placeholder.innerHTML = '<strong>System</strong>: No messages yet. Start chatting!';
                messageContainer.appendChild(placeholder);
                return;
            }
            
            // Add each message
            messages.forEach(msg => {
                const messageElem = document.createElement('div');
                messageElem.className = messageContainer.id === 'messages' ? 'message' : 'message-item';
                messageElem.innerHTML = `
                    <strong>${msg.user_id}</strong>: ${msg.message} 
                    <span class="${messageContainer.id === 'messages' ? 'time' : 'timestamp'}">${msg.timestamp}</span>
                `;
                messageContainer.appendChild(messageElem);
            });
            
            // Scroll to bottom
            messageContainer.scrollTop = messageContainer.scrollHeight;
        })
        .catch(error => {
            this.log(`Message fetch error: ${error.message}`);
        });
    },
    
    // Send a chat message with compatibility for both UI styles
    sendMessage: function(event) {
        if (event) {
            event.preventDefault();
        }
        
        // Check for message input in either UI style
        let messageInput = document.getElementById('message-input');
        if (!messageInput) {
            this.log('ERROR: message input element not found');
            return false;
        }
        
        const message = messageInput.value.trim();
        if (!message) {
            return false;
        }
        
        this.log(`Sending message: ${message}`);
        
        const sendMessageUrl = this.getEndpointPath('send_message');
        
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
                    this.log(`Error response: ${text}`);
                    throw new Error(`Failed to send message (${response.status}): ${text}`);
                });
            }
            return response.json();
        })
        .then(result => {
            this.log('Message sent successfully');
            messageInput.value = '';
            this.fetchMessages(); // Update messages immediately
        })
        .catch(error => {
            this.log(`Send message error: ${error.message}`);
            alert(`Failed to send message: ${error.message}`);
        });
        
        return false;
    },
    
    // Check authentication status
    checkAuthStatus: function() {
        this.log('Checking authentication status');
        
        const authStatusUrl = this.getEndpointPath('auth_status');
        this.log(`Using auth status URL: ${authStatusUrl}`);
        
        fetch(authStatusUrl, {
            method: 'GET',
            credentials: 'include'
        })
        .then(response => {
            this.log(`Response status: ${response.status}`);
            if (!response.ok) {
                return response.text().then(text => {
                    this.log(`Error response: ${text}`);
                    throw new Error(`Failed to check auth status (${response.status}): ${text}`);
                });
            }
            return response.json();
        })
        .then(result => {
            this.log(`Auth status: ${JSON.stringify(result)}`);
            this.updateUI(result.authenticated);
        })
        .catch(error => {
            this.log(`Auth status error: ${error.message}`);
            console.error('Failed to check authentication status:', error);
            this.updateUI(false); // Assume not authenticated on error
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
    webAuthn.log('DOM content loaded, initializing WebAuthn client');
    webAuthn.init();
});