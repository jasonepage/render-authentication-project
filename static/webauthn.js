/**
 * WebAuthn Client Handler v1.4.1
 * Simplified and robust implementation for cross-device FIDO2 WebAuthn
 */
const webAuthn = {
    version: '1.4.1',
    
    log: function(message) {
        console.log(`WebAuthn [${this.version}]: ${message}`);
    },
    
    // Base64URL to ArrayBuffer
    base64urlToArrayBuffer: function(base64url) {
        this.log(`Converting base64url to ArrayBuffer: ${base64url.substring(0, 20)}...`);
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
    },
    
    // ArrayBuffer to Base64URL
    arrayBufferToBase64url: function(buffer) {
        this.log(`Converting ArrayBuffer to base64url, buffer length: ${buffer.byteLength}`);
        const view = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < view.length; i++) {
            binary += String.fromCharCode(view[i]);
        }
        const base64 = btoa(binary);
        const base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        this.log(`Conversion result: ${base64url.substring(0, 20)}...`);
        return base64url;
    },
    
    // Show modal with message
    showModal: function(message) {
        this.log(`Showing modal: ${message}`);
        const modal = document.getElementById('auth-modal');
        const modalText = document.getElementById('modal-text');
        if (modal && modalText) {
            modalText.textContent = message;
            modal.style.display = 'block';
        } else {
            alert(message);
        }
    },
    
    // Hide modal
    hideModal: function() {
        this.log('Hiding modal');
        const modal = document.getElementById('auth-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    },

    // Register a new security key
    registerKey: function() {
        this.log('Starting registration process');
        this.showModal('Please insert your security key and follow the browser instructions...');

        // Step 1: Get registration options from server
        fetch('/register_options', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to get registration options');
            }
            return response.json();
        })
        .then(options => {
            this.log(`Received registration options: ${JSON.stringify(options).substring(0, 100)}...`);
            
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
            
            // Step 3: Send credential data to server
            return fetch('/register_complete', {
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
            if (!response.ok) {
                throw new Error('Failed to complete registration');
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

        // Step 1: Get login options from server
        fetch('/login_options', {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json'
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to get login options');
            }
            return response.json();
        })
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
            
            // Step 3: Send assertion to server
            return fetch('/login_complete', {
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
            if (!response.ok) {
                throw new Error('Failed to complete login');
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
        
        fetch('/logout', {
            method: 'POST',
            credentials: 'include'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to logout');
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

    // Check authentication status
    checkAuthStatus: function() {
        this.log('Checking authentication status');
        
        fetch('/auth_status', {
            method: 'GET',
            credentials: 'include'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to check auth status');
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

    // Update UI based on authentication state
    updateUI: function(isAuthenticated) {
        this.log(`Updating UI, authenticated: ${isAuthenticated}`);
        
        const authDiv = document.getElementById('auth-status');
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

    // Start polling for chat messages
    startMessagePolling: function() {
        this.log('Starting message polling');
        
        if (!this.messageInterval) {
            this.messageInterval = setInterval(() => {
                this.fetchMessages();
            }, 2000); // Poll every 2 seconds
        }
    },

    // Stop polling for chat messages
    stopMessagePolling: function() {
        this.log('Stopping message polling');
        
        if (this.messageInterval) {
            clearInterval(this.messageInterval);
            this.messageInterval = null;
        }
    },

    // Fetch chat messages
    fetchMessages: function() {
        fetch('/messages', {
            method: 'GET',
            credentials: 'include'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Failed to fetch messages');
            }
            return response.json();
        })
        .then(messages => {
            const messageList = document.getElementById('message-list');
            if (messageList) {
                messageList.innerHTML = '';
                
                messages.forEach(msg => {
                    const messageItem = document.createElement('div');
                    messageItem.className = 'message-item';
                    messageItem.innerHTML = `
                        <strong>${msg.user_id}</strong>: ${msg.message} <span class="timestamp">${msg.timestamp}</span>
                    `;
                    messageList.appendChild(messageItem);
                });
                
                // Scroll to bottom
                messageList.scrollTop = messageList.scrollHeight;
            }
        })
        .catch(error => {
            console.error('Failed to fetch messages:', error);
        });
    },

    // Send a chat message
    sendMessage: function(event) {
        event.preventDefault();
        
        const messageInput = document.getElementById('message-input');
        const message = messageInput.value.trim();
        
        if (message) {
            this.log(`Sending message: ${message}`);
            
            fetch('/send_message', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message: message })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Failed to send message');
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
        }
    },

    // Initialize the application
    init: function() {
        this.log('Initializing WebAuthn client');
        
        // Check authentication status on page load
        this.checkAuthStatus();
        
        // Setup event handlers
        const chatForm = document.getElementById('chat-form');
        if (chatForm) {
            chatForm.addEventListener('submit', (event) => {
                this.sendMessage(event);
            });
        }
        
        this.log('Initialization complete');
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    webAuthn.log('DOM content loaded, initializing WebAuthn client');
    webAuthn.init();
}); 