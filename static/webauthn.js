// WebAuthn API handling for key communication
const webAuthn = {
    // Server URL
    SERVER_URL: window.location.origin,
    
    // Keep track of authentication state
    isAuthenticated: false,
    userId: null,
    
    // Debug logging
    log(step, message, data = null) {
        console.log(`[WebAuthn] ${step}: ${message}`);
        if (data) {
            console.log(data);
        }
    },
    
    // Convert base64url to ArrayBuffer
    base64urlToArrayBuffer(base64url) {
        this.log('Base64URL Decode', `Converting: ${base64url.substring(0, 10)}...`);
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padding = '===='.slice(0, (4 - (base64.length % 4)) % 4);
        const base64String = base64 + padding;
        const binary = atob(base64String);
        const buffer = new ArrayBuffer(binary.length);
        const bytes = new Uint8Array(buffer);
        
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        
        this.log('Base64URL Decode', 'Conversion complete', { length: buffer.byteLength });
        return buffer;
    },
    
    // Convert ArrayBuffer to base64url
    arrayBufferToBase64url(buffer) {
        this.log('Base64URL Encode', `Converting buffer of length: ${buffer.byteLength}`);
        const bytes = new Uint8Array(buffer);
        let binary = '';
        
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        
        const base64 = btoa(binary);
        const base64url = base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        this.log('Base64URL Encode', `Result: ${base64url.substring(0, 10)}...`);
        return base64url;
    },
    
    // Show modal during key operations
    showModal(message) {
        this.log('UI', `Showing modal: ${message}`);
        document.getElementById('modal-message').textContent = message;
        document.getElementById('modal').classList.remove('hidden');
    },
    
    // Hide modal
    hideModal() {
        this.log('UI', 'Hiding modal');
        document.getElementById('modal').classList.add('hidden');
    },
    
    // Register a new key
    async registerKey() {
        this.log('Registration', '=== STARTING REGISTRATION PROCESS ===');
        
        // Check if already authenticated
        if (this.isAuthenticated) {
            this.log('Registration', 'Warning: Already authenticated, but registration attempted');
            alert('You are already registered and logged in. Please log out first if you want to register a new key.');
            return;
        }

        // Check browser support
        if (!window.PublicKeyCredential) {
            this.log('Registration', '❌ Browser does not support WebAuthn');
            throw new Error('WebAuthn is not supported in this browser');
        }

        try {
            this.showModal('Touch your key to register...');
            
            this.log('Registration', '1. Requesting registration options from server...');
            // 1. Get registration options from the server
            const optionsResponse = await fetch(`${this.SERVER_URL}/register_options`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ username: 'user' })
            }).catch(error => {
                this.log('Registration', `❌ Network error requesting options: ${error.message}`);
                throw error;
            });
            
            if (!optionsResponse.ok) {
                const error = await optionsResponse.text();
                this.log('Registration', `❌ Server rejected options request: ${error}`);
                throw new Error(`Failed to get registration options: ${error}`);
            }
            
            // 2. Parse the options
            const optionsJson = await optionsResponse.json();
            this.log('Registration', '2. Received registration options:', optionsJson);
            
            if (!optionsJson.challenge) {
                this.log('Registration', '❌ No challenge in server response');
                throw new Error('Invalid server response: missing challenge');
            }
            
            // 3. Prepare options for the browser's WebAuthn API
            this.log('Registration', '3. Preparing options for WebAuthn API...');
            const publicKeyOptions = {
                challenge: this.base64urlToArrayBuffer(optionsJson.challenge),
                rp: {
                    name: 'Key Chat System',
                    id: 'render-authentication-project.onrender.com'
                },
                user: {
                    id: this.base64urlToArrayBuffer(optionsJson.user.id),
                    name: optionsJson.user.name,
                    displayName: optionsJson.user.displayName
                },
                pubKeyCredParams: [
                    { type: 'public-key', alg: -7 } // ES256 algorithm
                ],
                authenticatorSelection: {
                    authenticatorAttachment: 'cross-platform',
                    requireResidentKey: false,
                    userVerification: 'discouraged'
                },
                timeout: 60000,
                attestation: 'none'
            };
            
            this.log('Registration', '4. Calling navigator.credentials.create with options:', publicKeyOptions);
            // 4. Call the WebAuthn API to create credentials
            const credential = await navigator.credentials.create({
                publicKey: publicKeyOptions
            }).catch(error => {
                this.log('Registration', `❌ WebAuthn API error: ${error.message}`);
                throw error;
            });
            
            this.log('Registration', '5. Credential created successfully:', credential);
            
            // 5. Prepare response for the server
            this.log('Registration', '6. Preparing response for server...');
            const response = {
                id: credential.id,
                rawId: this.arrayBufferToBase64url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: this.arrayBufferToBase64url(credential.response.clientDataJSON),
                    attestationObject: this.arrayBufferToBase64url(credential.response.attestationObject)
                }
            };
            
            this.log('Registration', '7. Sending response to server...');
            // 6. Send the response to the server
            const verificationResponse = await fetch(`${this.SERVER_URL}/register_complete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(response)
            }).catch(error => {
                this.log('Registration', `❌ Network error sending verification: ${error.message}`);
                throw error;
            });
            
            if (!verificationResponse.ok) {
                const error = await verificationResponse.text();
                this.log('Registration', `❌ Server rejected verification: ${error}`);
                throw new Error(`Failed to register key: ${error}`);
            }
            
            const result = await verificationResponse.json();
            this.log('Registration', '✅ Registration complete:', result);
            
            this.hideModal();
            
            // Update authentication state immediately
            this.isAuthenticated = true;
            this.userId = result.userId;
            this.updateUI();
            
            // Trigger event for chat.js
            const event = new CustomEvent('userAuthenticated', {
                detail: { userId: this.userId }
            });
            document.dispatchEvent(event);
            
            return result;
        } catch (error) {
            this.hideModal();
            this.log('Registration', `❌ Registration failed: ${error.message}`);
            this.log('Registration', 'Stack trace:', error.stack);
            throw error;
        }
    },
    
    // Login with key
    async loginWithKey() {
        this.log('Login', 'Starting login process...');
        try {
            this.showModal('Touch your key to login...');
            
            this.log('Login', '1. Requesting login options from server...');
            // 1. Get authentication options from the server
            const optionsResponse = await fetch(`${this.SERVER_URL}/login_options`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include'
            });
            
            if (!optionsResponse.ok) {
                throw new Error('Failed to get login options');
            }
            
            // 2. Parse the options
            const optionsJson = await optionsResponse.json();
            this.log('Login', '2. Received login options:', optionsJson);
            
            // 3. Prepare options for the browser's WebAuthn API
            this.log('Login', '3. Preparing options for WebAuthn API...');
            const publicKeyOptions = {
                challenge: this.base64urlToArrayBuffer(optionsJson.challenge),
                rpId: 'render-authentication-project.onrender.com',
                timeout: 60000,
                userVerification: 'discouraged'
            };
            
            // If we have allowCredentials from the server, add them
            if (optionsJson.allowCredentials && optionsJson.allowCredentials.length > 0) {
                this.log('Login', `Found ${optionsJson.allowCredentials.length} allowed credential(s)`);
                publicKeyOptions.allowCredentials = optionsJson.allowCredentials.map(cred => ({
                    id: this.base64urlToArrayBuffer(cred.id),
                    type: 'public-key',
                    transports: ['usb', 'nfc']
                }));
            }
            
            this.log('Login', '4. Calling navigator.credentials.get...');
            // 4. Call the WebAuthn API to get assertion
            const assertion = await navigator.credentials.get({
                publicKey: publicKeyOptions
            });
            this.log('Login', '4. Assertion received:', assertion);
            
            // 5. Prepare response for the server
            this.log('Login', '5. Preparing response for server...');
            const response = {
                id: assertion.id,
                rawId: this.arrayBufferToBase64url(assertion.rawId),
                type: assertion.type,
                response: {
                    clientDataJSON: this.arrayBufferToBase64url(assertion.response.clientDataJSON),
                    authenticatorData: this.arrayBufferToBase64url(assertion.response.authenticatorData),
                    signature: this.arrayBufferToBase64url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? this.arrayBufferToBase64url(assertion.response.userHandle) : null
                }
            };
            
            this.log('Login', '6. Sending response to server...');
            // 6. Send the assertion to the server
            const verificationResponse = await fetch(`${this.SERVER_URL}/login_complete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(response)
            });
            
            if (!verificationResponse.ok) {
                throw new Error('Failed to login with key');
            }
            
            const result = await verificationResponse.json();
            this.log('Login', '7. Login complete:', result);
            
            // Update authentication state
            this.isAuthenticated = true;
            this.userId = result.userId;
            
            this.hideModal();
            this.updateUI();
            
            // Trigger event for chat.js
            const event = new CustomEvent('userAuthenticated', {
                detail: { userId: this.userId }
            });
            document.dispatchEvent(event);
            
            return result;
        } catch (error) {
            this.hideModal();
            this.log('Login', '❌ Login failed:', error);
            alert(`Login failed: ${error.message}`);
            throw error;
        }
    },
    
    // Log out
    async logout() {
        this.log('Logout', 'Starting logout process...');
        try {
            const response = await fetch(`${this.SERVER_URL}/logout`, {
                method: 'POST',
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error('Logout failed');
            }
            
            this.isAuthenticated = false;
            this.userId = null;
            this.updateUI();
            
            this.log('Logout', 'Logout successful');
            
            // Trigger event for chat.js
            document.dispatchEvent(new Event('userLoggedOut'));
        } catch (error) {
            this.log('Logout', '❌ Logout failed:', error);
            alert(`Logout failed: ${error.message}`);
        }
    },
    
    // Check if user is already authenticated
    async checkAuthStatus() {
        this.log('Auth Check', 'Checking authentication status...');
        try {
            const response = await fetch(`${this.SERVER_URL}/auth_status`, {
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error('Failed to check auth status');
            }
            
            const data = await response.json();
            this.log('Auth Check', 'Status received:', data);
            
            this.isAuthenticated = data.authenticated;
            this.userId = data.userId;
            this.updateUI();
            
            if (this.isAuthenticated) {
                this.log('Auth Check', `User is authenticated as: ${this.userId}`);
                // Trigger event for chat.js
                const event = new CustomEvent('userAuthenticated', {
                    detail: { userId: this.userId }
                });
                document.dispatchEvent(event);
            } else {
                this.log('Auth Check', 'User is not authenticated');
            }
        } catch (error) {
            this.log('Auth Check', '❌ Auth check failed:', error);
        }
    },
    
    // Update UI based on authentication state
    updateUI() {
        this.log('UI Update', `Updating UI for auth state: ${this.isAuthenticated}`);
        
        // Get all UI elements
        const elements = {
            registerBtn: document.getElementById('register-btn'),
            loginBtn: document.getElementById('login-btn'),
            logoutBtn: document.getElementById('logout-btn'),
            messageInput: document.getElementById('message-input'),
            sendBtn: document.getElementById('send-btn'),
            authStatus: document.getElementById('auth-status')
        };

        // Log which elements were found/not found
        Object.entries(elements).forEach(([name, element]) => {
            if (!element) {
                console.error(`[WebAuthn] UI element not found: ${name}`);
            }
        });

        if (this.isAuthenticated) {
            this.log('UI Update', `Updating UI for authenticated user: ${this.userId}`);
            
            // Hide auth buttons, show logout
            elements.registerBtn?.classList.add('hidden');
            elements.loginBtn?.classList.add('hidden');
            elements.logoutBtn?.classList.remove('hidden');
            
            // Enable chat controls
            if (elements.messageInput) elements.messageInput.disabled = false;
            if (elements.sendBtn) elements.sendBtn.disabled = false;
            
            // Update status
            if (elements.authStatus) {
                elements.authStatus.textContent = `Logged in as: ${this.userId}`;
                elements.authStatus.classList.remove('text-red-500');
                elements.authStatus.classList.add('text-green-500');
            }
        } else {
            this.log('UI Update', 'Updating UI for unauthenticated state');
            
            // Show auth buttons, hide logout
            elements.registerBtn?.classList.remove('hidden');
            elements.loginBtn?.classList.remove('hidden');
            elements.logoutBtn?.classList.add('hidden');
            
            // Disable chat controls
            if (elements.messageInput) elements.messageInput.disabled = true;
            if (elements.sendBtn) elements.sendBtn.disabled = true;
            
            // Update status
            if (elements.authStatus) {
                elements.authStatus.textContent = 'Not logged in';
                elements.authStatus.classList.remove('text-green-500');
                elements.authStatus.classList.add('text-red-500');
            }
        }

        // Force a reflow to ensure CSS changes are applied
        document.body.offsetHeight;
    },
    
    // Initialize
    init() {
        this.log('Init', 'Initializing WebAuthn...');
        
        // Add event listeners with better error handling
        const registerBtn = document.getElementById('register-btn');
        if (registerBtn) {
            this.log('Init', 'Found register button, adding click handler');
            registerBtn.addEventListener('click', async (e) => {
                this.log('Click', 'Register button clicked');
                e.preventDefault();
                try {
                    if (!window.PublicKeyCredential) {
                        throw new Error('WebAuthn is not supported in this browser');
                    }
                    await this.registerKey();
                } catch (error) {
                    console.error('[WebAuthn] Registration error:', error);
                    alert(`Registration failed: ${error.message}`);
                }
            });
        } else {
            console.error('[WebAuthn] Register button not found in DOM');
        }

        // Add other event listeners with similar error handling
        const loginBtn = document.getElementById('login-btn');
        if (loginBtn) {
            this.log('Init', 'Found login button, adding click handler');
            loginBtn.addEventListener('click', async (e) => {
                this.log('Click', 'Login button clicked');
                e.preventDefault();
                try {
                    await this.loginWithKey();
                } catch (error) {
                    console.error('[WebAuthn] Login error:', error);
                    alert(`Login failed: ${error.message}`);
                }
            });
        }

        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            this.log('Init', 'Found logout button, adding click handler');
            logoutBtn.addEventListener('click', async (e) => {
                this.log('Click', 'Logout button clicked');
                e.preventDefault();
                try {
                    await this.logout();
                } catch (error) {
                    console.error('[WebAuthn] Logout error:', error);
                    alert(`Logout failed: ${error.message}`);
                }
            });
        }
        
        // Check initial auth status
        this.checkAuthStatus();
        this.log('Init', 'Initialization complete');
    }
};

// Initialize when the document is ready
document.addEventListener('DOMContentLoaded', () => {
    console.log('[WebAuthn] Document ready, initializing...');
    webAuthn.init();
}); 