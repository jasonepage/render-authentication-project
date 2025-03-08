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
        this.log('Registration', 'Starting registration process...');
        try {
            this.showModal('Touch your key to register...');
            
            this.log('Registration', '1. Requesting registration options from server...');
            // 1. Get registration options from the server
            const optionsResponse = await fetch(`${this.SERVER_URL}/register_options`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ username: 'user' })
            });
            
            if (!optionsResponse.ok) {
                throw new Error('Failed to get registration options');
            }
            
            // 2. Parse the options
            const optionsJson = await optionsResponse.json();
            this.log('Registration', '2. Received registration options:', optionsJson);
            
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
            
            this.log('Registration', '4. Calling navigator.credentials.create...');
            // 4. Call the WebAuthn API to create credentials
            const credential = await navigator.credentials.create({
                publicKey: publicKeyOptions
            });
            this.log('Registration', '4. Credential created:', credential);
            
            // 5. Prepare response for the server
            this.log('Registration', '5. Preparing response for server...');
            const response = {
                id: credential.id,
                rawId: this.arrayBufferToBase64url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: this.arrayBufferToBase64url(credential.response.clientDataJSON),
                    attestationObject: this.arrayBufferToBase64url(credential.response.attestationObject)
                }
            };
            
            this.log('Registration', '6. Sending response to server...');
            // 6. Send the response to the server
            const verificationResponse = await fetch(`${this.SERVER_URL}/register_complete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(response)
            });
            
            if (!verificationResponse.ok) {
                throw new Error('Failed to register key');
            }
            
            const result = await verificationResponse.json();
            this.log('Registration', '7. Registration complete:', result);
            
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
            this.log('Registration', '❌ Registration failed:', error);
            alert(`Registration failed: ${error.message}`);
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
        const registerBtn = document.getElementById('register-btn');
        const loginBtn = document.getElementById('login-btn');
        const logoutBtn = document.getElementById('logout-btn');
        const messageInput = document.getElementById('message-input');
        const sendBtn = document.getElementById('send-btn');
        const authStatus = document.getElementById('auth-status');
        
        if (this.isAuthenticated) {
            registerBtn.classList.add('hidden');
            loginBtn.classList.add('hidden');
            logoutBtn.classList.remove('hidden');
            messageInput.disabled = false;
            sendBtn.disabled = false;
            authStatus.textContent = `Logged in as: ${this.userId}`;
            this.log('UI Update', `UI updated for authenticated user: ${this.userId}`);
        } else {
            registerBtn.classList.remove('hidden');
            loginBtn.classList.remove('hidden');
            logoutBtn.classList.add('hidden');
            messageInput.disabled = true;
            sendBtn.disabled = true;
            authStatus.textContent = 'Not logged in';
            this.log('UI Update', 'UI updated for unauthenticated state');
        }
    },
    
    // Initialize
    init() {
        this.log('Init', 'Initializing WebAuthn...');
        // Add event listeners
        document.getElementById('register-btn')?.addEventListener('click', () => this.registerKey());
        document.getElementById('login-btn')?.addEventListener('click', () => this.loginWithKey());
        document.getElementById('logout-btn')?.addEventListener('click', () => this.logout());
        
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