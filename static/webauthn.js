// WebAuthn API handling for YubiKey communication
const webAuthn = {
    // Server URL
    SERVER_URL: window.location.origin,
    
    // Keep track of authentication state
    isAuthenticated: false,
    userId: null,
    
    // Convert base64url to ArrayBuffer
    base64urlToArrayBuffer(base64url) {
        const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
        const padding = '===='.slice(0, (4 - (base64.length % 4)) % 4);
        const base64String = base64 + padding;
        const binary = atob(base64String);
        const buffer = new ArrayBuffer(binary.length);
        const bytes = new Uint8Array(buffer);
        
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        
        return buffer;
    },
    
    // Convert ArrayBuffer to base64url
    arrayBufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        
        const base64 = btoa(binary);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    },
    
    // Show modal during YubiKey operations
    showModal(message) {
        document.getElementById('modal-message').textContent = message;
        document.getElementById('modal').classList.remove('hidden');
    },
    
    // Hide modal
    hideModal() {
        document.getElementById('modal').classList.add('hidden');
    },
    
    // Register a new YubiKey
    async registerYubiKey() {
        try {
            this.showModal('Touch your YubiKey to register...');
            
            // 1. Get registration options from the server
            const optionsResponse = await fetch(`${this.SERVER_URL}/register_options`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: 'user' }) // In a real app, get username from input
            });
            
            if (!optionsResponse.ok) {
                throw new Error('Failed to get registration options');
            }
            
            // 2. Parse the options
            const optionsJson = await optionsResponse.json();
            
            // 3. Prepare options for the browser's WebAuthn API
            const publicKeyOptions = {
                challenge: this.base64urlToArrayBuffer(optionsJson.challenge),
                rp: {
                    name: 'YubiKey Chat System',
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
            
            // 4. Call the WebAuthn API to create credentials
            const credential = await navigator.credentials.create({
                publicKey: publicKeyOptions
            });
            
            // 5. Prepare response for the server
            const response = {
                id: credential.id,
                rawId: this.arrayBufferToBase64url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: this.arrayBufferToBase64url(credential.response.clientDataJSON),
                    attestationObject: this.arrayBufferToBase64url(credential.response.attestationObject)
                }
            };
            
            // 6. Send the response to the server
            const verificationResponse = await fetch(`${this.SERVER_URL}/register_complete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(response)
            });
            
            if (!verificationResponse.ok) {
                throw new Error('Failed to register YubiKey');
            }
            
            const result = await verificationResponse.json();
            
            this.hideModal();
            
            // Auto-login after successful registration
            await this.loginWithYubiKey();
            
            return result;
        } catch (error) {
            this.hideModal();
            console.error('Registration error:', error);
            alert(`Registration failed: ${error.message}`);
            throw error;
        }
    },
    
    // Login with YubiKey
    async loginWithYubiKey() {
        try {
            this.showModal('Touch your YubiKey to login...');
            
            // 1. Get authentication options from the server
            const optionsResponse = await fetch(`${this.SERVER_URL}/login_options`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            });
            
            if (!optionsResponse.ok) {
                throw new Error('Failed to get login options');
            }
            
            // 2. Parse the options
            const optionsJson = await optionsResponse.json();
            
            // 3. Prepare options for the browser's WebAuthn API
            const publicKeyOptions = {
                challenge: this.base64urlToArrayBuffer(optionsJson.challenge),
                rpId: 'render-authentication-project.onrender.com',
                timeout: 60000,
                userVerification: 'discouraged'
            };
            
            // If we have allowCredentials from the server, add them
            if (optionsJson.allowCredentials && optionsJson.allowCredentials.length > 0) {
                publicKeyOptions.allowCredentials = optionsJson.allowCredentials.map(cred => ({
                    id: this.base64urlToArrayBuffer(cred.id),
                    type: 'public-key',
                    transports: ['usb', 'nfc']
                }));
            }
            
            // 4. Call the WebAuthn API to get assertion
            const assertion = await navigator.credentials.get({
                publicKey: publicKeyOptions
            });
            
            // 5. Prepare response for the server
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
            
            // 6. Send the assertion to the server
            const verificationResponse = await fetch(`${this.SERVER_URL}/login_complete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(response),
                credentials: 'include' // This ensures cookies are sent
            });
            
            if (!verificationResponse.ok) {
                throw new Error('Failed to login with YubiKey');
            }
            
            const result = await verificationResponse.json();
            
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
            console.error('Login error:', error);
            alert(`Login failed: ${error.message}`);
            throw error;
        }
    },
    
    // Log out
    logout() {
        fetch(`${this.SERVER_URL}/logout`, {
            method: 'POST',
            credentials: 'include'
        }).then(() => {
            this.isAuthenticated = false;
            this.userId = null;
            this.updateUI();
            
            // Trigger event for chat.js
            document.dispatchEvent(new Event('userLoggedOut'));
        }).catch(error => {
            console.error('Logout error:', error);
        });
    },
    
    // Check if user is already authenticated
    checkAuthStatus() {
        fetch(`${this.SERVER_URL}/auth_status`, {
            credentials: 'include'
        }).then(response => response.json())
        .then(data => {
            this.isAuthenticated = data.authenticated;
            this.userId = data.userId;
            this.updateUI();
            
            if (this.isAuthenticated) {
                // Trigger event for chat.js
                const event = new CustomEvent('userAuthenticated', {
                    detail: { userId: this.userId }
                });
                document.dispatchEvent(event);
            }
        }).catch(error => {
            console.error('Auth status check error:', error);
        });
    },
    
    // Update UI based on authentication state
    updateUI() {
        const statusMessage = document.getElementById('status-message');
        const registerButton = document.getElementById('register-button');
        const loginButton = document.getElementById('login-button');
        const logoutButton = document.getElementById('logout-button');
        const messageInput = document.getElementById('message-input');
        const sendButton = document.getElementById('send-button');
        
        if (this.isAuthenticated) {
            statusMessage.textContent = `Logged in as ${this.userId}`;
            statusMessage.classList.add('authenticated');
            registerButton.classList.add('hidden');
            loginButton.classList.add('hidden');
            logoutButton.classList.remove('hidden');
            messageInput.disabled = false;
            sendButton.disabled = false;
        } else {
            statusMessage.textContent = 'Not authenticated';
            statusMessage.classList.remove('authenticated');
            registerButton.classList.remove('hidden');
            loginButton.classList.remove('hidden');
            logoutButton.classList.add('hidden');
            messageInput.disabled = true;
            sendButton.disabled = true;
        }
    },
    
    // Initialize WebAuthn functionality
    init() {
        // Check if WebAuthn is supported
        if (!window.PublicKeyCredential) {
            alert('WebAuthn is not supported in this browser. Please use Chrome, Firefox, Edge, or Safari.');
            return;
        }
        
        // Set up event listeners
        document.getElementById('register-button').addEventListener('click', () => this.registerYubiKey());
        document.getElementById('login-button').addEventListener('click', () => this.loginWithYubiKey());
        document.getElementById('logout-button').addEventListener('click', () => this.logout());
        
        // Check if user is already authenticated
        this.checkAuthStatus();
    }
};

// Initialize WebAuthn when the page loads
document.addEventListener('DOMContentLoaded', () => {
    webAuthn.init();
}); 