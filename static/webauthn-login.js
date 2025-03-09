/**
 * WebAuthn Login Module v1.0.0
 * Handles the login process for WebAuthn
 */
const webAuthnLogin = {
    // DOM elements
    elements: {
        loginButton: null,
        modal: null,
        modalText: null
    },
    
    // Initialize the login module
    init: function() {
        // Find DOM elements
        this.elements.loginButton = document.getElementById('login-button');
        this.elements.modal = document.getElementById('auth-modal');
        this.elements.modalText = document.getElementById('modal-text');
        
        // Add event listeners
        if (this.elements.loginButton) {
            this.elements.loginButton.addEventListener('click', this.startLogin.bind(this));
        }
        
        webAuthnCore.log('Login module initialized');
    },
    
    // Start the login process
    startLogin: function() {
        webAuthnCore.log('Starting login process');
        this.showModal('Preparing login...');
        
        // Get login options from server
        fetch(webAuthnCore.getEndpointPath('loginOptions'), {
            method: 'POST',
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                if (response.status === 404) {
                    throw new Error(`Endpoint not found: ${webAuthnCore.getEndpointPath('loginOptions')}`);
                }
                return response.text().then(text => {
                    try {
                        // Try to parse as JSON
                        const data = JSON.parse(text);
                        throw new Error(data.error || `Server error: ${response.status}`);
                    } catch (e) {
                        // If not valid JSON, use the raw text
                        throw new Error(`Server error: ${response.status} - ${text}`);
                    }
                });
            }
            return response.json();
        })
        .then(options => {
            webAuthnCore.log('Received login options', options);
            
            // Prepare options for navigator.credentials.get()
            const publicKeyOptions = this.preparePublicKeyOptions(options);
            
            this.showModal('Please follow your security key\'s instructions...');
            
            // Get credentials
            return navigator.credentials.get({
                publicKey: publicKeyOptions
            });
        })
        .then(credential => {
            webAuthnCore.log('Credential retrieved', credential);
            
            // Prepare credential for sending to server
            const credentialResponse = this.prepareCredentialResponse(credential);
            
            this.showModal('Completing login...');
            
            // Send credential to server
            return fetch(webAuthnCore.getEndpointPath('loginComplete'), {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(credentialResponse)
            });
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || 'Login failed');
                });
            }
            return response.json();
        })
        .then(result => {
            webAuthnCore.log('Login complete', result);
            
            // Store user ID
            webAuthnCore.currentUserId = result.user_id;
            webAuthnCore.currentUsername = result.username;
            
            this.hideModal();
            webAuthnUI.updateAuthStatus(true, result.username);
            webAuthnUI.showMessage('Login successful!');
        })
        .catch(error => {
            webAuthnCore.logError('Login error', error);
            this.hideModal();
            webAuthnUI.showError('Login failed: ' + error.message);
        });
    },
    
    // Prepare options for navigator.credentials.get()
    preparePublicKeyOptions: function(options) {
        const publicKeyOptions = {
            challenge: webAuthnCore.base64.decode(options.challenge),
            timeout: options.timeout,
            rpId: options.rpId
        };
        
        // Add allowCredentials if present
        if (options.allowCredentials && options.allowCredentials.length > 0) {
            publicKeyOptions.allowCredentials = options.allowCredentials.map(credential => {
                return {
                    id: webAuthnCore.base64.decode(credential.id),
                    type: credential.type,
                    transports: credential.transports
                };
            });
        }
        
        // Add userVerification if present
        if (options.userVerification) {
            publicKeyOptions.userVerification = options.userVerification;
        }
        
        return publicKeyOptions;
    },
    
    // Prepare credential for sending to server
    prepareCredentialResponse: function(credential) {
        const credentialResponse = {
            id: credential.id,
            type: credential.type,
            response: {
                clientDataJSON: webAuthnCore.base64.encode(credential.response.clientDataJSON),
                authenticatorData: webAuthnCore.base64.encode(credential.response.authenticatorData),
                signature: webAuthnCore.base64.encode(credential.response.signature),
                userHandle: credential.response.userHandle ? webAuthnCore.base64.encode(credential.response.userHandle) : null
            }
        };
        
        return credentialResponse;
    },
    
    // Logout the user
    logout: function() {
        webAuthnCore.log('Logging out');
        
        fetch(webAuthnCore.getEndpointPath('logout'), {
            method: 'POST',
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || 'Logout failed');
                });
            }
            return response.json();
        })
        .then(result => {
            webAuthnCore.log('Logout complete', result);
            
            // Clear user ID
            webAuthnCore.currentUserId = null;
            webAuthnCore.currentUsername = null;
            
            webAuthnUI.updateAuthStatus(false);
            webAuthnUI.showMessage('You have been logged out.');
        })
        .catch(error => {
            webAuthnCore.logError('Logout error', error);
            webAuthnUI.showError('Logout failed: ' + error.message);
        });
    },
    
    // Show modal with message
    showModal: function(message) {
        if (this.elements.modalText) {
            this.elements.modalText.textContent = message;
        }
        if (this.elements.modal) {
            this.elements.modal.style.display = 'flex';
        }
    },
    
    // Hide modal
    hideModal: function() {
        if (this.elements.modal) {
            this.elements.modal.style.display = 'none';
        }
    }
};

// Initialize the login module when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    if (webAuthnCore.isSupported()) {
        webAuthnLogin.init();
    }
}); 