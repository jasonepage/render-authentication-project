/**
 * WebAuthn Registration Module v1.0.0
 * Handles the registration process for WebAuthn
 */
const webAuthnRegister = {
    // DOM elements
    elements: {
        registerButton: null,
        modal: null,
        modalText: null
    },
    
    // Initialize the registration module
    init: function() {
        // Find DOM elements
        this.elements.registerButton = document.getElementById('register-button');
        this.elements.modal = document.getElementById('auth-modal');
        this.elements.modalText = document.getElementById('modal-text');
        
        // Add event listeners
        if (this.elements.registerButton) {
            this.elements.registerButton.addEventListener('click', this.startRegistration.bind(this));
        }
        
        webAuthnCore.log('Registration module initialized');
    },
    
    // Start the registration process
    startRegistration: function() {
        webAuthnCore.log('Starting registration process');
        this.showModal('Preparing registration...');
        
        // Get registration options from server
        fetch(webAuthnCore.getEndpointPath('registerOptions'), {
            method: 'GET',
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) {
                return response.json().then(data => {
                    throw new Error(data.error || 'Failed to get registration options');
                });
            }
            return response.json();
        })
        .then(options => {
            webAuthnCore.log('Received registration options', options);
            
            // Prepare options for navigator.credentials.create()
            const publicKeyOptions = this.preparePublicKeyOptions(options);
            
            this.showModal('Please follow your security key\'s instructions...');
            
            // Create credentials
            return navigator.credentials.create({
                publicKey: publicKeyOptions
            });
        })
        .then(credential => {
            webAuthnCore.log('Credential created', credential);
            
            // Prepare credential for sending to server
            const credentialResponse = this.prepareCredentialResponse(credential);
            
            this.showModal('Completing registration...');
            
            // Send credential to server
            return fetch(webAuthnCore.getEndpointPath('registerComplete'), {
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
                    throw new Error(data.error || 'Registration failed');
                });
            }
            return response.json();
        })
        .then(result => {
            webAuthnCore.log('Registration complete', result);
            
            // Store user ID
            webAuthnCore.currentUserId = result.user_id;
            webAuthnCore.currentUsername = result.username;
            
            // Check if this was an existing key
            if (result.existing_account) {
                webAuthnCore.lastKeyRegistration.wasExistingKey = true;
                webAuthnCore.lastKeyRegistration.userId = result.user_id;
                this.hideModal();
                webAuthnUI.updateAuthStatus(true, result.username);
                webAuthnUI.showMessage('This security key is already registered. You have been logged in.');
            } else {
                webAuthnCore.lastKeyRegistration.wasExistingKey = false;
                this.hideModal();
                webAuthnUI.updateAuthStatus(true, result.username);
                webAuthnUI.showMessage('Registration successful! You are now logged in.');
            }
        })
        .catch(error => {
            webAuthnCore.logError('Registration error', error);
            this.hideModal();
            webAuthnUI.showError('Registration failed: ' + error.message);
        });
    },
    
    // Prepare options for navigator.credentials.create()
    preparePublicKeyOptions: function(options) {
        const publicKeyOptions = {
            challenge: webAuthnCore.base64.decode(options.challenge),
            rp: options.rp,
            user: {
                id: webAuthnCore.base64.decode(options.user.id),
                name: options.user.name,
                displayName: options.user.displayName
            },
            pubKeyCredParams: options.pubKeyCredParams,
            timeout: options.timeout,
            attestation: options.attestation,
            authenticatorSelection: options.authenticatorSelection
        };
        
        // Add excludeCredentials if present
        if (options.excludeCredentials) {
            publicKeyOptions.excludeCredentials = options.excludeCredentials.map(credential => {
                return {
                    id: webAuthnCore.base64.decode(credential.id),
                    type: credential.type,
                    transports: credential.transports
                };
            });
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
                attestationObject: webAuthnCore.base64.encode(credential.response.attestationObject)
            }
        };
        
        // Add transports if available
        if (credential.response.getTransports) {
            credentialResponse.transports = credential.response.getTransports();
        }
        
        return credentialResponse;
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

// Initialize the registration module when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    if (webAuthnCore.isSupported()) {
        webAuthnRegister.init();
    }
}); 