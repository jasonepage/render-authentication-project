/**
 * WebAuthn UI Module v1.0.0
 * Handles the user interface for WebAuthn
 */
const webAuthnUI = {
    // DOM elements
    elements: {
        authStatus: null,
        registerButton: null,
        loginButton: null,
        logoutButton: null,
        messageContainer: null
    },
    
    // Message timeout
    messageTimeout: null,
    
    // Initialize the UI module
    init: function() {
        // Find DOM elements
        this.elements.authStatus = document.getElementById('auth-status');
        this.elements.registerButton = document.getElementById('register-button');
        this.elements.loginButton = document.getElementById('login-button');
        this.elements.logoutButton = document.getElementById('logout-button');
        this.elements.messageContainer = document.getElementById('message-container');
        
        // Add event listeners
        if (this.elements.logoutButton) {
            this.elements.logoutButton.addEventListener('click', webAuthnLogin.logout.bind(webAuthnLogin));
        }
        
        // Check authentication status
        this.checkAuthStatus();
        
        webAuthnCore.log('UI module initialized');
    },
    
    // Check authentication status
    checkAuthStatus: function() {
        webAuthnCore.log('Checking authentication status');
        
        fetch(webAuthnCore.getEndpointPath('authStatus'), {
            method: 'GET',
            credentials: 'same-origin'
        })
        .then(response => response.json())
        .then(data => {
            webAuthnCore.log('Authentication status', data);
            
            if (data.authenticated) {
                webAuthnCore.currentUserId = data.user_id;
                webAuthnCore.currentUsername = data.username;
                this.updateAuthStatus(true, data.username);
            } else {
                this.updateAuthStatus(false);
            }
        })
        .catch(error => {
            webAuthnCore.logError('Error checking authentication status', error);
            this.updateAuthStatus(false);
        });
    },
    
    // Update authentication status UI
    updateAuthStatus: function(isAuthenticated, username) {
        if (!this.elements.authStatus) return;
        
        if (isAuthenticated) {
            // User is authenticated
            this.elements.authStatus.innerHTML = `
                <p>You are logged in as <span class="authenticated">${username || 'User'}</span></p>
                <div class="user-id-display">User ID: <span class="user-id-value">${webAuthnCore.currentUserId}</span></div>
                <button id="logout-button" class="action-button">Logout</button>
            `;
            
            // Hide register/login buttons, show logout button
            if (this.elements.registerButton) this.elements.registerButton.style.display = 'none';
            if (this.elements.loginButton) this.elements.loginButton.style.display = 'none';
            
            // Add event listener to new logout button
            const newLogoutButton = document.getElementById('logout-button');
            if (newLogoutButton) {
                newLogoutButton.addEventListener('click', webAuthnLogin.logout.bind(webAuthnLogin));
            }
            
            // Show chat UI if it exists
            const chatForm = document.getElementById('chat-form');
            const messageList = document.getElementById('message-list');
            if (chatForm) chatForm.style.display = 'flex';
            if (messageList) messageList.style.display = 'block';
        } else {
            // User is not authenticated
            this.elements.authStatus.innerHTML = `
                <p>You are not authenticated.</p>
                <div>
                    <button id="register-button" class="action-button">Register Security Key</button>
                    <button id="login-button" class="action-button">Login</button>
                </div>
            `;
            
            // Add event listeners to new buttons
            const newRegisterButton = document.getElementById('register-button');
            const newLoginButton = document.getElementById('login-button');
            
            if (newRegisterButton) {
                newRegisterButton.addEventListener('click', webAuthnRegister.startRegistration.bind(webAuthnRegister));
            }
            
            if (newLoginButton) {
                newLoginButton.addEventListener('click', webAuthnLogin.startLogin.bind(webAuthnLogin));
            }
            
            // Hide chat UI if it exists
            const chatForm = document.getElementById('chat-form');
            const messageList = document.getElementById('message-list');
            if (chatForm) chatForm.style.display = 'none';
            if (messageList) messageList.style.display = 'none';
        }
    },
    
    // Show a message to the user
    showMessage: function(message) {
        if (!this.elements.messageContainer) {
            // Create message container if it doesn't exist
            this.elements.messageContainer = document.createElement('div');
            this.elements.messageContainer.id = 'message-container';
            this.elements.messageContainer.style.position = 'fixed';
            this.elements.messageContainer.style.top = '20px';
            this.elements.messageContainer.style.left = '50%';
            this.elements.messageContainer.style.transform = 'translateX(-50%)';
            this.elements.messageContainer.style.padding = '10px 20px';
            this.elements.messageContainer.style.backgroundColor = '#4CAF50';
            this.elements.messageContainer.style.color = 'white';
            this.elements.messageContainer.style.borderRadius = '4px';
            this.elements.messageContainer.style.zIndex = '1000';
            this.elements.messageContainer.style.display = 'none';
            document.body.appendChild(this.elements.messageContainer);
        }
        
        // Clear previous timeout
        if (this.messageTimeout) {
            clearTimeout(this.messageTimeout);
        }
        
        // Set message and show container
        this.elements.messageContainer.textContent = message;
        this.elements.messageContainer.style.backgroundColor = '#4CAF50';
        this.elements.messageContainer.style.display = 'block';
        
        // Hide after 3 seconds
        this.messageTimeout = setTimeout(() => {
            this.elements.messageContainer.style.display = 'none';
        }, 3000);
    },
    
    // Show an error message to the user
    showError: function(message) {
        if (!this.elements.messageContainer) {
            // Create message container if it doesn't exist
            this.showMessage(''); // This will create the container
        }
        
        // Clear previous timeout
        if (this.messageTimeout) {
            clearTimeout(this.messageTimeout);
        }
        
        // Set message and show container with error styling
        this.elements.messageContainer.textContent = message;
        this.elements.messageContainer.style.backgroundColor = '#F44336';
        this.elements.messageContainer.style.display = 'block';
        
        // Hide after 3 seconds
        this.messageTimeout = setTimeout(() => {
            this.elements.messageContainer.style.display = 'none';
        }, 3000);
    }
};

// Initialize the UI module when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    if (webAuthnCore.isSupported()) {
        webAuthnUI.init();
    } else {
        // Show error if WebAuthn is not supported
        const authStatus = document.getElementById('auth-status');
        if (authStatus) {
            authStatus.innerHTML = `
                <p class="error">WebAuthn is not supported in this browser.</p>
                <p>Please use a modern browser that supports WebAuthn.</p>
            `;
        }
    }
}); 