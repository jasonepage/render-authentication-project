/**
 * WebAuthn Core Module v1.0.0
 * Core functionality for WebAuthn authentication
 */
const webAuthnCore = {
    version: '1.0.0',
    
    // Configuration
    config: {
        debugMode: true,
        server: window.location.origin,
        endpoints: {
            registerOptions: 'register_options',
            registerComplete: 'register_complete',
            loginOptions: 'login_options',
            loginComplete: 'login_complete',
            logout: 'logout',
            authStatus: 'auth_status'
        }
    },
    
    // Store current user ID when authenticated
    currentUserId: null,
    currentUsername: null,
    
    // Remember if a key was already registered
    lastKeyRegistration: {
        wasExistingKey: false,
        userId: null
    },
    
    // Simplified endpoint path function
    getEndpointPath: function(endpoint) {
        const path = this.config.endpoints[endpoint] || endpoint;
        // Ensure path starts with a slash
        return path.startsWith('/') ? path : `/${path}`;
    },
    
    // Enhanced logging with timestamps
    log: function(message, obj) {
        const timestamp = new Date().toISOString().substr(11, 8); // HH:MM:SS
        if (this.config.debugMode) {
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
    
    // Helper functions for base64 encoding/decoding
    base64: {
        encode: function(buffer) {
            return btoa(String.fromCharCode.apply(null, new Uint8Array(buffer)))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=+$/, '');
        },
        
        decode: function(base64url) {
            const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
            const binStr = atob(base64);
            const bin = new Uint8Array(binStr.length);
            for (let i = 0; i < binStr.length; i++) {
                bin[i] = binStr.charCodeAt(i);
            }
            return bin.buffer;
        }
    },
    
    // Check if WebAuthn is supported in this browser
    isSupported: function() {
        return window.PublicKeyCredential !== undefined;
    },
    
    // Initialize the module
    init: function() {
        if (!this.isSupported()) {
            this.logError('WebAuthn is not supported in this browser');
            return false;
        }
        
        this.log('WebAuthn Core initialized');
        return true;
    }
};

// Initialize the core module
document.addEventListener('DOMContentLoaded', function() {
    webAuthnCore.init();
}); 