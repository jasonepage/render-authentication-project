/**
 * WebAuthn Main Module v1.0.0
 * Loads all WebAuthn modules and initializes the system
 */
document.addEventListener('DOMContentLoaded', function() {
    console.log('WebAuthn Main Module loaded');
    
    // Check if WebAuthn is supported
    if (window.PublicKeyCredential === undefined) {
        console.error('WebAuthn is not supported in this browser');
        
        // Show error message
        const authStatus = document.getElementById('auth-status');
        if (authStatus) {
            authStatus.innerHTML = `
                <p class="error">WebAuthn is not supported in this browser.</p>
                <p>Please use a modern browser that supports WebAuthn.</p>
            `;
        }
        
        return;
    }
    
    // Initialize modules
    if (typeof webAuthnCore !== 'undefined') {
        console.log('Initializing WebAuthn Core');
        webAuthnCore.init();
    } else {
        console.error('WebAuthn Core module not loaded');
    }
    
    if (typeof webAuthnUI !== 'undefined') {
        console.log('Initializing WebAuthn UI');
        webAuthnUI.init();
    } else {
        console.error('WebAuthn UI module not loaded');
    }
}); 