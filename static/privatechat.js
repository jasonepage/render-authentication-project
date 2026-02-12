/**
 * ============================================================================
 * PRIVATE CHAT HANDLER - Protest Chat
 * ============================================================================
 * @file privatechat.js
 * @author Chris Becker, Jake McDowell, Jason Page
 * @date February 12, 2026
 * @description Private chat functionality for Protest Chat
 *              
 * VISIBILITY: Only authenticated users with physical security keys
 * POSTING: Only authenticated users with security keys can send messages
 * SECURITY: Maximum security for sensitive protest coordination
 * 
 * DEPLOYMENT CONFIGURATION:
 * 1. Update SERVER_URL below to match your deployment domain
 * 2. Adjust POLLING_INTERVAL if you want different refresh rates
 * 
 * FEATURES:
 * - Authenticated-only access (auto-hides when not logged in)
 * - Real-time message updates via polling
 * - Auto-scroll to latest messages
 * - Secure endpoint (requires valid session)
 * - Rate limiting and error handling
 * 
 * INTEGRATION:
 * - Requires webauthn.js for authentication state
 * - Listens for 'userAuthenticated' and 'userLoggedOut' events
 * - Auto-initializes when DOM loads
 * - Shows/hides based on authentication status
 * ============================================================================
 */

// Private Chat functionality
const privateChat = {
    // ========================================================================
    // CONFIGURATION - Update for your deployment
    // ========================================================================
    
    // Server URL - CHANGE THIS to your deployment domain
    SERVER_URL: 'https://render-authentication-project.onrender.com',  // TODO: Update this!
    
    // Message polling interval in milliseconds (3000 = 3 seconds)
    POLLING_INTERVAL: 3000,
    
    // References to DOM elements
    elements: {
        messagesContainer: null,
        messageInput: null,
        sendButton: null,
        chatContainer: null
    },
    
    // Message polling timer
    pollingTimer: null,
    
    // Last message timestamp for polling
    lastMessageTime: 0,
    
    // Load messages from the server
    loadMessages() {
        // Only load if authenticated
        if (!webAuthn || !webAuthn.currentUserId) {
            return;
        }
        
        fetch(`${this.SERVER_URL}/get_private_messages`, {
            credentials: 'include'
        })
        .then(response => response.json())
        .then(data => {
            if (data.messages && Array.isArray(data.messages)) {
                this.displayMessages(data.messages);
                
                // Update last message time if there are messages
                if (data.messages.length > 0) {
                    const newestMessage = data.messages[data.messages.length - 1];
                    if (newestMessage.timestamp) {
                        this.lastMessageTime = new Date(newestMessage.timestamp).getTime();
                    }
                }
            }
        })
        .catch(error => {
            console.error('Error loading private messages:', error);
            this.showSystemMessage('Failed to load private messages. Please try again later.');
        });
    },
    
    // Display messages in the chat container
    displayMessages(messages) {
        // Clear loading message
        this.elements.messagesContainer.innerHTML = '';
        
        if (messages.length === 0) {
            this.showSystemMessage('No private messages yet. Start the conversation!');
            return;
        }
        
        // Add each message to the container
        messages.forEach(message => {
            const messageElement = document.createElement('div');
            messageElement.classList.add('message');
            
            // Check if message is from current user
            const isCurrentUser = webAuthn.currentUserId && message.user === webAuthn.currentUserId;
            messageElement.classList.add(isCurrentUser ? 'message-user' : 'message-other');
            
            // Create message content
            const metaElement = document.createElement('div');
            metaElement.classList.add('message-meta');
            
            // Format the timestamp
            let timestamp;
            try {
                timestamp = new Date(message.time).toLocaleString();
            } catch (e) {
                timestamp = message.time; // Fallback to raw timestamp
            }
            
            metaElement.textContent = `${message.user} • ${timestamp}`;
            
            const textElement = document.createElement('div');
            textElement.textContent = message.message;
            
            messageElement.appendChild(metaElement);
            messageElement.appendChild(textElement);
            
            this.elements.messagesContainer.appendChild(messageElement);
        });
        
        // Scroll to the bottom
        this.scrollToBottom();
    },
    
    // Show a system message in the chat
    showSystemMessage(message) {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message', 'message-system');
        messageElement.textContent = message;
        this.elements.messagesContainer.appendChild(messageElement);
        this.scrollToBottom();
    },
    
    // Scroll the chat container to the bottom
    scrollToBottom() {
        this.elements.messagesContainer.scrollTop = this.elements.messagesContainer.scrollHeight;
    },
    
    // Send a message to the server
    sendMessage() {
        // Ensure user is authenticated
        if (!webAuthn || !webAuthn.currentUserId) {
            this.showSystemMessage('You must be logged in to send private messages.');
            return;
        }
        
        const message = this.elements.messageInput.value.trim();
        
        if (message === '') {
            return;
        }
        
        // Disable input while sending
        this.elements.messageInput.disabled = true;
        this.elements.sendButton.disabled = true;
        
        fetch(`${this.SERVER_URL}/send_private_message`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ message }),
            credentials: 'include'
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`Server returned ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            // Clear input field
            this.elements.messageInput.value = '';
            
            // Reload messages
            this.loadMessages();
        })
        .catch(error => {
            console.error('Error sending private message:', error);
            this.showSystemMessage('Failed to send message. Please try again.');
        })
        .finally(() => {
            // Re-enable input
            this.elements.messageInput.disabled = false;
            this.elements.sendButton.disabled = false;
            this.elements.messageInput.focus();
        });
    },
    
    // Start polling for new messages
    startPolling() {
        this.stopPolling(); // Clear any existing timer
        
        // Set up polling interval
        this.pollingTimer = setInterval(() => {
            this.loadMessages();
        }, this.POLLING_INTERVAL);
    },
    
    // Stop polling for messages
    stopPolling() {
        if (this.pollingTimer) {
            clearInterval(this.pollingTimer);
            this.pollingTimer = null;
        }
    },
    
    // Show the private chat (called when user logs in)
    show() {
        if (this.elements.chatContainer) {
            this.elements.chatContainer.style.display = 'block';
        }
    },
    
    // Hide the private chat (called when user logs out)
    hide() {
        if (this.elements.chatContainer) {
            this.elements.chatContainer.style.display = 'none';
        }
        this.stopPolling();
        
        // Clear messages
        if (this.elements.messagesContainer) {
            this.elements.messagesContainer.innerHTML = '';
        }
    },
    
    // Initialize chat functionality
    init() {
        // Get references to DOM elements
        this.elements.chatContainer = document.getElementById('private-chat-container');
        this.elements.messagesContainer = document.getElementById('private-messages');
        this.elements.messageInput = document.getElementById('private-message-input');
        this.elements.sendButton = document.getElementById('private-send-button');
        
        // Check if elements exist
        if (!this.elements.messagesContainer) {
            console.warn('Private chat container not found. Private chat will not be initialized.');
            return;
        }
        
        // Set up event listeners
        if (this.elements.sendButton) {
            this.elements.sendButton.addEventListener('click', () => this.sendMessage());
        }
        
        if (this.elements.messageInput) {
            this.elements.messageInput.addEventListener('keydown', event => {
                if (event.key === 'Enter') {
                    event.preventDefault();
                    this.sendMessage();
                }
            });
        }
        
        // Listen for authentication events
        document.addEventListener('userAuthenticated', () => {
            this.show();
            this.loadMessages();
            this.startPolling();
            
            if (this.elements.messageInput && this.elements.sendButton) {
                this.elements.messageInput.disabled = false;
                this.elements.sendButton.disabled = false;
            }
        });
        
        document.addEventListener('userLoggedOut', () => {
            this.hide();
        });
        
        // Only show and start if already authenticated
        if (webAuthn && webAuthn.currentUserId) {
            this.show();
            this.loadMessages();
            this.startPolling();
        } else {
            this.hide();
        }
    }
};

// Initialize private chat when the page loads
document.addEventListener('DOMContentLoaded', () => {
    privateChat.init();
});
