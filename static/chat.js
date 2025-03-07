// Chat functionality
const chat = {
    // Server URL (same as in webauthn.js)
    SERVER_URL: 'https://yusystem.onrender.com',
    
    // Message polling interval in ms
    POLLING_INTERVAL: 3000,
    
    // References to DOM elements
    elements: {
        messagesContainer: null,
        messageInput: null,
        sendButton: null
    },
    
    // Message polling timer
    pollingTimer: null,
    
    // Last message timestamp for polling
    lastMessageTime: 0,
    
    // Load messages from the server
    loadMessages() {
        fetch(`${this.SERVER_URL}/get_messages`, {
            credentials: 'include'
        })
        .then(response => response.json())
        .then(data => {
            if (data.messages && Array.isArray(data.messages)) {
                this.displayMessages(data.messages);
                
                // Update last message time if there are messages
                if (data.messages.length > 0) {
                    // Assuming messages are sorted by time with newest last
                    const newestMessage = data.messages[data.messages.length - 1];
                    if (newestMessage.timestamp) {
                        this.lastMessageTime = new Date(newestMessage.timestamp).getTime();
                    }
                }
            }
        })
        .catch(error => {
            console.error('Error loading messages:', error);
            this.showSystemMessage('Failed to load messages. Please try again later.');
        });
    },
    
    // Display messages in the chat container
    displayMessages(messages) {
        // Clear loading message
        this.elements.messagesContainer.innerHTML = '';
        
        if (messages.length === 0) {
            this.showSystemMessage('No messages yet. Be the first to send a message!');
            return;
        }
        
        // Add each message to the container
        messages.forEach(message => {
            const messageElement = document.createElement('div');
            messageElement.classList.add('message');
            
            // Check if message is from current user
            const isCurrentUser = webAuthn.isAuthenticated && message.user === webAuthn.userId;
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
        const message = this.elements.messageInput.value.trim();
        
        if (message === '') {
            return;
        }
        
        // Disable input while sending
        this.elements.messageInput.disabled = true;
        this.elements.sendButton.disabled = true;
        
        fetch(`${this.SERVER_URL}/send_message`, {
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
            console.error('Error sending message:', error);
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
    
    // Initialize chat functionality
    init() {
        // Get references to DOM elements
        this.elements.messagesContainer = document.getElementById('messages');
        this.elements.messageInput = document.getElementById('message-input');
        this.elements.sendButton = document.getElementById('send-button');
        
        // Set up event listeners
        this.elements.sendButton.addEventListener('click', () => this.sendMessage());
        this.elements.messageInput.addEventListener('keydown', event => {
            if (event.key === 'Enter') {
                event.preventDefault();
                this.sendMessage();
            }
        });
        
        // Listen for authentication events
        document.addEventListener('userAuthenticated', () => {
            this.loadMessages();
            this.startPolling();
            this.elements.messageInput.disabled = false;
            this.elements.sendButton.disabled = false;
        });
        
        document.addEventListener('userLoggedOut', () => {
            this.stopPolling();
            this.elements.messageInput.disabled = true;
            this.elements.sendButton.disabled = true;
        });
        
        // Load initial messages (viewable by all)
        this.loadMessages();
        
        // Start polling if authenticated
        if (webAuthn.isAuthenticated) {
            this.startPolling();
        }
    }
};

// Initialize chat when the page loads
document.addEventListener('DOMContentLoaded', () => {
    chat.init();
}); 