/**
 * FIDO2 Chat System - Chat Module
 * 
 * Handles client-side chat functionality including:
 * - Message loading and display
 * - Message sending
 * - Polling for new messages
 * - Username display
 * 
 * Author: [Your Name]
 * Date: [Current Date]
 * Version: 1.0
 */

// Chat functionality
const chat = {
    // Server URL (same as in webauthn.js)
    SERVER_URL: 'https://render-authentication-project.onrender.com',
    
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
                    if (newestMessage.time) {
                        this.lastMessageTime = new Date(newestMessage.time).getTime();
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
        const messageList = document.getElementById('message-list');
        if (!messageList) return;
        
        messageList.innerHTML = '';
        
        if (messages.length === 0) {
            const emptyMessage = document.createElement('div');
            emptyMessage.className = 'message-item system-message';
            emptyMessage.innerHTML = '<span class="message-user">System</span> <span class="message-text">No messages yet. Start chatting!</span>';
            messageList.appendChild(emptyMessage);
            return;
        }
        
        messages.forEach(message => {
            const messageElement = document.createElement('div');
            
            // Determine if this is a system message
            const isSystem = message.user === 'system';
            
            // Determine if this is the current user
            const isCurrentUser = webAuthn.isAuthenticated && message.user === webAuthn.userId;
            
            // Add appropriate CSS classes
            messageElement.className = 'message-item';
            if (isSystem) {
                messageElement.classList.add('system-message');
            } else if (isCurrentUser) {
                messageElement.classList.add('own-message');
            }
            
            // Format time if available
            const time = message.time ? formatTime(new Date(message.time)) : '';
            
            // Use username if available, otherwise use user ID
            const displayName = message.username || `User-${message.user.substring(0, 8)}`;
            
            // Display as "You" for current user
            const userDisplay = isCurrentUser ? 'You' : displayName;
            
            messageElement.innerHTML = `
                <span class="message-user">${userDisplay}</span>
                <span class="message-text">${escapeHtml(message.message)}</span>
                <span class="message-time">${time}</span>
            `;
            
            messageList.appendChild(messageElement);
        });
        
        // Scroll to the bottom of the message list
        messageList.scrollTop = messageList.scrollHeight;
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

// Helper function to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Helper function to format time
function formatTime(date) {
    if (!(date instanceof Date)) return '';
    
    try {
        const today = new Date();
        const yesterday = new Date(today);
        yesterday.setDate(yesterday.getDate() - 1);
        
        // Format for today: HH:MM
        if (date.toDateString() === today.toDateString()) {
            return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        }
        
        // Format for yesterday: Yesterday, HH:MM
        if (date.toDateString() === yesterday.toDateString()) {
            return `Yesterday, ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
        }
        
        // Format for other days: MM/DD/YYYY, HH:MM
        return date.toLocaleString([], { 
            month: 'numeric', 
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit', 
            minute: '2-digit'
        });
    } catch (e) {
        console.error('Error formatting time:', e);
        return '';
    }
}

// Initialize chat when the page loads
document.addEventListener('DOMContentLoaded', () => {
    chat.init();
}); 