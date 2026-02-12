/**
 * @file admin.js
 * @author Jason Page
 * @date February 12, 2026
 * @description Admin functionality for Protest Chat
 *              Handles registration slot creation and management
 */

const adminPanel = {
    SERVER_URL: 'https://render-authentication-project.onrender.com',
    
    elements: {
        panel: null,
        createButton: null,
        slotList: null
    },
    
    // Initialize admin panel
    init() {
        this.elements.panel = document.getElementById('admin-panel');
        this.elements.createButton = document.getElementById('create-slot-button');
        this.elements.slotList = document.getElementById('slot-list');
        
        if (!this.elements.panel) return;
        
        // Set up create button
        if (this.elements.createButton) {
            this.elements.createButton.addEventListener('click', () => this.createRegistrationSlot());
        }
        
        // Listen for authentication events
        document.addEventListener('userAuthenticated', (event) => {
            if (event.detail && event.detail.isAdmin) {
                this.show();
                this.loadSlots();
            }
        });
        
        document.addEventListener('userLoggedOut', () => {
            this.hide();
        });
    },
    
    // Show admin panel
    show() {
        if (this.elements.panel) {
            this.elements.panel.style.display = 'block';
        }
    },
    
    // Hide admin panel
    hide() {
        if (this.elements.panel) {
            this.elements.panel.style.display = 'none';
        }
        if (this.elements.slotList) {
            this.elements.slotList.innerHTML = '';
        }
    },
    
    // Create a new registration slot
    async createRegistrationSlot() {
        try {
            this.elements.createButton.disabled = true;
            this.elements.createButton.textContent = 'Creating...';
            
            const response = await fetch(`${this.SERVER_URL}/admin/create_registration_slot`, {
                method: 'POST',
                credentials: 'include',
                headers: { 'Content-Type': 'application/json' }
            });
            
            const data = await response.json();
            
            if (response.ok && data.success) {
                this.showNotification(`✅ Code created: ${data.slotCode}`, 'success');
                this.loadSlots();
            } else {
                this.showNotification(`❌ Error: ${data.error || 'Failed to create code'}`, 'error');
            }
        } catch (error) {
            console.error('Error creating slot:', error);
            this.showNotification('❌ Failed to create registration code', 'error');
        } finally {
            this.elements.createButton.disabled = false;
            this.elements.createButton.textContent = 'Generate Registration Code';
        }
    },
    
    // Load and display registration slots
    async loadSlots() {
        try {
            const response = await fetch(`${this.SERVER_URL}/admin/list_slots`, {
                credentials: 'include'
            });
            
            const data = await response.json();
            
            if (response.ok && data.slots) {
                this.displaySlots(data.slots);
            }
        } catch (error) {
            console.error('Error loading slots:', error);
        }
    },
    
    // Display slots in the UI
    displaySlots(slots) {
        if (!this.elements.slotList) return;
        
        if (slots.length === 0) {
            this.elements.slotList.innerHTML = '<p style="color: var(--text-tertiary); text-align: center; padding: 20px;">No registration codes yet</p>';
            return;
        }
        
        this.elements.slotList.innerHTML = slots.map(slot => `
            <div class="slot-item">
                <div>
                    <span class="slot-status ${slot.isUsed ? 'used' : 'unused'}">
                        ${slot.isUsed ? '✓ USED' : '○ AVAILABLE'}
                    </span>
                </div>
                <div class="slot-code">${slot.code}</div>
                <div style="font-size: 12px; color: var(--text-tertiary); margin-top: 8px;">
                    Created: ${new Date(slot.createdAt).toLocaleString()}
                    ${slot.isUsed ? `<br>Used: ${new Date(slot.usedAt).toLocaleString()}` : ''}
                </div>
            </div>
        `).join('');
    },
    
    // Show notification message
    showNotification(message, type) {
        // Create notification element
        const notification = document.createElement('div');
        notification.textContent = message;
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 16px 24px;
            background-color: ${type === 'success' ? 'var(--accent-green)' : 'var(--accent-red)'};
            color: white;
            border-radius: 8px;
            font-weight: 700;
            z-index: 10000;
            animation: slideIn 0.3s ease-out;
        `;
        
        document.body.appendChild(notification);
        
        // Remove after 5 seconds
        setTimeout(() => {
            notification.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => notification.remove(), 300);
        }, 5000);
    }
};

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

// Initialize when page loads
document.addEventListener('DOMContentLoaded', () => {
    adminPanel.init();
});
