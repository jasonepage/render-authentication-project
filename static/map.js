/**
 * Map.js - Live Location Sharing for Protest Chat
 * Handles real-time location updates and map display for authenticated users
 */

// Configuration
const SERVER_URL = window.location.origin;
const UPDATE_INTERVAL = 15000; // Update location every 15 seconds
const REFRESH_INTERVAL = 10000; // Refresh other users' locations every 10 seconds

// State
let map = null;
let userMarker = null;
let otherMarkers = {};
let isSharing = false;
let updateIntervalId = null;
let refreshIntervalId = null;
let userLocation = null;
let currentUserId = null;

// Custom icons for markers
const userIcon = L.icon({
    iconUrl: 'data:image/svg+xml;base64,' + btoa(`
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#1da1f2" width="32" height="32">
            <circle cx="12" cy="12" r="10" fill="#1da1f2" stroke="white" stroke-width="2"/>
            <circle cx="12" cy="12" r="4" fill="white"/>
        </svg>
    `),
    iconSize: [32, 32],
    iconAnchor: [16, 16],
    popupAnchor: [0, -16]
});

const otherIcon = L.icon({
    iconUrl: 'data:image/svg+xml;base64,' + btoa(`
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#10b981" width="28" height="28">
            <circle cx="12" cy="12" r="9" fill="#10b981" stroke="white" stroke-width="2"/>
            <circle cx="12" cy="12" r="3" fill="white"/>
        </svg>
    `),
    iconSize: [28, 28],
    iconAnchor: [14, 14],
    popupAnchor: [0, -14]
});

/**
 * Initialize the map
 */
function initMap() {
    console.log('Initializing map...');
    
    // Create map centered on US (will recenter on user location when available)
    map = L.map('map').setView([39.8283, -98.5795], 4);
    
    // Add tile layer (OpenStreetMap)
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        maxZoom: 19
    }).addTo(map);
    
    console.log('Map initialized');
}

/**
 * Get user's current location from browser
 */
function getUserLocation() {
    return new Promise((resolve, reject) => {
        if (!navigator.geolocation) {
            reject(new Error('Geolocation not supported'));
            return;
        }
        
        navigator.geolocation.getCurrentPosition(
            (position) => {
                resolve({
                    latitude: position.coords.latitude,
                    longitude: position.coords.longitude
                });
            },
            (error) => {
                reject(error);
            },
            {
                enableHighAccuracy: true,
                timeout: 10000,
                maximumAge: 0
            }
        );
    });
}

/**
 * Update user's location on the server
 */
async function updateLocation(latitude, longitude) {
    try {
        const response = await fetch(`${SERVER_URL}/update_location`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ latitude, longitude })
        });
        
        if (!response.ok) {
            throw new Error('Failed to update location');
        }
        
        console.log('Location updated successfully');
        return true;
    } catch (error) {
        console.error('Error updating location:', error);
        return false;
    }
}

/**
 * Remove user's location from the server
 */
async function removeLocation() {
    try {
        const response = await fetch(`${SERVER_URL}/remove_location`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to remove location');
        }
        
        console.log('Location removed successfully');
        return true;
    } catch (error) {
        console.error('Error removing location:', error);
        return false;
    }
}

/**
 * Fetch all active locations from the server
 */
async function fetchLocations() {
    try {
        const response = await fetch(`${SERVER_URL}/get_locations`);
        
        if (!response.ok) {
            throw new Error('Failed to fetch locations');
        }
        
        const data = await response.json();
        return data.locations || [];
    } catch (error) {
        console.error('Error fetching locations:', error);
        return [];
    }
}

/**
 * Update map markers with current locations
 */
async function updateMapMarkers() {
    const locations = await fetchLocations();
    
    // Update active count
    document.getElementById('active-count').textContent = locations.length;
    
    // Track which user IDs we've seen
    const seenUserIds = new Set();
    
    // Update or create markers for each location
    locations.forEach(location => {
        seenUserIds.add(location.userId);
        
        // Skip if this is the current user (they have their own marker)
        if (location.userId === currentUserId) {
            return;
        }
        
        const lat = location.latitude;
        const lon = location.longitude;
        
        // Update or create marker
        if (otherMarkers[location.userId]) {
            // Update existing marker
            otherMarkers[location.userId].setLatLng([lat, lon]);
        } else {
            // Create new marker
            const marker = L.marker([lat, lon], { icon: otherIcon }).addTo(map);
            
            // Create popup content
            const popupContent = `
                <div class="marker-popup">
                    <div class="marker-username">${location.username}</div>
                    <div class="marker-time">Last updated: ${new Date(location.updatedAt).toLocaleTimeString()}</div>
                </div>
            `;
            
            marker.bindPopup(popupContent);
            otherMarkers[location.userId] = marker;
        }
    });
    
    // Remove markers for users who are no longer sharing
    Object.keys(otherMarkers).forEach(userId => {
        if (!seenUserIds.has(userId)) {
            map.removeLayer(otherMarkers[userId]);
            delete otherMarkers[userId];
        }
    });
}

/**
 * Start sharing location
 */
async function startSharing() {
    console.log('Starting location sharing...');
    
    try {
        // Get initial location
        userLocation = await getUserLocation();
        console.log('Got user location:', userLocation);
        
        // Update location on server
        const success = await updateLocation(userLocation.latitude, userLocation.longitude);
        
        if (!success) {
            throw new Error('Failed to start sharing');
        }
        
        // Create or update user marker
        if (userMarker) {
            userMarker.setLatLng([userLocation.latitude, userLocation.longitude]);
        } else {
            userMarker = L.marker([userLocation.latitude, userLocation.longitude], { icon: userIcon }).addTo(map);
            userMarker.bindPopup('<div class="marker-popup"><strong>You are here</strong></div>');
        }
        
        // Center map on user
        map.setView([userLocation.latitude, userLocation.longitude], 13);
        
        // Start periodic updates
        isSharing = true;
        updateIntervalId = setInterval(async () => {
            try {
                const loc = await getUserLocation();
                userLocation = loc;
                await updateLocation(loc.latitude, loc.longitude);
                
                // Update user marker
                if (userMarker) {
                    userMarker.setLatLng([loc.latitude, loc.longitude]);
                }
            } catch (error) {
                console.error('Error during periodic location update:', error);
            }
        }, UPDATE_INTERVAL);
        
        // Start refreshing other users' locations
        if (!refreshIntervalId) {
            refreshIntervalId = setInterval(updateMapMarkers, REFRESH_INTERVAL);
        }
        
        // Update UI
        updateSharingStatus(true);
        
        console.log('Location sharing started');
    } catch (error) {
        console.error('Error starting location sharing:', error);
        alert('Unable to access your location. Please enable location permissions.');
        isSharing = false;
    }
}

/**
 * Stop sharing location
 */
async function stopSharing() {
    console.log('Stopping location sharing...');
    
    // Stop periodic updates
    if (updateIntervalId) {
        clearInterval(updateIntervalId);
        updateIntervalId = null;
    }
    
    // Remove location from server
    await removeLocation();
    
    // Remove user marker
    if (userMarker) {
        map.removeLayer(userMarker);
        userMarker = null;
    }
    
    isSharing = false;
    userLocation = null;
    
    // Update UI
    updateSharingStatus(false);
    
    console.log('Location sharing stopped');
}

/**
 * Center map on user's location
 */
function centerOnUser() {
    if (userLocation) {
        map.setView([userLocation.latitude, userLocation.longitude], 15);
    } else {
        alert('Location not available. Start sharing to enable this feature.');
    }
}

/**
 * Update sharing status UI
 */
function updateSharingStatus(sharing) {
    const statusElement = document.getElementById('sharing-status');
    const startButton = document.getElementById('start-sharing');
    const stopButton = document.getElementById('stop-sharing');
    const indicator = statusElement.querySelector('.status-indicator');
    
    if (sharing) {
        statusElement.innerHTML = `
            <span class="status-indicator online"></span>
            Location sharing: <strong style="color: #10b981;">Online</strong>
        `;
        startButton.style.display = 'none';
        stopButton.style.display = 'block';
    } else {
        statusElement.innerHTML = `
            <span class="status-indicator offline"></span>
            Location sharing: <strong>Offline</strong>
        `;
        startButton.style.display = 'block';
        stopButton.style.display = 'none';
    }
}

/**
 * Initialize map page
 */
async function initMapPage() {
    console.log('Initializing map page...');
    
    // Check authentication status
    try {
        const response = await fetch(`${SERVER_URL}/auth_status`);
        const data = await response.json();
        
        if (!data.authenticated) {
            // Redirect to chat page if not authenticated
            window.location.href = '/chat';
            return;
        }
        
        currentUserId = data.userId;
        
        // Update auth status display
        const authStatus = document.getElementById('auth-status');
        authStatus.innerHTML = `
            <p>✅ Authenticated as <strong>${data.username || 'User-' + data.userId.substring(0, 6)}</strong></p>
        `;
        
        // Show map controls
        document.getElementById('map-controls').style.display = 'flex';
        
        // Initialize map
        initMap();
        
        // Start refreshing locations
        updateMapMarkers();
        refreshIntervalId = setInterval(updateMapMarkers, REFRESH_INTERVAL);
        
    } catch (error) {
        console.error('Error checking authentication:', error);
        window.location.href = '/chat';
    }
}

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Initialize map page
    initMapPage();
    
    // Button listeners
    document.getElementById('start-sharing').addEventListener('click', startSharing);
    document.getElementById('stop-sharing').addEventListener('click', stopSharing);
    document.getElementById('center-map').addEventListener('click', centerOnUser);
    
    // Stop sharing when page is closed/refreshed
    window.addEventListener('beforeunload', () => {
        if (isSharing) {
            // Send synchronous request to remove location
            navigator.sendBeacon(`${SERVER_URL}/remove_location`, JSON.stringify({}));
        }
    });
});

// Cleanup on page unload
window.addEventListener('unload', () => {
    if (updateIntervalId) {
        clearInterval(updateIntervalId);
    }
    if (refreshIntervalId) {
        clearInterval(refreshIntervalId);
    }
});
