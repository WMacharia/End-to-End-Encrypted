const socket = io();
let myUsername = '';

// === LOCAL STORAGE HELPERS ===
function getCachedMessage(id) {
    const cache = JSON.parse(localStorage.getItem('chat_history_cache') || '{}');
    return cache[id];
}

function cacheMessage(id, text) {
    const cache = JSON.parse(localStorage.getItem('chat_history_cache') || '{}');
    cache[id] = text;
    localStorage.setItem('chat_history_cache', JSON.stringify(cache));
}

// === APP LOGIC ===

window.addEventListener('load', () => {
    const savedUser = localStorage.getItem('secure_chat_username');
    if (savedUser) {
        document.getElementById('username').value = savedUser;
        login();
    }
});

function login() {
    const username = document.getElementById('username').value;
    if (!username) return alert("Enter username");
    localStorage.setItem('secure_chat_username', username);
    socket.emit('login', username);
}

function logout() {
    localStorage.removeItem('secure_chat_username');
    localStorage.removeItem('chat_history_cache'); 
    location.reload();
}

function sendMessage() {
    const to = document.getElementById('recipient').value;
    const text = document.getElementById('msg-input').value;
    if (!to || !text) return alert("Fill all fields");
    
    socket.emit('send_msg', { to, text });
    
    // We don't have an ID yet, so we wait for the server 'msg_sent' confirmation 
    // or 'new_msg' to cache it properly. 
    // But for UI responsiveness, we add it momentarily.
    document.getElementById('msg-input').value = '';
}

function addMessageToUI(msg, type, id = null) {
    const container = document.getElementById('messages');
    
    // Prevent duplicates
    if (id && document.querySelector(`div[data-id="${id}"]`)) return;

    const div = document.createElement('div');
    div.className = `message ${type}`;
    
    // 1. Check Local Cache first!
    const cachedText = id ? getCachedMessage(id) : null;

    if (cachedText) {
        // We have it locally! Show decrypted.
        div.innerText = `${msg.sender}: ${cachedText}`;
        div.classList.add('decrypted');
    } 
    else if (type === 'received') {
        div.innerText = `${msg.sender}: 🔒 Decrypting...`;
        div.style.color = "#666";
        div.style.fontStyle = "italic";
        if (id) {
            div.dataset.id = id;
            // Trigger decryption
            socket.emit('request_decrypt', id);
        }
    } 
    else if (type === 'sent') {
        // It's a sent message. If we don't have cache (e.g. cleared browser),
        // we can't recover it because we don't decrypt our own sent messages usually.
        // But wait, we have the text from the input?
        // For now, show generic text if lost.
        div.innerText = `${msg.sender}: ${msg.text}`; 
        if(id) {
            div.dataset.id = id;
            // If this was loaded from history and we are the sender, cache what the server sent
            // (The server sends "Message Sent (Encrypted)" placeholder)
            // This implies Sent messages are lost on refresh if not in DB.
            // To fix: We must cache it the moment we send it.
        }
    }
    
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

socket.on('login_success', (username) => {
    myUsername = username;
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('chat-screen').style.display = 'block';
    document.getElementById('my-name').innerText = username;
    
    if (!document.getElementById('logout-btn')) {
        const btn = document.createElement('button');
        btn.id = 'logout-btn';
        btn.innerText = 'Logout';
        btn.onclick = logout;
        btn.style.marginLeft = '10px';
        btn.style.background = '#dc3545';
        document.getElementById('header').appendChild(btn);
    }
});

// Handle NEW incoming message (Live)
socket.on('new_msg', (msg) => {
    // If I am the sender (confirmation from server), cache my text!
    if (msg.sender === myUsername) {
        // We need to know what text we sent.
        // The server 'new_msg' for sender doesn't have text.
        // See update in 'msg_sent' below.
    } else {
        addMessageToUI(msg, 'received', msg.id);
    }
});

// Handle my own sent message confirmation
// We need to capture the ID here to save to cache
socket.on('msg_sent_confirm', ({ id, text }) => {
    cacheMessage(id, text);
    addMessageToUI({ sender: 'Me', text: text }, 'sent', id);
});

socket.on('history', (msgs) => {
    const container = document.getElementById('messages');
    container.innerHTML = '';
    msgs.forEach(m => {
        const type = m.sender === myUsername ? 'sent' : 'received';
        addMessageToUI(m, type, m.id);
    });
});

socket.on('decrypted_msg', ({ id, text }) => {
    // 1. Cache it immediately!
    cacheMessage(id, text);

    // 2. Update UI
    const el = document.querySelector(`div[data-id="${id}"]`);
    if (el) {
        const sender = el.innerText.split(':')[0];
        el.innerText = `${sender}: ${text}`;
        el.classList.add('decrypted');
        el.style.color = "black";
        el.style.fontStyle = "normal";
    }
});

socket.on('error', (err) => {
    // If decryption fails, update UI to show error state instead of stuck on "Decrypting..."
    console.error(err);
    const msgs = document.querySelectorAll('.message');
    msgs.forEach(div => {
        if(div.innerText.includes("Decrypting")) {
            div.innerText += " (Failed - Keys Lost)";
            div.style.color = "red";
        }
    });
});