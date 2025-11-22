const socket = io();
let myUsername = '';

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
    location.reload();
}

function sendMessage() {
    const to = document.getElementById('recipient').value;
    const text = document.getElementById('msg-input').value;
    if (!to || !text) return alert("Fill all fields");
    
    socket.emit('send_msg', { to, text });
    // Add to UI immediately
    addMessageToUI({ sender: 'Me', text: text, isDecrypted: true }, 'sent');
    document.getElementById('msg-input').value = '';
}

function addMessageToUI(msg, type, id = null) {
    const container = document.getElementById('messages');
    
    // Check if message already exists to prevent duplicates
    if (id && document.querySelector(`div[data-id="${id}"]`)) return;

    const div = document.createElement('div');
    div.className = `message ${type}`;
    div.innerText = `${msg.sender}: ${msg.text}`;
    if (id) div.dataset.id = id;
    
    // LOGIC: If we receive an encrypted message, don't show "Click to decrypt".
    // Instead, show a loading state and trigger decryption immediately.
    if (type === 'received') {
        if (!msg.isDecrypted) {
            div.innerText = `${msg.sender}: 🔒 Decrypting...`;
            div.style.color = "#666";
            div.style.fontStyle = "italic";
            // TRIGGER AUTO DECRYPT
            socket.emit('request_decrypt', id);
        } else {
            div.classList.add('decrypted');
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

// Handle incoming live message
socket.on('new_msg', (msg) => {
    addMessageToUI(msg, 'received', msg.id);
});

// Handle history load
socket.on('history', (msgs) => {
    const container = document.getElementById('messages');
    container.innerHTML = '';
    msgs.forEach(m => {
        const type = m.sender === myUsername ? 'sent' : 'received';
        // If plaintext exists in DB, use it. Otherwise use placeholder.
        const text = m.text; 
        addMessageToUI(m, type, m.id);
    });
});

// Handle the result of the auto-decryption
socket.on('decrypted_msg', ({ id, text }) => {
    const el = document.querySelector(`div[data-id="${id}"]`);
    if (el) {
        // Update the text from "🔒 Decrypting..." to the actual message
        const sender = el.innerText.split(':')[0];
        el.innerText = `${sender}: ${text}`;
        
        el.classList.add('decrypted');
        el.style.color = "black";
        el.style.fontStyle = "normal";
    }
});

socket.on('error', (err) => console.error(err));