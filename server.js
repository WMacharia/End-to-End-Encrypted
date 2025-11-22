const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mysql = require('mysql2/promise');
const fs = require('fs').promises;
const { MessengerClient } = require('./messenger');
const { cryptoKeyToJSON } = require('./lib');
const { subtle } = require('node:crypto').webcrypto;

const KEY_FILE = 'system_keys.json';

// === CONFIGURATION ===
const DB_CONFIG = {
    host: 'localhost',
    user: 'root',
    password: '123456',
    database: 'secure_chat'
};

// === SETUP ===
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.static('public'));
app.use(express.json());

const activeClients = {};
let caKeyPair, govKeyPair;

// === CRYPTO HELPERS ===

async function importKey(jwk, type, isPrivate = false) {
    if (!jwk) return null;
    const format = 'jwk';
    let algo;
    let usage = [];
    
    if (type === 'HMAC') {
        algo = { name: 'HMAC', hash: 'SHA-256' };
        usage = ['sign']; 
    } else if (type === 'ECDH') {
        algo = { name: 'ECDH', namedCurve: 'P-384' };
        usage = isPrivate ? ['deriveKey'] : [];
    } else if (type === 'ECDSA') {
        algo = { name: 'ECDSA', namedCurve: 'P-384' };
        usage = isPrivate ? ['sign'] : ['verify'];
    } 
    // Removed HKDF block because we strictly use HMAC for state keys now

    return await subtle.importKey(format, jwk, algo, true, usage);
}

// === SYSTEM KEY PERSISTENCE ===

async function initSystemKeys() {
    try {
        const data = await fs.readFile(KEY_FILE, 'utf8');
        const keys = JSON.parse(data);
        caKeyPair = {
            pub: await importKey(keys.ca.pub, 'ECDSA'),
            sec: await importKey(keys.ca.sec, 'ECDSA', true)
        };
        govKeyPair = {
            pub: await importKey(keys.gov.pub, 'ECDH'),
            sec: await importKey(keys.gov.sec, 'ECDH', true)
        };
        console.log("System Keys Loaded from disk.");
    } catch (e) {
        console.log("Generating new System Keys...");
        const ca = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']);
        const gov = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveKey']);
        caKeyPair = { pub: ca.publicKey, sec: ca.privateKey };
        govKeyPair = { pub: gov.publicKey, sec: gov.privateKey };

        const saveState = {
            ca: { pub: await cryptoKeyToJSON(ca.publicKey), sec: await cryptoKeyToJSON(ca.privateKey) },
            gov: { pub: await cryptoKeyToJSON(gov.publicKey), sec: await cryptoKeyToJSON(gov.privateKey) }
        };
        await fs.writeFile(KEY_FILE, JSON.stringify(saveState));
        console.log("System Keys Saved to disk.");
    }
}

// === DATABASE HELPERS ===

async function getDBConnection() {
    return await mysql.createConnection(DB_CONFIG);
}

async function serializeState(state) {
    const serialized = { ...state };
    const keyFields = ['RK', 'CKs', 'CKr', 'DHr']; 
    for (const field of keyFields) {
        if (state[field]) serialized[field] = await cryptoKeyToJSON(state[field]);
    }
    if (state.DHs) {
        serialized.DHs = {
            pub: await cryptoKeyToJSON(state.DHs.pub),
            sec: await cryptoKeyToJSON(state.DHs.sec)
        };
    }
    if (state.MKSKIPPED) {
        serialized.MKSKIPPED = {};
        for (const [idx, keyRaw] of Object.entries(state.MKSKIPPED)) {
            if(Array.isArray(keyRaw)) {
                 serialized.MKSKIPPED[idx] = keyRaw.map(k => Buffer.from(k).toString('base64'));
            } else {
                 serialized.MKSKIPPED[idx] = Buffer.from(keyRaw).toString('base64');
            }
        }
    }
    delete serialized.theirIdentityPK;
    return JSON.stringify(serialized);
}

async function deserializeState(jsonStr) {
    const state = JSON.parse(jsonStr);
    
    // FIX: Reverted RK back to 'HMAC'. This was the cause of the SyntaxError.
    if (state.RK) state.RK = await importKey(state.RK, 'HMAC'); 
    if (state.CKs) state.CKs = await importKey(state.CKs, 'HMAC');
    if (state.CKr) state.CKr = await importKey(state.CKr, 'HMAC');
    if (state.DHr) state.DHr = await importKey(state.DHr, 'ECDH');
    
    if (state.DHs) {
        state.DHs.pub = await importKey(state.DHs.pub, 'ECDH');
        state.DHs.sec = await importKey(state.DHs.sec, 'ECDH', true);
    }
    
    if (state.MKSKIPPED) {
        for (const [idx, val] of Object.entries(state.MKSKIPPED)) {
            if(Array.isArray(val)) {
                 state.MKSKIPPED[idx] = val.map(b64 => Buffer.from(b64, 'base64'));
            } else {
                 state.MKSKIPPED[idx] = Buffer.from(val, 'base64');
            }
        }
    }
    return state;
}

// === ROUTES & LOGIC ===

io.on('connection', (socket) => {
    console.log('A user connected');
    let currentUser = null;

    socket.on('login', async (username) => {
        const db = await getDBConnection();
        currentUser = username;
        
        const [rows] = await db.execute('SELECT * FROM users WHERE username = ?', [username]);
        let client = new MessengerClient(caKeyPair.pub, govKeyPair.pub);
        
        if (rows.length === 0) {
            // REGISTER
            const cert = await client.generateCertificate(username);
            const certStr = JSON.stringify(cert);
            const signature = await subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-384' } }, caKeyPair.sec, Buffer.from(certStr));
            const identitySec = await cryptoKeyToJSON(client.EGKeyPair.sec);
            
            const storageData = {
                cert,
                sig: Buffer.from(signature).toString('base64'),
                identitySec
            };

            await db.execute('INSERT INTO users (username, certificate_json) VALUES (?, ?)', 
                [username, JSON.stringify(storageData)]);
            activeClients[username] = client;
        } else {
            // LOGIN
            const storageData = JSON.parse(rows[0].certificate_json);
            client.EGKeyPair = {
                pub: await importKey(storageData.cert.publicKey, 'ECDH'),
                sec: await importKey(storageData.identitySec, 'ECDH', true)
            };
            activeClients[username] = client;
        }

        socket.join(username);
        socket.emit('login_success', username);
        
        // SEND HISTORY
        const [msgs] = await db.execute('SELECT * FROM messages WHERE receiver = ? OR sender = ? ORDER BY id ASC', [username, username]);
        
        const history = msgs.map(m => {
            let displayText;
            let isDecrypted = false;

            // If plaintext exists in DB (previously decrypted or sent by me), use it
            if (m.plaintext) {
                displayText = m.plaintext;
                isDecrypted = true;
            } else {
                displayText = m.sender === currentUser ? "Message Sent (Encrypted)" : "Encrypted Message Received";
                isDecrypted = false;
            }
            
            return {
                id: m.id,
                sender: m.sender,
                text: displayText,
                isDecrypted: isDecrypted
            };
        });

        socket.emit('history', history);
        await db.end();
    });

    socket.on('send_msg', async ({ to, text }) => {
        if (!activeClients[currentUser]) return;
        const client = activeClients[currentUser];
        const db = await getDBConnection();

        try {
            if (!client.conns[to]) {
                const [rows] = await db.execute('SELECT certificate_json FROM users WHERE username = ?', [to]);
                if (rows.length === 0) throw new Error("User not found");
                
                const data = JSON.parse(rows[0].certificate_json);
                const signature = Buffer.from(data.sig, 'base64');
                const sigArrayBuf = signature.buffer.slice(signature.byteOffset, signature.byteOffset + signature.byteLength);
                await client.receiveCertificate(data.cert, sigArrayBuf);
            }

            const [stateRows] = await db.execute('SELECT state_json FROM conversations WHERE user_from = ? AND user_to = ?', [currentUser, to]);
            if (stateRows.length > 0) {
                const savedState = await deserializeState(stateRows[0].state_json);
                client.conns[to] = savedState;
                if (client.certs[to]) client.conns[to].theirIdentityPK = client.certs[to];
            }

            const [header, ciphertext] = await client.sendMessage(to, text);
            
            const newStateJson = await serializeState(client.conns[to]);
            await db.execute(`INSERT INTO conversations (user_from, user_to, state_json) 
                VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE state_json = ?`, 
                [currentUser, to, newStateJson, newStateJson]);

            const headerJson = JSON.stringify(header);
            const ctHex = Buffer.from(ciphertext).toString('hex');
            const ivHex = Buffer.from(header.receiverIV).toString('hex');
            
            // Store plaintext for SENDER immediately
            const [result] = await db.execute('INSERT INTO messages (sender, receiver, header_json, ciphertext_hex, iv_hex, plaintext) VALUES (?, ?, ?, ?, ?, ?)',
                [currentUser, to, headerJson, ctHex, ivHex, text]);

            io.to(to).emit('new_msg', { 
                id: result.insertId, 
                sender: currentUser, 
                text: "Encrypted Message Received",
                isDecrypted: false
            });
            
            socket.emit('msg_sent', { to, text });

        } catch (e) {
            console.error(e);
            socket.emit('error', e.message);
        }
        await db.end();
    });

    socket.on('request_decrypt', async (msgId) => {
        if (!activeClients[currentUser]) return;
        const client = activeClients[currentUser];
        const db = await getDBConnection();

        try {
            const [rows] = await db.execute('SELECT * FROM messages WHERE id = ?', [msgId]);
            if (rows.length === 0) return;
            const msg = rows[0];

            if (msg.plaintext) {
                 socket.emit('decrypted_msg', { id: msgId, text: msg.plaintext });
                 return;
            }

             if(!client.conns[msg.sender]) {
                 const [uRows] = await db.execute('SELECT certificate_json FROM users WHERE username = ?', [msg.sender]);
                 if(uRows.length > 0) {
                     const d = JSON.parse(uRows[0].certificate_json);
                     const s = Buffer.from(d.sig, 'base64');
                     const sBuf = s.buffer.slice(s.byteOffset, s.byteOffset + s.byteLength);
                     await client.receiveCertificate(d.cert, sBuf);
                 }
            }
            
            const [stateRows] = await db.execute('SELECT state_json FROM conversations WHERE user_from = ? AND user_to = ?', [currentUser, msg.sender]);
            if (stateRows.length > 0) {
                const savedState = await deserializeState(stateRows[0].state_json);
                client.conns[msg.sender] = savedState;
                if (client.certs[msg.sender]) client.conns[msg.sender].theirIdentityPK = client.certs[msg.sender];
            }

            const header = JSON.parse(msg.header_json);
            header.receiverIV = new Uint8Array(Buffer.from(msg.iv_hex, 'hex'));
            const ciphertext = new Uint8Array(Buffer.from(msg.ciphertext_hex, 'hex'));

            const plaintext = await client.receiveMessage(msg.sender, [header, ciphertext]);

            await db.execute('UPDATE messages SET plaintext = ? WHERE id = ?', [plaintext, msgId]);

            const newStateJson = await serializeState(client.conns[msg.sender]);
            await db.execute(`INSERT INTO conversations (user_from, user_to, state_json) 
                VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE state_json = ?`, 
                [currentUser, msg.sender, newStateJson, newStateJson]);

            socket.emit('decrypted_msg', { id: msgId, text: plaintext });

        } catch (e) {
            console.error("Decryption Error:", e);
            socket.emit('error', "Decryption Failed: " + e.message);
        }
        await db.end();
    });
});

initSystemKeys().then(() => {
    server.listen(3000, () => {
        console.log('listening on *:3000');
    });
});