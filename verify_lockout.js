const http = require('http');

function request(method, path, body) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/api/auth' + path,
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, body: JSON.parse(data), headers: res.headers });
                } catch (e) {
                    resolve({ status: res.statusCode, body: data, headers: res.headers });
                }
            });
        });

        req.on('error', (e) => reject(e));
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

async function start() {
    const email = `test_${Date.now()}@example.com`;
    const password = 'Password123!';

    console.log(`--- Registering ${email} ---`);
    const regRes = await request('POST', '/register', { email, password, name: 'Test User' });
    console.log('Register:', regRes.status, regRes.body.message);

    if (regRes.status !== 201) return;

    console.log('\n--- Attempting Login (Wrong Password x3) ---');
    for (let i = 1; i <= 4; i++) {
        const res = await request('POST', '/login', { email, password: 'WrongPassword!' });
        console.log(`Attempt ${i}: Status ${res.status}`);
        if (res.status === 423) {
            console.log('>>> Account Locked! (Success)');
            console.log('Message:', res.body.message);
            console.log('Can Request Unlock:', res.body.canRequestUnlock);
            break;
        }
    }

    console.log('\n--- Requesting Unlock ---');
    const unlockRes = await request('POST', '/unlock-request', { email, reason: 'I forgot my password' });
    console.log('Unlock Request:', unlockRes.status, unlockRes.body.message);

    console.log('\n--- Verifying Admin Logic (reading file manually as we are not admin) ---');
    const path = require('path');
    const fs = require('fs');
    const dbPath = path.join(__dirname, 'data', 'users.json');
    if (fs.existsSync(dbPath)) {
        const users = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
        const user = users.find(u => u.email === email);
        console.log('User in DB isLocked:', user.isLocked);
        console.log('User unblockRequest status:', user.unblockRequest ? user.unblockRequest.status : 'None');
    } else {
        console.log('Could not find users.json to verify.');
    }
}

start();
