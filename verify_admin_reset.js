const http = require('http');
const fs = require('fs');
const path = require('path');

function request(method, path, body, cookie) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/api/auth' + path,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Cookie': cookie || ''
            }
        };
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try { resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(data) }); }
                catch { resolve({ status: res.statusCode, headers: res.headers, body: data }); }
            });
        });
        req.on('error', (e) => reject(e));
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

async function start() {
    const email = `admin_reset_${Date.now()}@example.com`;
    const password = 'Password123!';

    console.log(`\n--- 1. Creating User ${email} ---`);
    await request('POST', '/register', { email, password, name: 'Locked User' });

    console.log(`\n--- 2. Locking User (3 Failed Attempts) ---`);
    for (let i = 0; i < 3; i++) {
        await request('POST', '/login', { email, password: 'WrongPassword!' });
    }

    // Verify Locked
    const lockCheck = await request('POST', '/login', { email, password });
    if (lockCheck.status === 423) {
        console.log('✅ User is LOCKED (423)');
    } else {
        console.log('❌ User NOT Locked:', lockCheck.status);
        return;
    }

    console.log(`\n--- 3. Submitting Unlock Request ---`);
    await request('POST', '/unlock-request', { email, reason: 'Please unlock me' });

    console.log(`\n--- 4. Admin Approves Request ---`);
    // Create Admin
    const adminEmail = `admin_${Date.now()}@example.com`;
    const adminReg = await request('POST', '/register', { email: adminEmail, password, name: 'Admin' });
    const adminToken = adminReg.headers['set-cookie'][0];

    // Promote to Admin (Direct DB Hack for test)
    const dbPath = path.join(__dirname, 'data', 'users.json');
    let users = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
    const adminUserIdx = users.findIndex(u => u.email === adminEmail);
    users[adminUserIdx].role = 'admin';
    fs.writeFileSync(dbPath, JSON.stringify(users, null, 2));

    // Find Target User ID
    const targetUser = users.find(u => u.email === email);

    // Handle Request (Admin API)
    // Note: admin path is /api/admin/handle-request (not auth) but my helper function prefixes /api/auth.
    // I'll fix the path in the call.

    const adminOptions = {
        hostname: 'localhost',
        port: 3000,
        path: '/api/admin/handle-request',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Cookie': adminToken
        }
    };

    await new Promise((resolve) => {
        const req = http.request(adminOptions, (res) => {
            res.on('data', () => { });
            res.on('end', resolve);
        });
        req.write(JSON.stringify({ userId: targetUser.id, action: 'approve' }));
        req.end();
    });
    console.log('✅ Admin Approved Request');

    console.log(`\n--- 5. User Logging In (Expect Redirect) ---`);
    const finalLogin = await request('POST', '/login', { email, password });

    if (finalLogin.status === 200) {
        console.log('✅ Login Successful');
        if (finalLogin.body.redirect && finalLogin.body.redirect.includes('reset-password')) {
            console.log(`✅ REDIRECT RECEIVED: ${finalLogin.body.redirect}`);
        } else {
            console.log('❌ NO REDIRECT RECEIVED:', finalLogin.body);
        }
    } else {
        console.log('❌ Login Failed:', finalLogin.status, finalLogin.body);
    }
}

start();
