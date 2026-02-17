const http = require('http');
const fs = require('fs');
const path = require('path');

function request(method, pathStr, body, cookies) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/api' + pathStr, // Note: added /api prefix here for convenience 
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Cookie': cookies || ''
            }
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                let parsed;
                try { parsed = JSON.parse(data); } catch { parsed = data; }
                resolve({ status: res.statusCode, body: parsed, headers: res.headers });
            });
        });

        req.on('error', (e) => reject(e));
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

async function start() {
    const dbPath = path.join(__dirname, 'data', 'users.json');
    if (!fs.existsSync(dbPath)) {
        console.log('No database found.');
        return;
    }

    const users = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
    // Find the locked user from previous test
    const lockedUser = users.find(u => u.unblockRequest && u.unblockRequest.status === 'pending');

    if (!lockedUser) {
        console.log('No locked user with pending request found for testing.');
        return;
    }

    console.log(`Found locked user: ${lockedUser.email}`);

    // Create an ADMIN user
    const adminEmail = `admin_${Date.now()}@example.com`;
    console.log(`\n--- Registering Admin ${adminEmail} ---`);
    // Note: /auth/register is at /api/auth/register, function adds /api
    const regRes = await request('POST', '/auth/register', { email: adminEmail, password: 'Password123!', name: 'Admin' });
    if (regRes.status !== 201) {
        console.log('Admin registration failed:', regRes.body);
        return;
    }

    let adminCookie = regRes.headers['set-cookie'][0];
    console.log('Admin Registered. Cookie obtained.');

    // Manually promote to admin in DB
    const usersV2 = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
    const adminUserIndex = usersV2.findIndex(u => u.email === adminEmail);
    usersV2[adminUserIndex].role = 'admin';
    fs.writeFileSync(dbPath, JSON.stringify(usersV2, null, 2));
    console.log('Manually promoted to Admin in DB.');

    // 1. Get Requests
    console.log('\n--- Admin: Fetching Requests ---');
    const reqsRes = await request('GET', '/admin/requests', null, adminCookie);
    console.log('Requests:', reqsRes.body.results);

    if (reqsRes.body.results > 0) {
        // 2. Approve Request
        console.log(`\n--- Admin: Approving Request for ${lockedUser.email} ---`);
        const approveRes = await request('POST', '/admin/handle-request', { userId: lockedUser.id, action: 'approve' }, adminCookie);
        console.log('Approve Status:', approveRes.status);
        console.log('Approve Msg:', approveRes.body.message);
    }

    // 3. Verify Unlock
    console.log(`\n--- Verifying Unlock for ${lockedUser.email} ---`);
    // Attempt login with correct password (assuming it was Password123! from previous script)
    const loginRes = await request('POST', '/auth/login', { email: lockedUser.email, password: 'Password123!' });
    console.log('Login Status:', loginRes.status);
    if (loginRes.status === 200) {
        console.log('>>> SUCCESS: User is unlocked and logged in!');
    } else {
        console.log('>>> FAIL: User still locked or login failed.');
        console.log(loginRes.body);
    }
}

start();
