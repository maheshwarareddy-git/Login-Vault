const http = require('http');

function request(method, path, body) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'localhost',
            port: 3000,
            path: '/api/auth' + path,
            method: method,
            headers: { 'Content-Type': 'application/json' }
        };
        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => data += chunk);
            res.on('end', () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
                catch { resolve({ status: res.statusCode, body: data }); }
            });
        });
        req.on('error', (e) => reject(e));
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

async function start() {
    // 1. Create a user to reset
    const email = `reset_test_${Date.now()}@example.com`;
    console.log(`--- Creating User ${email} ---`);
    await request('POST', '/register', { email, password: 'OldPassword1!', name: 'Reset User' });

    // 2. Request Reset
    console.log('\n--- Requesting Password Reset ---');
    const res = await request('POST', '/forgot-password', { email });
    console.log('Forgot Password Response:', res.status, res.body.message);

    // 3. User needs to manually check server log for token... 
    // Since we can't easily grep the running server console from here without a complex setup,
    // we will cheat and read the token directly from the DB file for verification purposes.

    const fs = require('fs');
    const path = require('path');
    const dbPath = path.join(__dirname, 'data', 'users.json');

    // Give DB a moment to flush
    await new Promise(r => setTimeout(r, 1000));

    const users = JSON.parse(fs.readFileSync(dbPath, 'utf-8'));
    const user = users.find(u => u.email === email);

    if (!user || !user.resetPasswordToken) {
        console.log('FAILED: User not found or no token generated.');
        return;
    }

    const token = user.resetPasswordToken;
    console.log(`\n--- Extracted Token from DB: ${token} ---`);

    // 4. Reset Password
    console.log('\n--- Reseting Password ---');
    const newPass = 'NewPassword123!';
    const resetRes = await request('POST', '/reset-password', {
        token,
        password: newPass,
        confirmPassword: newPass
    });
    console.log('Reset Response:', resetRes.status, resetRes.body.message);

    // 5. Verify New Login
    console.log('\n--- Verifying Login with New Password ---');
    const loginRes = await request('POST', '/login', { email, password: newPass });

    if (loginRes.status === 200) {
        console.log('>>> SUCCESS: Logged in with new password!');
    } else {
        console.log('>>> FAIL: Could not login.', loginRes.body);
    }
}

start();
