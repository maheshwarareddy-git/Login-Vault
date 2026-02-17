const JsonDB = require('./backend/config/database');
const userDb = new JsonDB('users');

const email = 'gravityanti1001@gmail.com';
const user = userDb.findOne({ email });

if (user) {
    console.log(`Found user: ${user.name} (${user.id})`);

    userDb.updateById(user.id, {
        isLocked: false,
        failedLoginAttempts: 0,
        unblockRequest: {
            ...user.unblockRequest,
            status: 'approved',
            resolvedAt: new Date().toISOString(),
            resolvedBy: 'SYSTEM_OVERRIDE'
        }
    });

    console.log('✅ User MANUALLY UNLOCKED.');

    if (user.resetPasswordToken) {
        console.log('🔑 EXISTING RESET LINK:');
        console.log(`http://localhost:3000/reset-password.html?token=${user.resetPasswordToken}`);
    } else {
        console.log('⚠️ No reset token found.');
    }
} else {
    console.log('❌ User not found.');
}
