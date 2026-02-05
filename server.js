const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const db = require('./config/db');
const { encrypt, decrypt, generateKeyPair, signData, verifySignature, calculateLogHash } = require('./middleware/cryptoUtils');
const crypto = require('crypto');

dotenv.config();

const app = express();

// Email Config (Gmail)
// Email Config (Gmail)
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});


// Middleware
app.use(bodyParser.json()); // Support JSON bodies
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session Setup
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Set to true if using HTTPS
}));

// API Routes

// 1. Auth API
// Step 0: Register
app.post('/api/register', async (req, res) => {
    const { username, email, phone_number, password, role, full_name } = req.body;

    // Basic Validation
    if (!username || !email || !password || !full_name) {
        return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    try {
        // Check for existing user
        const [existing] = await db.query('SELECT * FROM users WHERE username = ? OR email = ?', [username, email]);
        if (existing.length > 0) {
            return res.status(400).json({ success: false, message: 'Username or Email already exists' });
        }

        // Hash Password
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(password, salt);

        // Generate Key Pair
        const { publicKey, privateKey } = generateKeyPair();

        // Insert User
        await db.query(
            'INSERT INTO users (username, email, phone_number, password_hash, role, full_name, public_key, private_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [username, email, phone_number, hash, role, full_name, publicKey, privateKey]
        );

        res.json({ success: true, message: 'Registration Successful' });

    } catch (err) {
        console.error("REGISTER ERROR:", err.message);
        console.error(err); // Full stack
        res.status(500).json({ success: false, message: 'Server Error: ' + err.message });
    }
});

// Step 1: Login & Generate OTP
app.post('/api/login', async (req, res) => {
    const { username, password, role } = req.body;

    try {
        const [users] = await db.query('SELECT * FROM users WHERE username = ? AND role = ?', [username, role]);

        if (users.length > 0) {
            // Verify password with bcrypt
            const isValidPassword = await bcrypt.compare(password, users[0].password_hash);

            if (isValidPassword) {
                // Generate OTP
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                const expiry = new Date(Date.now() + 5 * 60 * 1000); // 5 mins

                await db.query('UPDATE users SET otp_code = ?, otp_expires_at = ? WHERE id = ?',
                    [otp, expiry, users[0].id]);

                // Log OTP always for testing/dummy users
                console.log(`[DEV MODE] Generated OTP for ${users[0].email}: ${otp}`);

                // Send Email
                try {
                    await transporter.sendMail({
                        from: '"BioSecure Auth" <meruguakhil2004@gmail.com>',
                        to: users[0].email,
                        subject: 'Your Login OTP',
                        text: `Your One-Time Password is: ${otp}`
                    });
                    console.log(`OTP sent to ${users[0].email}`);
                } catch (emailErr) {
                    console.warn("SMTP Failed, ignoring:", emailErr.message);
                }

                res.json({ success: true, otpRequired: true, userId: users[0].id, message: 'OTP sent to email' });

            } else {
                res.status(401).json({ success: false, message: 'Invalid Password' });
            }
        } else {
            res.status(401).json({ success: false, message: 'Invalid Credentials' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Step 2: Verify OTP
app.post('/api/verify-otp', async (req, res) => {
    const { userId, otp } = req.body;

    try {
        const [users] = await db.query('SELECT * FROM users WHERE id = ?', [userId]);

        if (users.length > 0) {
            const user = users[0];
            const now = new Date();

            if (user.otp_code === otp && new Date(user.otp_expires_at) > now) {
                // OTP Valid
                req.session.user = user;

                // Clear OTP
                await db.query('UPDATE users SET otp_code = NULL, otp_expires_at = NULL WHERE id = ?', [user.id]);

                // Log Access with Hash Chain
                const [lastLog] = await db.query('SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1');
                const prevHash = lastLog.length > 0 ? lastLog[0].hash : '00000000000000000000000000000000';
                const logDetails = `User logged in as ${user.role} via Email OTP`;
                const newHash = calculateLogHash(prevHash, JSON.stringify({ user_id: user.id, action: 'LOGIN_SUCCESS', details: logDetails }));

                await db.query('INSERT INTO audit_logs (user_id, action, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?)',
                    [user.id, 'LOGIN_SUCCESS', logDetails, prevHash, newHash]);

                // Role-based Redirect
                let redirectUrl = '/dashboard.html'; // Fallback
                if (user.role === 'doctor') redirectUrl = '/doctor_dashboard.html';
                else if (user.role === 'patient') redirectUrl = '/patient_dashboard.html';
                else if (user.role === 'admin') redirectUrl = '/admin_dashboard.html';

                res.json({ success: true, redirect: redirectUrl });
            } else {
                res.status(401).json({ success: false, message: 'Invalid or Expired OTP' });
            }
        } else {
            res.status(401).json({ success: false, message: 'User not found' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Forgot Password API
app.post('/api/request-reset', async (req, res) => {
    const { email } = req.body;
    try {
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length > 0) {
            const user = users[0];
            const otp = Math.floor(100000 + Math.random() * 900000).toString();
            const expiry = new Date(Date.now() + 10 * 60 * 1000); // 10 mins

            await db.query('UPDATE users SET otp_code = ?, otp_expires_at = ? WHERE id = ?',
                [otp, expiry, user.id]);

            // Log OTP always
            console.log(`[DEV MODE] Reset OTP for ${email}: ${otp}`);

            // Try sending email, fallback to console
            try {
                await transporter.sendMail({
                    from: '"BioSecure Utils" <support@biosecure.com>',
                    to: email,
                    subject: 'Password Reset Code',
                    text: `Your reset code is: ${otp}`
                });
                console.log(`Reset OTP sent to ${email}`);
            } catch (emailErr) {
                console.warn("SMTP Failed, ignoring.");
            }

            res.json({ success: true, message: 'OTP sent to email (Check console)' });
        } else {
            // User requested to check validity explicitly
            res.json({ success: false, message: 'Email address not found in our records.' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

app.post('/api/reset-password', async (req, res) => {
    const { email, otp, newPassword } = req.body;
    try {
        const [users] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length > 0) {
            const user = users[0];
            const now = new Date();

            if (user.otp_code === otp && new Date(user.otp_expires_at) > now) {
                // Hash new password
                const salt = await bcrypt.genSalt(10);
                const hash = await bcrypt.hash(newPassword, salt);

                await db.query('UPDATE users SET password_hash = ?, otp_code = NULL, otp_expires_at = NULL WHERE id = ?',
                    [hash, user.id]);

                res.json({ success: true, message: 'Password reset successful. Please login.' });
            } else {
                res.status(400).json({ success: false, message: 'Invalid or Expired OTP' });
            }
        } else {
            res.status(400).json({ success: false, message: 'Invalid Request' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

app.get('/api/user', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, user: req.session.user });
    } else {
        res.json({ loggedIn: false });
    }
});

// 2. Data API (Protected with ACL)
const { checkAccess } = require('./middleware/accessControl');

// Admin Route: View Audit Logs
app.get('/api/admin/logs', checkAccess('view_audit_logs'), async (req, res) => {
    try {
        const [logs] = await db.query('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 20');
        res.json({ success: true, logs });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Database Error' });
    }
});

// Doctor Route: View Patient Records
app.get('/api/doctor/patients', checkAccess('view_patient_records'), async (req, res) => {
    try {
        // Fetch ALL patients, regardless of whether they have a record
        const [patients] = await db.query(`
            SELECT u.id as patient_id, u.full_name as patient_name, u.email,
                   r.id as record_id, r.diagnosis, r.prescription 
            FROM users u
            LEFT JOIN records r ON u.id = r.patient_id AND r.doctor_id = ?
            WHERE u.role = 'patient'`,
            [req.session.user.id]
        );

        // Process records: Decrypt if exists
        const processed = patients.map(p => {
            if (p.record_id) {
                return {
                    ...p,
                    decrypted_diagnosis: decrypt(p.diagnosis),
                    decrypted_prescription: decrypt(p.prescription)
                };
            }
            return p;
        });

        res.json({ success: true, records: processed });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Initialize Appointments Table
async function initDB() {
    await db.query(`CREATE TABLE IF NOT EXISTS appointments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        patient_id INT,
        doctor_id INT,
        doctor_name VARCHAR(100),
        patient_name VARCHAR(100),
        date_time DATETIME,
        reason VARCHAR(255),
        status VARCHAR(20) DEFAULT 'Pending',
        FOREIGN KEY (patient_id) REFERENCES users(id)
    )`);

    // Chat Messages Table
    await db.query(`CREATE TABLE IF NOT EXISTS messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        sender_id INT,
        receiver_id INT,
        sender_name VARCHAR(100),
        encrypted_content TEXT,
        content TEXT, 
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (receiver_id) REFERENCES users(id)
    )`);
}
initDB();

// ---------------- API ROUTES ----------------

// Admin Route: System Stats
app.get('/api/admin/stats', checkAccess('view_system_stats', db), async (req, res) => {
    try {
        const [[{ u_count }]] = await db.query('SELECT COUNT(*) as u_count FROM users');
        const [[{ a_count }]] = await db.query('SELECT COUNT(*) as a_count FROM audit_logs');
        const [[{ app_count }]] = await db.query('SELECT COUNT(*) as app_count FROM appointments');

        // Real System Health Logic
        // Count security incidents (DENIED or FAILED) in the last hour
        const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
        const [[{ incident_count }]] = await db.query(
            "SELECT COUNT(*) as incident_count FROM audit_logs WHERE (action LIKE '%DENIED%' OR action LIKE '%FAILED%') AND timestamp > ?",
            [oneHourAgo]
        );

        let health = 'Optimal';
        if (incident_count > 0) health = 'Warning'; // Trigger immediately for demo
        if (incident_count > 3) health = 'Critical';

        res.json({
            success: true,
            user_count: u_count,
            audit_count: a_count,
            appointment_count: app_count,
            system_health: health
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Admin: Get All Users
app.get('/api/admin/all_users', checkAccess('view_system_stats'), async (req, res) => {
    try {
        const [users] = await db.query("SELECT id, username, email, full_name, role, created_at FROM users ORDER BY created_at DESC");
        res.json({ success: true, users });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Admin: Delete User (Cascade)
app.post('/api/admin/delete_user', checkAccess('view_system_stats'), async (req, res) => {
    const { user_id } = req.body;
    if (!user_id) return res.status(400).json({ success: false, message: 'User ID required' });

    try {
        // Delete related records first (Cascade manually if FK constraints aren't set up perfectly)
        await db.query("DELETE FROM records WHERE patient_id = ? OR doctor_id = ?", [user_id, user_id]);
        await db.query("DELETE FROM appointments WHERE patient_id = ? OR doctor_id = ?", [user_id, user_id]);
        await db.query("DELETE FROM audit_logs WHERE user_id = ?", [user_id]);
        await db.query("DELETE FROM messages WHERE sender_id = ? OR receiver_id = ?", [user_id, user_id]);

        // Finally delete user
        await db.query("DELETE FROM users WHERE id = ?", [user_id]);

        res.json({ success: true, message: 'User and all related data deleted.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Delete Failed: ' + err.message });
    }
});

// Admin: Change User Role
app.post('/api/admin/change_role', checkAccess('view_system_stats'), async (req, res) => {
    const { user_id, new_role } = req.body;
    const admin_id = req.session.user.id;

    if (!user_id || !new_role) return res.status(400).json({ success: false, message: 'User ID and New Role required' });

    // Validate role
    const validRoles = ['admin', 'doctor', 'patient'];
    if (!validRoles.includes(new_role)) {
        return res.status(400).json({ success: false, message: 'Invalid Role' });
    }

    try {
        // Prevent changing own role to prevent lockout (optional but good practice)
        if (parseInt(user_id) === admin_id) {
            return res.status(400).json({ success: false, message: 'Cannot change your own role.' });
        }

        await db.query("UPDATE users SET role = ? WHERE id = ?", [new_role, user_id]);

        // Audit Log
        const [lastLog] = await db.query('SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1');
        const prevHash = lastLog.length > 0 ? lastLog[0].hash : '00000000000000000000000000000000';
        const logDetails = `Admin ${admin_id} changed role of User ${user_id} to ${new_role}`;
        const newHash = calculateLogHash(prevHash, JSON.stringify({ user_id: admin_id, action: 'CHANGE_ROLE', details: logDetails }));

        await db.query('INSERT INTO audit_logs (user_id, action, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?)',
            [admin_id, 'CHANGE_ROLE', logDetails, prevHash, newHash]);

        res.json({ success: true, message: 'User role updated successfully.' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Update Failed: ' + err.message });
    }
});

// Admin: Get All Appointments
app.get('/api/admin/all_appointments', checkAccess('view_system_stats'), async (req, res) => {
    try {
        const [apps] = await db.query(`
            SELECT a.*, p.full_name as p_name, d.full_name as d_name 
            FROM appointments a
            LEFT JOIN users p ON a.patient_id = p.id
            LEFT JOIN users d ON a.doctor_id = d.id
            ORDER BY a.date_time DESC
        `);
        res.json({ success: true, appointments: apps });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Admin: Delete Appointment
app.post('/api/admin/delete_appointment', checkAccess('view_system_stats'), async (req, res) => {
    const { app_id } = req.body;
    try {
        await db.query("DELETE FROM appointments WHERE id = ?", [app_id]);
        res.json({ success: true, message: 'Appointment Deleted' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Delete Failed' });
    }
});

// Patient Route: Book Appointment
app.post('/api/patient/book_appointment', checkAccess('book_appointments', db), async (req, res) => {
    const { doctor_id, doctor_name, date_time, reason } = req.body;
    const patient_id = req.session.user.id;
    const patient_name = req.session.user.full_name;

    try {
        await db.query(
            'INSERT INTO appointments (patient_id, doctor_id, doctor_name, patient_name, date_time, reason) VALUES (?, ?, ?, ?, ?, ?)',
            [patient_id, doctor_id, doctor_name, patient_name, date_time, reason]
        );
        res.json({ success: true, message: 'Appointment Booked Successfully' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Booking Error' });
    }
});

// Doctor Route: View Appointments
app.get('/api/doctor/appointments', checkAccess('view_own_profile', db), async (req, res) => {
    try {
        const [apps] = await db.query('SELECT * FROM appointments WHERE doctor_id = ? ORDER BY date_time ASC', [req.session.user.id]);
        res.json({ success: true, appointments: apps });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Error fetching appointments' });
    }
});

// Patient Route: Get All Doctors for Dropdown
app.get('/api/patient/doctors', checkAccess('book_appointments', db), async (req, res) => {
    try {
        const [doctors] = await db.query("SELECT id, full_name FROM users WHERE role = 'doctor'");
        res.json({ success: true, doctors });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Error fetching doctors' });
    }
});

// Patient Route: View Appointments
app.get('/api/patient/appointments', checkAccess('book_appointments', db), async (req, res) => {
    try {
        const [apps] = await db.query('SELECT * FROM appointments WHERE patient_id = ? ORDER BY date_time ASC', [req.session.user.id]);
        res.json({ success: true, appointments: apps });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Error fetching appointments' });
    }
});

// Doctor Route: Create Record (with Digital Signature)
app.post('/api/doctor/create_record', checkAccess('update_patient_records', db), async (req, res) => {
    const { patient_id, diagnosis, prescription } = req.body;
    const doctor_id = req.session.user.id;

    try {
        // 1. Fetch Doctor's Private Key
        const [users] = await db.query('SELECT private_key FROM users WHERE id = ?', [doctor_id]);
        if (users.length === 0 || !users[0].private_key) {
            return res.status(400).json({ success: false, message: 'Doctor keys not found' });
        }
        const privateKey = users[0].private_key;

        // 2. Encrypt Data
        const encDiagnosis = encrypt(diagnosis);
        const encPrescription = encrypt(prescription);

        // 3. Digital Signature (Sign the concatenated ciphertexts to prove integrity)
        // Data to sign: encDiagnosis + encPrescription
        const dataTo  = encDiagnosis + encPrescription;
        const signature = signData(dataToSign, privateKey);

        // 4. Insert into DB
        await db.query(
            'INSERT INTO records (patient_id, doctor_id, diagnosis, prescription, digital_signature) VALUES (?, ?, ?, ?, ?)',
            [patient_id, doctor_id, encDiagnosis, encPrescription, signature]
        );

        // 5. Audit Log (Hash Chain)
        const [lastLog] = await db.query('SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1');
        const prevHash = lastLog.length > 0 ? lastLog[0].hash : '00000000000000000000000000000000';
        const logDetails = `Doctor ${doctor_id} created record for Patient ${patient_id}`;
        const newHash = calculateLogHash(prevHash, JSON.stringify({ user_id: doctor_id, action: 'CREATE_RECORD', details: logDetails }));

        await db.query('INSERT INTO audit_logs (user_id, action, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?)',
            [doctor_id, 'CREATE_RECORD', logDetails, prevHash, newHash]);

        res.json({ success: true, message: 'Record Created & Signed Successfully' });

    } catch (err) {
        console.error(err);
        const fs = require('fs');
        fs.appendFileSync('error_log.txt', `[${new Date().toISOString()}] CREATE RECORD ERROR: ${err.message}\n${err.stack}\n\n`);
        res.status(500).json({ success: false, message: 'Creation Error' });
    }
});

// Doctor Route: Update Record (Secure Edit)
app.post('/api/doctor/update_record', checkAccess('update_patient_records', db), async (req, res) => {
    const { record_id, diagnosis, prescription } = req.body;
    const doctor_id = req.session.user.id;

    try {
        // 1. Verify Ownership & Existence (or ACL allows updates if logic differs)
        const [records] = await db.query('SELECT * FROM records WHERE id = ? AND doctor_id = ?', [record_id, doctor_id]);
        if (records.length === 0) {
            return res.status(404).json({ success: false, message: 'Record not found or unauthorized' });
        }
        const patient_id = records[0].patient_id;

        // 2. Fetch Doctor's Private Key
        const [users] = await db.query('SELECT private_key FROM users WHERE id = ?', [doctor_id]);
        if (users.length === 0 || !users[0].private_key) {
            return res.status(400).json({ success: false, message: 'Doctor keys not found' });
        }
        const privateKey = users[0].private_key;

        // 3. Encrypt NEW Data
        const encDiagnosis = encrypt(diagnosis);
        const encPrescription = encrypt(prescription);

        // 4. Re-Sign Data
        const dataToSign = encDiagnosis + encPrescription;
        const signature = signData(dataToSign, privateKey);

        // 5. Update DB
        await db.query(
            'UPDATE records SET diagnosis = ?, prescription = ?, digital_signature = ? WHERE id = ?',
            [encDiagnosis, encPrescription, signature, record_id]
        );

        // 6. Audit Log (Hash Chain)
        const [lastLog] = await db.query('SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1');
        const prevHash = lastLog.length > 0 ? lastLog[0].hash : '00000000000000000000000000000000';
        const logDetails = `Doctor ${doctor_id} UPDATED record ${record_id} for Patient ${patient_id}`;
        const newHash = calculateLogHash(prevHash, JSON.stringify({ user_id: doctor_id, action: 'UPDATE_RECORD', details: logDetails }));

        await db.query('INSERT INTO audit_logs (user_id, action, details, prev_hash, hash) VALUES (?, ?, ?, ?, ?)',
            [doctor_id, 'UPDATE_RECORD', logDetails, prevHash, newHash]);

        res.json({ success: true, message: 'Record Updated & Re-Signed Successfully' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Update Error' });
    }
});

// Patient Route: View Own Records (with Verification)
app.get('/api/patient/records', checkAccess('view_own_records', db), async (req, res) => {
    try {
        // Fetch Records + Doctor's Public Key
        const [records] = await db.query(`
            SELECT r.*, u.full_name as doctor_name, u.public_key 
            FROM records r 
            JOIN users u ON r.doctor_id = u.id 
            WHERE r.patient_id = ?`,
            [req.session.user.id]
        );

        // Verify and Decrypt
        const processedRecords = records.map(record => {
            const dataToVerify = record.diagnosis + record.prescription;
            const isVerified = verifySignature(dataToVerify, record.digital_signature, record.public_key);

            return {
                ...record,
                diagnosis: record.diagnosis, // Keep encrypted for display (optional)
                decrypted_diagnosis: decrypt(record.diagnosis),
                decrypted_prescription: decrypt(record.prescription),
                is_verified: isVerified
            };
        });

        res.json({ success: true, records: processedRecords });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Server Error' });
    }
});

// Patient Route: Update Contact Info (Action)
app.post('/api/patient/update_contact', checkAccess('update_contact_info', db), async (req, res) => {
    const { phone } = req.body;
    // In a real app, update DB
    res.json({ success: true, message: `Contact info updated to ${phone} (Simulated)` });
});

// Fallback: Serve index.html (Landing Page) for root
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------------- KEY EXCHANGE DEMO ROUTES ----------------
const DHExchange = require('./middleware/keyExchange');

// 1. Initialize Key Exchange (Server generates keys)
app.get('/api/crypto/init', (req, res) => {
    try {
        const dh = new DHExchange();
        const serverPublicKey = dh.generateKeys();

        // Store private key in session to compute secret later
        req.session.dh_private = dh.getPrivateKey();

        res.json({
            success: true,
            prime: dh.getPrime(),
            generator: dh.getGenerator(),
            serverPublicKey: serverPublicKey
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Key Generation Failed' });
    }
});

// 2. Exchange Keys (Client sends their Public Key)
app.post('/api/crypto/exchange', (req, res) => {
    const { clientPublicKey } = req.body;

    if (!req.session.dh_private || !clientPublicKey) {
        return res.status(400).json({ success: false, message: 'Invalid session or missing key' });
    }

    try {
        const dh = new DHExchange();
        dh.setPrivateKey(req.session.dh_private);

        const sharedSecret = dh.computeSecret(clientPublicKey);

        // Store shared secret for future communication
        req.session.shared_secret = sharedSecret;

        // For DEMO purposes only, we return the server's computed secret so the user can verify
        // In PROD, NEVER return the secret!
        res.json({
            success: true,
            message: 'Secret Established',
            debug_secret_server: sharedSecret // DEMO ONLY
        });
    } catch (err) {
        console.error("EXCHANGE ERROR:", err.message);
        console.error("Stack:", err.stack);
        const fs = require('fs');
        fs.appendFileSync('error_log.txt', `[${new Date().toISOString()}] ${err.message}\n${err.stack}\n\n`);
        res.status(500).json({ success: false, message: 'Exchange Failed' });
        res.status(500).json({ success: false, message: 'Exchange Failed' });
    }
});

// 3. Encrypt Message using Shared Secret
app.post('/api/crypto/encrypt-message', (req, res) => {
    const { message } = req.body;

    if (!req.session.shared_secret) {
        return res.status(400).json({ success: false, message: 'No secure session established' });
    }

    try {
        // Derive a 32-byte key from the shared secret (using SHA256)
        const secretHash = crypto.createHash('sha256').update(req.session.shared_secret).digest();

        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', secretHash, iv);

        let encrypted = cipher.update(message, 'utf8', 'hex');
        encrypted += cipher.final('hex');

        const payload = iv.toString('hex') + ':' + encrypted;

        // Also simulate decryption to prove it works
        const decipher = crypto.createDecipheriv('aes-256-cbc', secretHash, iv);
        let decrypted = decipher.update(Buffer.from(encrypted, 'hex'));
        decrypted = Buffer.concat([decrypted, decipher.final()]);

        res.json({
            success: true,
            original: message,
            encrypted: payload,
            decrypted_check: decrypted.toString()
        });

    } catch (err) {
        const fs = require('fs');
        fs.appendFileSync('error_log.txt', `[${new Date().toISOString()}] ENCRYPT ERROR: ${err.message}\n${err.stack}\n\n`);
        console.error("ENCRYPT ERROR:", err);
        res.status(500).json({ success: false, message: 'Encryption Failed' });
    }
});

// ---------------- SECURE CHAT ROUTES ----------------

// Get Contactable Users
app.get('/api/chat/users', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ success: false });
    const user = req.session.user;

    try {
        let contacts = [];
        if (user.role === 'patient') {
            // Patients see all Doctors
            const [doctors] = await db.query("SELECT id, full_name, role FROM users WHERE role = 'doctor'");
            contacts = doctors;
        } else if (user.role === 'doctor') {
            // Doctors see Patients who have messaged them OR all patients (simpler for demo: All Patients)
            const [patients] = await db.query("SELECT id, full_name, role FROM users WHERE role = 'patient'");
            contacts = patients;
        } else {
            // Admin sees everyone
            const [all] = await db.query("SELECT id, full_name, role FROM users WHERE id != ?", [user.id]);
            contacts = all;
        }
        res.json({ success: true, contacts });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false });
    }
});

// Send Message (Accepts Ciphertext for Demo Visuals)
app.post('/api/chat/send', async (req, res) => {
    const { encrypted_content, receiver_id } = req.body;
    const user = req.session.user;

    if (!user || !receiver_id) return res.status(400).json({ success: false });

    try {
        // ... (Decryption Logic same as before)
        const { decrypt } = require('./middleware/cryptoUtils');
        if (!req.session.shared_secret) {
            return res.status(400).json({ success: false, message: 'Encryption Session Lost' });
        }

        const crypto = require('crypto');
        const secretHash = crypto.createHash('sha256').update(req.session.shared_secret).digest();

        const textParts = encrypted_content.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', secretHash, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        const plainContent = decrypted.toString();

        // Store with Receiver ID
        await db.query(
            'INSERT INTO messages (sender_id, receiver_id, sender_name, encrypted_content, content) VALUES (?, ?, ?, ?, ?)',
            [user.id, receiver_id, user.full_name, encrypted_content, plainContent]
        );

        res.json({ success: true });

    } catch (err) {
        console.error("Chat Error", err);
        res.status(500).json({ success: false });
    }
});

// Get History (Peer-to-Peer)
app.get('/api/chat/history', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ success: false });
    const user = req.session.user;
    const { partner_id } = req.query;

    if (!partner_id) return res.json({ success: true, messages: [] });

    try {
        const [messages] = await db.query(
            `SELECT * FROM messages 
             WHERE (sender_id = ? AND receiver_id = ?) 
                OR (sender_id = ? AND receiver_id = ?) 
             ORDER BY timestamp ASC LIMIT 50`,
            [user.id, partner_id, partner_id, user.id]
        );
        res.json({ success: true, messages });
    } catch (err) {
        const fs = require('fs');
        fs.appendFileSync('error_log.txt', `[${new Date().toISOString()}] HISTORY ERROR: ${err.message}\n${err.stack}\n\n`);
        console.error("HISTORY ERROR:", err);
        res.status(500).json({ success: false });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
