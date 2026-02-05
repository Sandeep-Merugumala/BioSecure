const db = require('./config/db');
const bcrypt = require('bcrypt');
const { generateKeyPair } = require('./middleware/cryptoUtils');

const PASSWORD = 'Sandeep0512@';
const DOCTOR_COUNT = 4;
const PATIENT_COUNT = 50;

async function seed() {
    console.log("🌱 Starting Seeder...");

    try {
        // 1. Generate Hash
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(PASSWORD, salt);
        console.log(`🔐 Password Hashed: ${hash.substring(0, 20)}...`);

        const users = [];

        // 2. Generate Doctors
        for (let i = 1; i <= DOCTOR_COUNT; i++) {
            const { publicKey, privateKey } = generateKeyPair();
            users.push([
                `doctor_${i}`,                  // username
                `doctor${i}@biosecure.com`,     // email
                `555-010${i}`,                  // phone
                hash,                           // password_hash
                'doctor',                       // role
                `Dr. Dummy ${i}`,               // full_name
                publicKey,
                privateKey
            ]);
        }

        // 3. Generate Patients
        for (let i = 1; i <= PATIENT_COUNT; i++) {
            const { publicKey, privateKey } = generateKeyPair();
            users.push([
                `patient_${i}`,                 // username
                `patient${i}@biosecure.com`,    // email
                `555-020${i}`,                  // phone
                hash,                           // password_hash
                'patient',                      // role
                `Patient Demo ${i}`,            // full_name
                publicKey,
                privateKey
            ]);
        }

        console.log(`✨ Prepare to insert ${users.length} users...`);

        // 4. Batch Insert
        const query = `
            INSERT INTO users 
            (username, email, phone_number, password_hash, role, full_name, public_key, private_key) 
            VALUES ?
        `;

        await db.query(query, [users]);

        console.log("✅ Seeding Complete!");
        process.exit(0);

    } catch (err) {
        console.error("❌ Seeding Failed:", err);
        process.exit(1);
    }
}

seed();
