const ACL = {
    admin: {
        can: [
            'view_audit_logs',      // Object 1: Audit Logs
            'manage_users',         // Object 2: User Accounts
            'configure_security',   // Object 3: Security Config
            'view_system_stats'     // Object 4: System Statistics
        ]
    },
    doctor: {
        can: [
            'view_patient_records',   // Object 1: Patient Records (Read)
            'update_patient_records', // Object 2: Patient Records (Write) - ADDED
            'write_prescriptions',    // Object 3: Prescriptions
            'view_own_profile'        // Object 4: Doctor Profile
        ]
    },
    patient: {
        can: [
            'view_own_records',     // Object 1: Own Medical History
            'view_prescriptions',   // Object 2: Own Prescriptions
            'update_contact_info',  // Object 3: Contact Details - ADDED
            'book_appointments'     // Object 4: Appointments - ADDED
        ]
    }
};

/**
 * Middleware to Enforce Access Control
 * @param {string} permission - The specific permission required (e.g., 'view_audit_logs')
 */
/**
 * Middleware to Enforce Access Control
 * @param {string} permission - The specific permission required (e.g., 'view_audit_logs')
 * @param {object} db - Minimum viable DB object to perform queries (Optional but needed for auditing)
 */
const checkAccess = (permission, db) => {
    return async (req, res, next) => {
        // 1. Check if user is logged in
        if (!req.session || !req.session.user) {
            return res.status(401).json({
                success: false,
                message: 'Unauthorized: Please login first',
                error_code: 'AUTH_REQUIRED'
            });
        }

        const userRole = req.session.user.role;
        const userId = req.session.user.id; // Get ID for logging

        // 2. Check if role exists in ACL
        if (!ACL[userRole]) {
            return res.status(403).json({
                success: false,
                message: 'Forbidden: Invalid Role',
                error_code: 'INVALID_ROLE'
            });
        }

        // 3. Check if role has the specific permission
        if (ACL[userRole].can.includes(permission)) {
            return next();
        } else {
            // 4. Deny Access & Log to DB
            const action = `ACCESS_DENIED: ${permission}`;
            const details = `User ${req.session.user.username} (${userRole}) attempted to access ${permission}`;
            console.warn(details);

            if (db) {
                try {
                    await db.query('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)',
                        [userId, action, details]);
                } catch (err) {
                    console.error("Failed to write audit log:", err);
                }
            }

            return res.status(403).json({
                success: false,
                message: 'Forbidden: You do not have permission to perform this action.',
                error_code: 'ACCESS_DENIED'
            });
        }
    };
};

module.exports = { ACL, checkAccess };
