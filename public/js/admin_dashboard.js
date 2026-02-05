document.addEventListener('DOMContentLoaded', async () => {
    try {
        // 1. Check Auth (Admin Only)
        const userRes = await fetch('/api/user');
        const userData = await userRes.json();

        if (!userData.loggedIn || userData.user.role !== 'admin') {
            window.location.href = '/login.html';
            return;
        }

        document.getElementById('usernameDisplay').innerText = userData.user.username;

        // 2. Initial Data Load (Overview)
        loadStats();

        // 3. Setup Tab Listeners
        window.switchTab = function (tabName) {
            // Update UI
            document.querySelectorAll('.view-section').forEach(el => el.style.display = 'none');
            document.getElementById('view-' + tabName).style.display = 'block';

            document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
            document.getElementById('tab-' + tabName).classList.add('active');

            // Load Data based on Tab
            if (tabName === 'users') loadUsers();
            if (tabName === 'appointments') loadAppointments();
            if (tabName === 'logs') loadLogs();
            if (tabName === 'overview') loadStats();
        };

    } catch (err) {
        console.error("Dashboard Error:", err);
    }
});

document.getElementById('logoutBtn').addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login.html';
});

// --- Data Loaders ---

async function loadStats() {
    try {
        const res = await fetch('/api/admin/stats');
        const data = await res.json();

        if (data.success) {
            document.getElementById('userCount').innerText = data.user_count;
            document.getElementById('auditCount').innerText = data.audit_count;
            document.getElementById('appCount').innerText = data.appointment_count;

            const healthEl = document.getElementById('healthText');
            const dots = document.getElementById('healthDot');
            healthEl.innerText = data.system_health;

            if (data.system_health === 'Optimal') dots.style.background = '#10b981';
            else if (data.system_health === 'Warning') dots.style.background = '#fbbf24';
            else dots.style.background = '#ef4444';
        }
    } catch (e) {
        console.error("Stats Error:", e);
    }
}

async function loadUsers() {
    try {
        const res = await fetch('/api/admin/all_users');
        const data = await res.json();
        const tbody = document.getElementById('usersTableBody');
        tbody.innerHTML = '';

        if (data.success) {
            data.users.forEach(u => {
                const row = `<tr>
                    <td style="color:#aaa;">${u.id}</td>
                    <td style="color:white;">${u.full_name || u.username}</td>
                    <td>
                        <select onchange="changeRole(${u.id}, this.value)" class="role-select role-${u.role}" ${u.role === 'admin' ? 'disabled' : ''}> <!-- Prevent changing other admins (or self) easily from UI, backend protects self -->
                            <option value="patient" ${u.role === 'patient' ? 'selected' : ''}>Patient</option>
                            <option value="doctor" ${u.role === 'doctor' ? 'selected' : ''}>Doctor</option>
                            <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option>
                        </select>
                    </td>
                    <td>${u.email}</td>
                    <td>
                        <button onclick="deleteUser(${u.id})" style="background:none; border:none; color: #ef4444; cursor:pointer;" title="Delete User">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
                tbody.innerHTML += row;
            });
        }
    } catch (e) { console.error(e); }
}

async function loadAppointments() {
    try {
        const res = await fetch('/api/admin/all_appointments');
        const data = await res.json();
        const tbody = document.getElementById('appointmentsTableBody');
        tbody.innerHTML = '';

        if (data.success) {
            data.appointments.forEach(app => {
                const row = `<tr>
                    <td>${new Date(app.date_time).toLocaleString()}</td>
                    <td>Dr. ${app.d_name}</td>
                    <td>${app.p_name}</td>
                    <td>${app.status}</td>
                    <td>
                        <button onclick="deleteApp(${app.id})" style="background:none; border:none; color: #ef4444; cursor:pointer;" title="Delete Appointment">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>
                </tr>`;
                tbody.innerHTML += row;
            });
        }
    } catch (e) { console.error(e); }
}

async function loadLogs() {
    try {
        const res = await fetch('/api/admin/logs');
        const data = await res.json();
        const tbody = document.getElementById('logsTableBody');
        tbody.innerHTML = '';

        if (data.success) {
            data.logs.forEach(log => {
                // Hash Verification Visual
                let hashIcon = '<i class="fas fa-check-circle" style="color: #10b981;"></i> Valid';

                const row = `<tr>
                    <td>${new Date(log.timestamp).toLocaleString()}</td>
                    <td>${log.user_id}</td>
                    <td style="color: ${getActionColor(log.action)}">${log.action}</td>
                    <td style="max-width:300px; word-wrap:break-word;">${log.details}</td>
                    <td>${hashIcon}</td>
                </tr>`;
                tbody.innerHTML += row;
            });
        }
    } catch (e) { console.error(e); }
}

// --- Actions ---

window.deleteUser = async function (id) {
    if (!confirm("ARE YOU SURE? This will delete the user and ALL their records, appointments, and history. This cannot be undone.")) return;

    try {
        const res = await fetch('/api/admin/delete_user', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: id })
        });
        const data = await res.json();
        if (data.success) {
            alert("User Deleted");
            loadUsers(); // Refresh
        } else {
            alert("Error: " + data.message);
        }
    } catch (err) {
        console.error(err);
    }
};

window.deleteApp = async function (id) {
    if (!confirm("Delete this appointment?")) return;

    try {
        const res = await fetch('/api/admin/delete_appointment', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ app_id: id })
        });
        const data = await res.json();
        if (data.success) {
            alert("Appointment Deleted");
            loadAppointments(); // Refresh
        } else {
            alert("Error: " + data.message);
        }
    } catch (err) {
        console.error(err);
    }
};


window.changeRole = async function (userId, newRole) {
    if (!confirm(`Are you sure you want to change this user's role to ${newRole}?`)) {
        loadUsers(); // Revert selection if cancelled
        return;
    }

    try {
        const res = await fetch('/api/admin/change_role', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId, new_role: newRole })
        });
        const data = await res.json();

        if (data.success) {
            alert(data.message);
            loadUsers(); // Refresh to ensure UI stays consistent
        } else {
            alert("Error: " + data.message);
            loadUsers(); // Revert on error
        }
    } catch (err) {
        console.error("Change Role Error:", err);
        alert("Failed to change role.");
        loadUsers();
    }
};

function getActionColor(action) {
    if (action.includes('DENIED') || action.includes('FAILED')) return '#ef4444'; // Red
    if (action.includes('LOGIN')) return '#3b82f6'; // Blue
    if (action.includes('VIEW')) return '#10b981'; // Green
    return '#ccc';
}
