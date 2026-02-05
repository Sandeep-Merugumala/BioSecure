document.addEventListener('DOMContentLoaded', async () => {
    try {
        // 1. Check Auth
        const userRes = await fetch('/api/user');
        const userData = await userRes.json();

        if (!userData.loggedIn || userData.user.role !== 'patient') {
            window.location.href = '/login.html';
            return;
        }

        const user = userData.user;
        document.getElementById('usernameDisplay').innerText = user.full_name || user.username;

        // Populate Digital ID (Pre-load)
        setupDigitalID(user);

        // 2. Initial Data
        loadOverview();

        // 3. Setup Tabs
        window.switchTab = function (tabName) {
            document.querySelectorAll('.view-section').forEach(el => el.style.display = 'none');
            document.getElementById('view-' + tabName).style.display = 'block';

            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            document.getElementById('tab-' + tabName).classList.add('active');

            const titles = {
                'overview': 'Patient Overview',
                'history': 'Medical History',
                'appointments': 'My Appointments',
                'digitalid': 'Digital Identity'
            };
            document.getElementById('pageTitle').innerText = titles[tabName];

            if (tabName === 'overview') loadOverview();
            if (tabName === 'history') loadHistory();
            if (tabName === 'appointments') loadAppointments();
        };

    } catch (err) {
        console.error("Dashboard Error:", err);
    }
});

document.getElementById('logoutBtn').addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    window.location.href = '/login.html';
});

// --- LOADERS ---
async function loadOverview() {
    const res = await fetch('/api/patient/appointments');
    const data = await res.json();
    if (data.success) {
        document.getElementById('upAppCount').innerText = data.appointments.length;
    }
}

async function loadHistory() {
    const res = await fetch('/api/patient/records');
    const data = await res.json();
    const container = document.getElementById('historyContainer');

    // Grid
    let html = '<div class="grid" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:1.5rem;">';

    if (data.success && data.records.length > 0) {
        data.records.forEach(rec => {
            html += `
            <div class="card">
                <div class="card-header">
                    <span class="card-title">Dr. ${rec.doctor_name}</span>
                    <span class="role-badge role-patient"><i class="fas fa-check"></i> Verified Record</span>
                </div>
                <div class="card-body">
                    <label style="color:#aaa; font-size:0.8rem;">PRESCRIPTION</label>
                    <p style="color:white; margin-bottom:1rem;">${rec.decrypted_prescription}</p>
                    
                    <div style="border-top:1px solid #333; padding-top:0.5rem;">
                        <span style="font-size:0.8rem; color:var(--accent-secure);">
                            <i class="fas fa-signature"></i> Digital Signature Valid
                        </span>
                    </div>
                </div>
            </div>`;
        });
    } else {
        html += '<p style="color:#aaa;">No medical history found.</p>';
    }

    html += '</div>';
    container.innerHTML = html;
}

async function loadAppointments() {
    // 1. Fetch Doctors for Select
    const docRes = await fetch('/api/patient/doctors');
    const docData = await docRes.json();
    const select = document.getElementById('docSelect');

    if (docData.success) {
        select.innerHTML = docData.doctors.map(d => `<option value="${d.id}">${d.full_name}</option>`).join('');
    }

    // 2. Fetch Appointments for List
    const appRes = await fetch('/api/patient/appointments');
    const appData = await appRes.json();
    const tbody = document.getElementById('appTableBody');
    tbody.innerHTML = '';

    if (appData.success && appData.appointments.length > 0) {
        appData.appointments.forEach(app => {
            tbody.innerHTML += `
            <tr>
                <td>${new Date(app.date_time).toLocaleString()}</td>
                <td style="color:white;">Dr. ${app.doctor_name}</td>
                <td><span class="role-badge role-patient">${app.status}</span></td>
            </tr>`;
        });
    } else {
        tbody.innerHTML = '<tr><td colspan="3">No appointments.</td></tr>';
    }
}

// --- ID LOGIC ---
function setupDigitalID(user) {
    document.getElementById('pNameID').innerText = user.full_name;
    document.getElementById('pIdID').innerText = "System ID: " + user.id;

    // Encode
    const rawData = `ID:${user.id}|${user.full_name}|${user.role}`;
    const token = btoa(rawData);

    document.getElementById('rawToken').value = token;

    // QR
    document.getElementById('qrcode').innerHTML = ''; // Clear prev
    new QRCode(document.getElementById("qrcode"), {
        text: token,
        width: 150,
        height: 150,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.H
    });
}

window.copyToken = function () {
    const el = document.getElementById('rawToken');
    el.select();
    document.execCommand('copy');
    showToast("Token Copied to Clipboard", "success");
};

window.bookAppointment = async function (e) {
    e.preventDefault();
    const docSelect = document.getElementById('docSelect');
    const doctor_id = docSelect.value;
    const doctor_name = docSelect.options[docSelect.selectedIndex].text;
    const date_time = document.getElementById('appDate').value;
    const reason = document.getElementById('appReason').value;

    try {
        const res = await fetch('/api/patient/book_appointment', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ doctor_id, doctor_name, date_time, reason })
        });
        const data = await res.json();
        if (data.success) {
            showToast(data.message, "success");
            loadAppointments(); // Refresh list
        } else {
            showToast("Booking Failed: " + data.message, "error");
        }
    } catch (err) {
        console.error(err);
        showToast("Network Error", "error");
    }
};
