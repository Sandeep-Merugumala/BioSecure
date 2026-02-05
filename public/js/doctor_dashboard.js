document.addEventListener('DOMContentLoaded', async () => {
    try {
        // 1. Check Auth
        const userRes = await fetch('/api/user');
        const userData = await userRes.json();

        if (!userData.loggedIn || userData.user.role !== 'doctor') {
            window.location.href = '/login.html';
            return;
        }

        document.getElementById('usernameDisplay').innerText = userData.user.full_name || userData.user.username;

        // 2. Initial Data Load (Overview)
        loadOverview();

        // 3. Setup Tab Listeners
        window.switchTab = function (tabName) {
            // Update UI
            document.querySelectorAll('.view-section').forEach(el => el.style.display = 'none');
            document.getElementById('view-' + tabName).style.display = 'block';

            document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
            document.getElementById('tab-' + tabName).classList.add('active');

            // Update Title
            const titles = {
                'overview': 'Doctor Overview',
                'patients': 'My Patients',
                'appointments': 'Upcoming Appointments',
                'scanner': 'Patient Verification'
            };
            document.getElementById('pageTitle').innerText = titles[tabName];

            // Load Data
            if (tabName === 'overview') loadOverview();
            if (tabName === 'patients') loadPatients();
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

// --- Data Loaders ---

async function loadOverview() {
    // Parallel fetch for stats
    const [patRes, appRes] = await Promise.all([
        fetch('/api/doctor/patients'),
        fetch('/api/doctor/appointments')
    ]);
    const patData = await patRes.json();
    const appData = await appRes.json();

    if (patData.success) {
        document.getElementById('patCount').innerText = patData.records.length;
    }
    if (appData.success) {
        document.getElementById('apptCount').innerText = appData.appointments.length;
    }
}

async function loadPatients() {
    const res = await fetch('/api/doctor/patients');
    const data = await res.json();
    const container = document.getElementById('patientsContainer');
    container.innerHTML = ''; // Loading or Clear

    if (!data.success) return;

    if (data.records.length === 0) {
        container.innerHTML = '<p style="color:#aaa;">No patients assigned.</p>';
        return;
    }

    // Grid Layout for Patients
    let html = '<div class="grid" style="display:grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap:1.5rem;">';

    data.records.forEach(record => {
        if (record.record_id) {
            // Existing Record
            html += `
            <div class="card">
                <div class="card-header">
                    <span class="card-title">${record.patient_name}</span>
                    <span class="role-badge role-patient">ID: ${record.patient_id}</span>
                </div>
                <div class="card-body">
                    <label style="font-size:0.8rem; color:#aaa;">DIAGNOSIS (ENCRYPTED):</label>
                    <div class="encrypted-text" id="enc-${record.record_id}">${record.diagnosis.substring(0, 30)}...</div>
                    
                    <div class="decrypted-text" id="dec-${record.record_id}" style="display:none; margin-top:0.5rem;">
                        <strong>Diagnosis:</strong> <span id="diag-txt-${record.record_id}">${record.decrypted_diagnosis}</span><br>
                        <strong>Rx:</strong> <span id="rx-txt-${record.record_id}">${record.decrypted_prescription}</span>
                    </div>

                    <div style="display:flex; gap:0.5rem; margin-top:1rem;">
                        <button onclick="toggleDecrypt(${record.record_id})" class="btn-primary" style="flex:1; padding:0.5rem; font-size:0.85rem;">
                            <i class="fas fa-eye"></i> View
                        </button>
                         <button onclick="openEditModal(${record.record_id})" class="btn-secondary" style="border-color:var(--accent-secure); color:var(--accent-secure); padding:0.5rem;">
                            <i class="fas fa-edit"></i>
                        </button>
                    </div>
                </div>
            </div>`;
        } else {
            // No Record (Create New)
            html += `
            <div class="card" style="border-left: 4px solid #f59e0b;">
                <div class="card-header">
                    <span class="card-title">${record.patient_name}</span>
                    <span class="role-badge role-admin">New Patient</span>
                </div>
                 <div class="card-body">
                    <p style="color:#aaa; font-size:0.9rem;">No medical record established.</p>
                    <button onclick="createRecord(${record.patient_id})" class="btn-primary" style="margin-top:1rem; background: var(--accent-audit); color:black;">
                        <i class="fas fa-plus-circle"></i> Create Initial Record
                    </button>
                </div>
            </div>`;
        }
    });

    html += '</div>';
    container.innerHTML = html;
}

async function loadAppointments() {
    const res = await fetch('/api/doctor/appointments');
    const data = await res.json();
    const container = document.getElementById('appointmentsContainer');

    // We can use the professional table style here
    let html = `
    <div class="log-container">
        <table class="log-table">
            <thead>
                <tr>
                    <th>Date</th>
                    <th>Patient</th>
                    <th>Reason</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
    `;

    if (data.success && data.appointments.length > 0) {
        data.appointments.forEach(app => {
            html += `
                <tr>
                    <td>${new Date(app.date_time).toLocaleString()}</td>
                    <td style="color:white; font-weight:bold;">${app.patient_name}</td>
                    <td>${app.reason}</td>
                    <td><span class="role-badge role-doctor">${app.status}</span></td>
                </tr>
            `;
        });
    } else {
        html += '<tr><td colspan="4">No appointments found.</td></tr>';
    }

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

// --- Actions ---

window.createRecord = function (patientId) {
    document.getElementById('createPatientId').value = patientId;
    document.getElementById('createDiagnosis').value = '';
    document.getElementById('createPrescription').value = '';
    document.getElementById('createModal').style.display = 'flex';
};

window.closeCreateModal = function () {
    document.getElementById('createModal').style.display = 'none';
};

window.submitCreate = async function () {
    const patientId = document.getElementById('createPatientId').value;
    const diagnosis = document.getElementById('createDiagnosis').value;
    const prescription = document.getElementById('createPrescription').value;

    if (!diagnosis || !prescription) {
        showToast("Please fill all fields", "error");
        return;
    }

    try {
        const res = await fetch('/api/doctor/create_record', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ patient_id: patientId, diagnosis, prescription })
        });
        const data = await res.json();
        if (data.success) {
            closeCreateModal();
            showToast("Record Created Successfully!", "success");
            loadPatients(); // Refresh view
            loadOverview(); // Refresh stats
        } else {
            showToast(data.message, "error");
        }
    } catch (err) {
        console.error(err);
        showToast("Server Error", "error");
    }
};

window.toggleDecrypt = function (id) {
    const enc = document.getElementById('enc-' + id);
    const dec = document.getElementById('dec-' + id);

    if (dec.style.display === 'none') {
        dec.style.display = 'block';
        enc.style.display = 'none';
        // enc.style.opacity = '0.5';
    } else {
        dec.style.display = 'none';
        enc.style.display = 'block';
        // enc.style.opacity = '1';
    }
};

window.verifyPatient = function () {
    const input = document.getElementById('scanInput').value.trim();
    const resultDiv = document.getElementById('scanResult');

    if (!input) {
        alert("Please enter a token.");
        return;
    }

    try {
        const decoded = atob(input);
        if (decoded.startsWith("ID:") && decoded.includes("|")) {
            const parts = decoded.split("|");
            const name = parts[1];

            resultDiv.style.display = "block";
            resultDiv.style.background = "rgba(16, 185, 129, 0.1)";
            resultDiv.style.border = "1px solid #10b981";
            resultDiv.style.color = "#10b981";
            resultDiv.innerHTML = `
                <div style="font-size:1.2rem; margin-bottom:0.5rem;"><i class="fas fa-check-circle"></i> Verified</div>
                <strong>${name}</strong><br>
                <small>Valid BioSecure Identity</small>
            `;
        } else {
            throw new Error("Invalid");
        }
    } catch (err) {
        resultDiv.style.display = "block";
        resultDiv.style.background = "rgba(239, 68, 68, 0.1)";
        resultDiv.style.border = "1px solid #ef4444";
        resultDiv.style.color = "#ef4444";
        resultDiv.innerHTML = `<div><i class="fas fa-times-circle"></i> Invalid Token</div>`;
    }
};

// --- Modal Functions ---

window.openEditModal = function (id) {
    // 1. Get current values from the (hidden) decrypted spans or DOM
    // Note: User must have clicked "View" first to decrypt, otherwise data is empty/encrypted.
    // For better UX, we could auto-decrypt if needed, but for security, let's assume valid data is there or prompt.
    // Actually, the 'record' object in 'data.records' has the decrypted text if we store it.
    // But since `loadPatients` scope is gone, we grab from DOM strings (which might require decrypting first).

    // Check if decrypted view is visible/populated
    const diagEl = document.getElementById('diag-txt-' + id);
    const rxEl = document.getElementById('rx-txt-' + id);

    if (!diagEl || !rxEl || diagEl.closest('.decrypted-text').style.display === 'none') {
        showToast("Please 'View' (Decrypt) the record first.", "error");
        return;
    }

    document.getElementById('editRecordId').value = id;
    document.getElementById('editDiagnosis').value = diagEl.innerText;
    document.getElementById('editPrescription').value = rxEl.innerText;

    document.getElementById('editModal').style.display = 'flex';
};

window.closeModal = function () {
    document.getElementById('editModal').style.display = 'none';
};

window.submitEdit = async function () {
    const id = document.getElementById('editRecordId').value;
    const diagnosis = document.getElementById('editDiagnosis').value;
    const prescription = document.getElementById('editPrescription').value;

    if (!diagnosis || !prescription) {
        showToast("Fields cannot be empty", "error");
        return;
    }

    try {
        const res = await fetch('/api/doctor/update_record', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ record_id: id, diagnosis, prescription })
        });
        const data = await res.json();

        if (data.success) {
            closeModal();
            loadPatients(); // Refresh to show new Data (ciphertext will change)
            showToast("Record Updated Successfully!", "success");
        } else {
            showToast(data.message, "error");
        }
    } catch (err) {
        console.error(err);
        showToast("Server Error", "error");
    }
};
