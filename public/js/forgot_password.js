const requestForm = document.getElementById('requestForm');
const resetForm = document.getElementById('resetForm');
const status = document.getElementById('statusMessage');

// Elements for Strength Meter
const newPassInput = document.getElementById('newPassword');
const confirmNewPassInput = document.getElementById('confirmNewPassword');
const togglePassword = document.getElementById('togglePassword');
const strengthMeter = document.getElementById('strengthMeter');
const strengthStatus = document.getElementById('strengthStatus');
const strengthBar = document.getElementById('strengthBar');
const matchText = document.getElementById('reset-password-match');
const requirements = {
    length: document.getElementById('req-length'),
    uppercase: document.getElementById('req-uppercase'),
    lowercase: document.getElementById('req-lowercase'),
    number: document.getElementById('req-number'),
    special: document.getElementById('req-special')
};

const commonPasswords = ["password", "123456", "12345678", "admin", "welcome", "biosecure"];

// Toggle Password Visibility
if (togglePassword) {
    togglePassword.addEventListener('click', function () {
        const type = newPassInput.getAttribute('type') === 'password' ? 'text' : 'password';
        newPassInput.setAttribute('type', type);
        this.classList.toggle('fa-eye');
        this.classList.toggle('fa-eye-slash');
    });
}

function updateRequirement(element, isMet) {
    if (!element) return;
    const icon = element.querySelector('.requirement-icon');
    if (isMet) {
        element.classList.remove('req-unmet');
        element.classList.add('req-met');
        icon.classList.remove('fa-times-circle');
        icon.classList.add('fa-check-circle');
    } else {
        element.classList.remove('req-met');
        element.classList.add('req-unmet');
        icon.classList.remove('fa-check-circle');
        icon.classList.add('fa-times-circle');
    }
}

function calculateStrength(password) {
    let score = 0;

    // Checks
    const isLength = password.length >= 8;
    const isUpper = /[A-Z]/.test(password);
    const isLower = /[a-z]/.test(password);
    const isNumber = /\d/.test(password);
    const isSpecial = /[^A-Za-z0-9]/.test(password);
    const isBlacklisted = commonPasswords.includes(password.toLowerCase());

    // Update UI List
    updateRequirement(requirements.length, isLength);
    updateRequirement(requirements.uppercase, isUpper);
    updateRequirement(requirements.lowercase, isLower);
    updateRequirement(requirements.number, isNumber);
    updateRequirement(requirements.special, isSpecial);

    if (isBlacklisted) return -1;

    if (isLength) score++;
    if (isUpper) score++;
    if (isLower) score++;
    if (isNumber) score++;
    if (isSpecial) score++;

    return score;
}

function updateMeter(score) {
    let width = (score / 5) * 100;
    let label = "Weak";
    let colorClass = "fill-weak";
    let textClass = "status-weak";

    if (score === -1) {
        width = 100;
        label = "Weak (Common)";
    } else if (score <= 2) {
        label = "Weak";
        colorClass = "fill-weak";
        textClass = "status-weak";
    } else if (score === 3 || score === 4) {
        label = "Medium";
        colorClass = "fill-medium";
        textClass = "status-medium";
    } else if (score === 5) {
        label = "Strong";
        colorClass = "fill-strong";
        textClass = "status-strong";
    }

    if (strengthBar) {
        strengthBar.style.width = `${Math.max(width, 5)}%`;
        strengthBar.className = `progress-bar-fill ${colorClass}`;
    }

    if (strengthStatus) {
        strengthStatus.innerText = label;
        strengthStatus.className = `strength-status ${textClass}`;
    }
}

if (newPassInput) {
    newPassInput.addEventListener('input', () => {
        const val = newPassInput.value;

        if (strengthMeter) {
            if (val.length > 0) {
                strengthMeter.style.display = 'block';
            } else {
                strengthMeter.style.display = 'none';
                return;
            }
        }

        const score = calculateStrength(val);
        updateMeter(score);
        checkMatch();
    });
}

if (confirmNewPassInput) {
    confirmNewPassInput.addEventListener('input', checkMatch);
}

function checkMatch() {
    const pass = newPassInput.value;
    const confirm = confirmNewPassInput.value;

    if (!matchText) return;

    if (confirm.length === 0) {
        matchText.style.display = 'none';
        return;
    }

    matchText.style.display = 'block';
    if (pass === confirm) {
        matchText.innerText = "Passwords Match";
        matchText.style.color = "green";
    } else {
        matchText.innerText = "Passwords Do Not Match";
        matchText.style.color = "red";
    }
}

requestForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('email').value;
    const btn = e.target.querySelector('button');

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Checking...';
    status.style.display = 'none';

    try {
        const res = await fetch('/api/request-reset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email })
        });
        const data = await res.json();

        if (data.success) {
            requestForm.style.display = 'none';
            resetForm.style.display = 'block';
            document.getElementById('resetEmail').value = email;

            status.innerText = data.message;
            status.style.color = '#10b981';
            status.style.display = 'block';
        } else {
            status.innerText = data.message;
            status.style.color = 'var(--accent-alert)';
            status.style.display = 'block';
            btn.disabled = false;
            btn.innerHTML = 'Send Code <i class="fas fa-paper-plane"></i>';
        }
    } catch (err) {
        console.error(err);
        status.innerText = "Network Error";
        status.style.display = 'block';
        btn.disabled = false;
    }
});

resetForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('resetEmail').value;
    const otp = document.getElementById('otp').value;
    const newPassword = newPassInput.value;
    const confirmPassword = confirmNewPassInput.value;
    const score = calculateStrength(newPassword);

    if (newPassword !== confirmPassword) {
        alert("Passwords do not match!");
        return;
    }

    // NIST Enforcement: Block if Weak
    if (score <= 2) {
        alert("Password is too weak. Please meet more requirements (Length, Uppercase, Lowercase, Number, Special).");
        return;
    }

    try {
        const res = await fetch('/api/reset-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, otp, newPassword })
        });
        const data = await res.json();

        if (data.success) {
            alert("Success! Your password has been updated. Please login.");
            window.location.href = 'login.html';
        } else {
            status.innerText = data.message;
            status.style.color = 'var(--accent-alert)';
            status.style.display = 'block';
        }
    } catch (err) {
        console.error(err);
        status.innerText = "Network Error";
        status.style.display = 'block';
    }
});
