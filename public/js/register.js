// NIST SP 800-63-2 Compliance + Visual UI
const commonPasswords = ["password", "123456", "12345678", "admin", "welcome", "biosecure"];

// Elements
const passwordInput = document.getElementById('password');
const confirmPasswordInput = document.getElementById('confirm_password');
const togglePassword = document.getElementById('togglePassword');
const strengthMeter = document.getElementById('strengthMeter');
const strengthStatus = document.getElementById('strengthStatus');
const strengthBar = document.getElementById('strengthBar');
const matchText = document.getElementById('password-match');
const requirements = {
    length: document.getElementById('req-length'),
    uppercase: document.getElementById('req-uppercase'),
    lowercase: document.getElementById('req-lowercase'),
    number: document.getElementById('req-number'),
    special: document.getElementById('req-special')
};

// Toggle Password Visibility
if (togglePassword) {
    togglePassword.addEventListener('click', function () {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
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
    // Width: 20% per point (max 5)
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

if (passwordInput) {
    passwordInput.addEventListener('input', () => {
        const val = passwordInput.value;

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

if (confirmPasswordInput) {
    confirmPasswordInput.addEventListener('input', checkMatch);
}

function checkMatch() {
    const pass = passwordInput.value;
    const confirm = confirmPasswordInput.value;

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

const regForm = document.getElementById('registerForm');
if (regForm) {
    regForm.addEventListener('submit', async function (e) {
        e.preventDefault();

        const pass = passwordInput.value;
        const confirm = confirmPasswordInput.value;
        const score = calculateStrength(pass);

        if (pass !== confirm) {
            alert("Passwords do not match!");
            return;
        }

        // NIST Enforcement: Block if Weak (Score <= 2 or Blacklisted)
        if (score <= 2) {
            alert("Password is too weak. Please meet more requirements (Length, Uppercase, Lowercase, Number, Special).");
            return;
        }

        const formData = {
            full_name: document.getElementById('full_name').value,
            username: document.getElementById('username').value,
            email: document.getElementById('email').value,
            phone_number: document.getElementById('phone_number').value,
            role: document.getElementById('role').value,
            password: pass
        };

        const errorMsg = document.getElementById('errorMessage');
        const successMsg = document.getElementById('successMessage');

        // Reset messages
        errorMsg.style.display = 'none';
        successMsg.style.display = 'none';

        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });

            const data = await response.json();

            if (data.success) {
                successMsg.innerText = "Registration successful! Redirecting...";
                successMsg.style.display = 'block';
                setTimeout(() => {
                    window.location.href = 'login.html';
                }, 2000);
            } else {
                errorMsg.innerText = data.message || "Registration Failed";
                errorMsg.style.display = 'block';
            }
        } catch (err) {
            console.error("Registration Error:", err);
            errorMsg.innerText = "Network Error - check console";
            errorMsg.style.display = 'block';
        }
    });
}
