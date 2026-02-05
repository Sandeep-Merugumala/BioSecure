document.getElementById('loginForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const role = document.getElementById('role').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const errorMsg = document.getElementById('errorMessage');

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, password, role })
        });

        const data = await response.json();

        if (data.success) {
            if (data.otpRequired) {
                // Hide Login, Show OTP
                document.getElementById('loginForm').style.display = 'none';
                document.getElementById('otpForm').style.display = 'block';
                document.getElementById('userId').value = data.userId;
                document.querySelector('.auth-title').innerHTML = '<i class="fas fa-shield-alt"></i> Verify Identity';

                // Show hint
                console.log(data.message);
            } else {
                window.location.href = data.redirect;
            }
        } else {
            errorMsg.innerText = data.message || "Login Failed";
            errorMsg.style.display = 'block';
        }
    } catch (err) {
        console.error("Login Error:", err);
        errorMsg.innerText = "Network Error - check console";
        errorMsg.style.display = 'block';
    }
});

document.getElementById('otpForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    const userId = document.getElementById('userId').value;
    const otp = document.getElementById('otp').value;
    const errorMsg = document.getElementById('otpErrorMessage');

    try {
        const response = await fetch('/api/verify-otp', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId, otp })
        });

        const data = await response.json();

        if (data.success) {
            window.location.href = data.redirect;
        } else {
            errorMsg.innerText = data.message || "Verification Failed";
            errorMsg.style.display = 'block';
        }
    } catch (err) {
        console.error("OTP Error:", err);
        errorMsg.innerText = "Network Error - check console";
        errorMsg.style.display = 'block';
    }
});
