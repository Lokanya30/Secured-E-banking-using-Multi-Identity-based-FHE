document.getElementById('loginForm')?.addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent the default form submission
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message); // Show success or error message
        if (data.success) {
            // Hide login section and show post-login options
            document.getElementById('loginSection').style.display = 'none';
            document.getElementById('postLoginSection').style.display = 'block';
            document.getElementById('loggedInUser').innerText = username; // Display logged-in username
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

document.getElementById('registerForm')?.addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent the default form submission
    const username = document.getElementById('newUsername').value;
    const password = document.getElementById('newPassword').value;

    fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message); // Show success or error message
        if (data.success) {
            document.getElementById('registerSection').style.display = 'none';
            document.getElementById('loginSection').style.display = 'block';
        }
    })
    .catch(error => {
        console.error('Error:', error);
    });
});

// Show register form
document.getElementById('showRegister').addEventListener('click', function() {
    document.getElementById('loginSection').style.display = 'none';
    document.getElementById('registerSection').style.display = 'block';
});

// Show login form
document.getElementById('showLogin').addEventListener('click', function() {
    document.getElementById('registerSection').style.display = 'none';
    document.getElementById('loginSection').style.display = 'block';
});

// Logout functionality
document.getElementById('logoutButton')?.addEventListener('click', function() {
    document.getElementById('postLoginSection').style.display = 'none';
    document.getElementById('loginSection').style.display = 'block';
});