/**
 * logout.js
 * Handles the secure termination of the user session
 */
function handleLogout() {
    // 1. Request user confirmation before proceeding
    const confirmLogout = confirm("Are you sure you want to sign out?");
    
    if (confirmLogout) {
        // 2. Clear all sensitive session and local data
        localStorage.clear();
        sessionStorage.clear();
        
        // 3. Redirect the user to the login portal immediately
        // Ensure that 'login.html' exists in the root directory
        window.location.href = "login.html";
    }
}