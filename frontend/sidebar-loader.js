/**
 * sidebar-loader.js
 * Include this ONE script in every page.
 * It fetches sidebar.html, injects it, then wires up
 * active-highlight + logout — because innerHTML kills <script> tags.
 */
(function () {

    fetch("sidebar.html")
        .then(res => res.text())
        .then(html => {

            // ── Inject HTML ───────────────────────────────────────
            const container = document.getElementById("sidebar-container");
            container.innerHTML = html;

            // ── Active page highlight ─────────────────────────────
            const currentPage = window.location.pathname.split("/").pop() || "dashboard.html";
            container.querySelectorAll("nav a.nav-item").forEach(link => {
                if (link.getAttribute("href") === currentPage) {
                    link.classList.add("active");
                }
            });

            // ── Logout ────────────────────────────────────────────
            const logoutBtn = document.getElementById("logoutBtn");
            if (logoutBtn) {
                logoutBtn.addEventListener("click", function () {
                    if (confirm("Are you sure you want to logout?")) {
                        localStorage.clear();
                        sessionStorage.clear();
                        window.location.href = "login.html";
                    }
                });
            }

        })
        .catch(err => console.error("Sidebar failed to load:", err));

})();