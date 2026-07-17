// Initialize Analytics Chart on Page Load
document.addEventListener('DOMContentLoaded', () => {
    const ctx = document.getElementById('anomalyLineChart').getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['10:00', '10:10', '10:20', '10:30', '10:40', '10:50'],
            datasets: [{
                label: 'Anomalies Detected',
                data: [2, 5, 3, 12, 4, 8],
                borderColor: '#f85149',
                backgroundColor: 'rgba(248, 81, 73, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false
        }
    });
});

// Function to connect with AI Backend
async function startScan() {
    console.log("Starting Network Analysis...");
    
    // UI Notification
    alert("System Command: AI model is analyzing network traffic for BGP hijacking...");

    try {
        // Fetching result from the Python Flask Server
        const response = await fetch('http://127.0.0.1:5000/scan');
        const data = await response.json();

        if (data.status === "Success") {
            // Displaying the final result from the AI model
            alert(`SCAN COMPLETE!\nResult: ${data.result}\nDetails: ${data.details}`);
            console.log("AI Response:", data);
        }
    } catch (error) {
        console.error("Connection Error:", error);
        alert("CRITICAL ERROR: Backend server (app.py) is not running! Run 'python app.py' first.");
    }
}

function uploadLogs() {
    alert("System Command: Opening secure file gateway for NSL-KDD datasets...");
}