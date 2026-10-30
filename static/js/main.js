/* ==============================================================================
   TracePoint – Client Logic & Compact Chart Visualizations
   ============================================================================== */

document.addEventListener("DOMContentLoaded", () => {
    // 1. Setup Hash Copy buttons
    document.querySelectorAll(".copy-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            const hashText = btn.getAttribute("data-hash");
            if (hashText) {
                navigator.clipboard.writeText(hashText).then(() => {
                    const originalHtml = btn.innerHTML;
                    btn.innerHTML = "✓ Copied";
                    btn.style.color = "#39805B";
                    setTimeout(() => {
                        btn.innerHTML = originalHtml;
                        btn.style.color = "";
                    }, 2000);
                });
            }
        });
    });

    // 2. Setup Modals
    document.querySelectorAll("[data-modal-open]").forEach(trigger => {
        trigger.addEventListener("click", (e) => {
            e.preventDefault();
            const modalId = trigger.getAttribute("data-modal-open");
            const modal = document.getElementById(modalId);
            if (modal) modal.classList.add("active");
        });
    });

    document.querySelectorAll("[data-modal-close]").forEach(closeBtn => {
        closeBtn.addEventListener("click", () => {
            const modal = closeBtn.closest(".modal-overlay");
            if (modal) modal.classList.remove("active");
        });
    });

    window.addEventListener("click", (e) => {
        if (e.target.classList.contains("modal-overlay")) {
            e.target.classList.remove("active");
        }
    });

    // 3. Client-side Table Search & Filters
    const searchInputs = document.querySelectorAll("[data-table-search]");
    searchInputs.forEach(input => {
        input.addEventListener("input", () => {
            const query = input.value.toLowerCase().trim();
            const targetTableId = input.getAttribute("data-table-search");
            const table = document.getElementById(targetTableId);
            if (!table) return;

            const rows = table.querySelectorAll("tbody tr");
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(query) ? "" : "none";
            });
        });
    });

    // 4. File Dropzone visual feedback
    const dropzone = document.getElementById("evidence-dropzone");
    const fileInput = document.getElementById("evidence-file-input");
    const fileSelectedLabel = document.getElementById("file-selected-label");

    if (dropzone && fileInput) {
        dropzone.addEventListener("click", () => fileInput.click());

        dropzone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropzone.classList.add("dragover");
        });

        ["dragleave", "drop"].forEach(event => {
            dropzone.addEventListener(event, (e) => {
                e.preventDefault();
                dropzone.classList.remove("dragover");
            });
        });

        dropzone.addEventListener("drop", (e) => {
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                updateFileLabel();
            }
        });

        fileInput.addEventListener("change", updateFileLabel);

        function updateFileLabel() {
            if (fileInput.files.length > 0) {
                const f = fileInput.files[0];
                const sizeMb = (f.size / (1024 * 1024)).toFixed(2);
                if (fileSelectedLabel) {
                    fileSelectedLabel.textContent = `Selected: ${f.name} (${sizeMb} MB)`;
                    fileSelectedLabel.style.color = "#416A91";
                    fileSelectedLabel.style.fontWeight = "600";
                }
            }
        }
    }

    // 5. Initialize Charts if on Dashboard
    initDashboardCharts();
});

// Helper for fill demo user on login page
function fillLogin(email, password) {
    const emailField = document.getElementById("login-email");
    const passField = document.getElementById("login-password");
    if (emailField && passField) {
        emailField.value = email;
        passField.value = password;
    }
}

// Chart.js Theme Defaults for TracePoint Institutional Light UI
function initDashboardCharts() {
    const evidenceTypeCanvas = document.getElementById("chart-evidence-types");
    const casesCanvas = document.getElementById("chart-cases-status");
    const integrityCanvas = document.getElementById("chart-integrity-status");
    const timelineCanvas = document.getElementById("chart-custody-timeline");

    if (!evidenceTypeCanvas && !casesCanvas && !integrityCanvas && !timelineCanvas) {
        return;
    }

    // Fetch dashboard stats from API endpoint
    fetch("/api/dashboard-stats")
        .then(res => res.json())
        .then(data => {
            renderEvidenceTypeChart(evidenceTypeCanvas, data.evidence_types);
            renderCasesChart(casesCanvas, data.cases_status);
            renderIntegrityChart(integrityCanvas, data.integrity_stats);
            renderCustodyTimelineChart(timelineCanvas, data.custody_timeline);
        })
        .catch(err => console.error("Error loading dashboard metrics:", err));
}

function renderEvidenceTypeChart(canvas, typeData) {
    if (!canvas || !typeData) return;
    const labels = Object.keys(typeData);
    const counts = Object.values(typeData);

    new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: labels.length ? labels : ['No Data'],
            datasets: [{
                data: counts.length ? counts : [1],
                backgroundColor: [
                    '#416A91', '#39805B', '#C28B36', '#6C5B7B',
                    '#457B9D', '#8EA4BE', '#D97706', '#94A3B8'
                ],
                borderWidth: 2,
                borderColor: '#FFFFFF'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#5A6578', boxWidth: 12, font: { size: 11, family: 'Inter' } }
                }
            },
            cutout: '65%'
        }
    });
}

function renderCasesChart(canvas, casesData) {
    if (!canvas || !casesData) return;
    const labels = Object.keys(casesData);
    const counts = Object.values(casesData);

    new Chart(canvas, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Cases',
                data: counts,
                backgroundColor: '#416A91',
                borderRadius: 4,
                maxBarThickness: 36
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    ticks: { color: '#5A6578', font: { size: 11 } },
                    grid: { display: false }
                },
                y: {
                    ticks: { color: '#5A6578', stepSize: 1, font: { size: 11 } },
                    grid: { color: '#ECEFF2' },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function renderIntegrityChart(canvas, integrityData) {
    if (!canvas || !integrityData) return;

    new Chart(canvas, {
        type: 'doughnut',
        data: {
            labels: ['Verified', 'Mismatch', 'Pending Verification'],
            datasets: [{
                data: [
                    integrityData.verified || 0,
                    integrityData.compromised || 0,
                    integrityData.pending || 0
                ],
                backgroundColor: ['#39805B', '#B84B4B', '#BAC5D5'],
                borderWidth: 2,
                borderColor: '#FFFFFF'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#5A6578', boxWidth: 12, font: { size: 11 } }
                }
            },
            cutout: '65%'
        }
    });
}

function renderCustodyTimelineChart(canvas, timelineData) {
    if (!canvas || !timelineData) return;
    const labels = timelineData.map(item => item.date);
    const counts = timelineData.map(item => item.count);

    new Chart(canvas, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Custody Transfers',
                data: counts,
                borderColor: '#416A91',
                backgroundColor: 'rgba(65, 106, 145, 0.08)',
                borderWidth: 2,
                fill: true,
                tension: 0.25,
                pointBackgroundColor: '#416A91',
                pointRadius: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    ticks: { color: '#5A6578', font: { size: 10 } },
                    grid: { display: false }
                },
                y: {
                    ticks: { color: '#5A6578', stepSize: 1, font: { size: 10 } },
                    grid: { color: '#ECEFF2' },
                    beginAtZero: true
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}
