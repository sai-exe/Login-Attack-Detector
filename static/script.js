/**
 * LOGIN ATTACK DETECTOR — UI INTERACTIONS & CHARTS
 * Handles 3D Card Tilt, Animated Statistic Counters, Chart.js Visualizations, and UI Controls
 */

document.addEventListener("DOMContentLoaded", () => {
    initStatisticCounters();
    init3DCardTilt();
    initCharts();
    initFileInputHelper();
    initLogFilters();
});

/* ==========================================================================
   1. ANIMATED STATISTIC COUNTERS
   ========================================================================== */
function initStatisticCounters() {
    const counters = document.querySelectorAll(".counter-value");

    counters.forEach(counter => {
        const rawText = counter.getAttribute("data-target") || counter.textContent.trim().replace(/,/g, "");
        const target = parseFloat(rawText);

        if (isNaN(target)) return;

        // Cache the target value on the element
        counter.setAttribute("data-target", target);

        // Skip animation if user prefers reduced motion
        if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
            counter.textContent = target.toLocaleString();
            return;
        }

        const duration = 1000; // ms
        const startTime = performance.now();

        function update(currentTime) {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            // Ease out cubic
            const easeProgress = 1 - Math.pow(1 - progress, 3);
            const current = Math.floor(easeProgress * target);

            counter.textContent = current.toLocaleString();

            if (progress < 1) {
                requestAnimationFrame(update);
            } else {
                counter.textContent = target.toLocaleString();
            }
        }

        requestAnimationFrame(update);
    });
}

/* ==========================================================================
   2. 3D CARD TILT ON MOUSE HOVER
   ========================================================================== */
function init3DCardTilt() {
    // Disable on touchscreens or reduced motion
    if ('ontouchstart' in window || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
        return;
    }

    const tiltCards = document.querySelectorAll(".stat-card, .tilt-card, .alert-card");

    tiltCards.forEach(card => {
        card.addEventListener("mousemove", (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            const centerX = rect.width / 2;
            const centerY = rect.height / 2;

            const rotateX = ((y - centerY) / centerY) * -6; // Max 6 deg
            const rotateY = ((x - centerX) / centerX) * 6;  // Max 6 deg

            card.style.transform = `perspective(1000px) rotateX(${rotateX.toFixed(2)}deg) rotateY(${rotateY.toFixed(2)}deg) translateY(-5px)`;
        });

        card.addEventListener("mouseleave", () => {
            card.style.transform = "perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0px)";
        });
    });
}

/* ==========================================================================
   3. CHART.JS VISUALIZATIONS (LIGHT SAAS THEME)
   ========================================================================== */
function initCharts() {
    if (typeof Chart === "undefined") return;

    // Global Chart.js Light Theme Settings
    Chart.defaults.font.family = "'Plus Jakarta Sans', sans-serif";
    Chart.defaults.color = "#6B7280";

    /* Chart 1: Login Activity (Bar Chart) */
    const loginCanvas = document.getElementById("loginChart");
    if (loginCanvas) {
        const successfulEl = document.getElementById("successfulCount");
        const failedEl = document.getElementById("failedCount");

        const successful = Number(successfulEl?.getAttribute("data-target") || successfulEl?.textContent.replace(/,/g, "") || 0);
        const failed = Number(failedEl?.getAttribute("data-target") || failedEl?.textContent.replace(/,/g, "") || 0);

        new Chart(loginCanvas, {
            type: "bar",
            data: {
                labels: ["Successful Logins", "Failed Logins"],
                datasets: [{
                    label: "Attempts",
                    data: [successful, failed],
                    backgroundColor: [
                        "rgba(16, 185, 129, 0.85)", // Success Emerald
                        "rgba(239, 68, 68, 0.85)"   // Threat Red
                    ],
                    borderColor: [
                        "#10B981",
                        "#EF4444"
                    ],
                    borderWidth: 1.5,
                    borderRadius: 10,
                    borderSkipped: false,
                    maxBarThickness: 75
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: {
                    duration: 1200,
                    easing: "easeOutQuart"
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: "#1F2937",
                        titleFont: { size: 13, weight: "700" },
                        bodyFont: { size: 12, weight: "600" },
                        padding: 12,
                        cornerRadius: 8,
                        boxPadding: 6
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0,
                            color: "#9CA3AF",
                            font: { size: 11, weight: "600" }
                        },
                        grid: {
                            color: "rgba(226, 232, 240, 0.7)"
                        },
                        border: {
                            dash: [4, 4]
                        }
                    },
                    x: {
                        ticks: {
                            color: "#4B5563",
                            font: { size: 12, weight: "700" }
                        },
                        grid: {
                            display: false
                        }
                    }
                }
            }
        });
    }

    /* Chart 2: IP Risk Distribution (Doughnut Chart) */
    const riskCanvas = document.getElementById("riskDistributionChart");
    if (riskCanvas) {
        const highCount = Number(riskCanvas.dataset.high || 0);
        const mediumCount = Number(riskCanvas.dataset.medium || 0);
        const lowCount = Number(riskCanvas.dataset.low || 0);

        const totalRisks = highCount + mediumCount + lowCount;

        new Chart(riskCanvas, {
            type: "doughnut",
            data: {
                labels: ["High Risk", "Medium Risk", "Low Risk"],
                datasets: [{
                    data: totalRisks > 0 ? [highCount, mediumCount, lowCount] : [0, 0, 1],
                    backgroundColor: [
                        "#EF4444", // Threat Red
                        "#F59E0B", // Warning Orange
                        "#10B981"  // Safe Green
                    ],
                    borderWidth: 2,
                    borderColor: "#FFFFFF",
                    hoverOffset: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "68%",
                animation: {
                    duration: 1400,
                    easing: "easeOutQuart"
                },
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            boxWidth: 12,
                            padding: 14,
                            font: { size: 12, weight: "600" },
                            color: "#4B5563"
                        }
                    },
                    tooltip: {
                        backgroundColor: "#1F2937",
                        padding: 10,
                        cornerRadius: 8,
                        callbacks: {
                            label: function(context) {
                                return ` ${context.label}: ${context.raw} IPs`;
                            }
                        }
                    }
                }
            }
        });
    }
}

/* ==========================================================================
   4. FILE UPLOAD INTERACTION HELPER
   ========================================================================== */
function initFileInputHelper() {
    const fileInput = document.getElementById("csvFile");
    const fileLabel = document.getElementById("fileLabelText");

    if (fileInput && fileLabel) {
        fileInput.addEventListener("change", (e) => {
            if (e.target.files && e.target.files[0]) {
                fileLabel.textContent = `Selected: ${e.target.files[0].name}`;
                fileLabel.style.color = "#7C3AED";
                fileLabel.style.fontWeight = "700";
            }
        });
    }
}

/* ==========================================================================
   5. LOG ANALYSIS INSTANT FILTERING HELPER
   ========================================================================== */
function initLogFilters() {
    const searchInput = document.getElementById("searchInput");
    const statusFilter = document.getElementById("statusFilter");
    const tableRows = Array.from(document.querySelectorAll("#logsTable tbody tr[data-status]"));
    const recordCount = document.getElementById("recordCount");
    const noResults = document.getElementById("noResults");

    if (!searchInput || !statusFilter || tableRows.length === 0) return;

    function filterLogs() {
        const query = searchInput.value.trim().toLowerCase();
        const selectedStatus = statusFilter.value;
        let visibleCount = 0;

        tableRows.forEach(row => {
            const searchText = row.dataset.search || "";
            const status = row.dataset.status || "";

            const matchesSearch = searchText.includes(query);
            const matchesStatus = (selectedStatus === "ALL" || status === selectedStatus);

            const visible = matchesSearch && matchesStatus;
            row.hidden = !visible;
            if (visible) visibleCount++;
        });

        if (recordCount) {
            recordCount.textContent = `Showing ${visibleCount} of ${tableRows.length} records`;
        }
        if (noResults) {
            noResults.hidden = visibleCount !== 0;
        }
    }

    searchInput.addEventListener("input", filterLogs);
    statusFilter.addEventListener("change", filterLogs);
}