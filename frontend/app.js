const uploadPanel = document.getElementById("uploadPanel");
const input = document.getElementById("pcapInput");
const demoButton = document.getElementById("demoButton");
const loading = document.getElementById("loading");
const errorBox = document.getElementById("errorBox");
const dashboard = document.getElementById("dashboard");

input.addEventListener("change", () => {
    if (input.files.length) analyzeFile(input.files[0]);
});

demoButton.addEventListener("click", loadDemo);

["dragenter", "dragover"].forEach((eventName) => {
    uploadPanel.addEventListener(eventName, (event) => {
        event.preventDefault();
        uploadPanel.classList.add("dragging");
    });
});

["dragleave", "drop"].forEach((eventName) => {
    uploadPanel.addEventListener(eventName, (event) => {
        event.preventDefault();
        uploadPanel.classList.remove("dragging");
    });
});

uploadPanel.addEventListener("drop", (event) => {
    const file = event.dataTransfer.files[0];
    if (file) analyzeFile(file);
});

document.querySelectorAll(".nav-item").forEach((button) => {
    button.addEventListener("click", () => {
        document.querySelectorAll(".nav-item").forEach((item) => item.classList.remove("active"));
        document.querySelectorAll(".page-section").forEach((section) => section.classList.remove("active"));
        button.classList.add("active");
        document.getElementById(button.dataset.target).classList.add("active");
    });
});

async function analyzeFile(file) {
    const formData = new FormData();
    formData.append("file", file);

    setLoading(true);
    hideError();

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            body: formData,
        });
        const payload = await response.json();

        if (!response.ok) {
            throw new Error(payload.detail || "The capture could not be analyzed.");
        }

        renderDashboard(payload);
    } catch (error) {
        showError(error.message);
    } finally {
        setLoading(false);
    }
}

async function loadDemo() {
    setLoading(true);
    hideError();

    try {
        const response = await fetch("/api/demo", { method: "POST" });
        const payload = await response.json();
        renderDashboard(payload);
    } catch (error) {
        showError("The demo could not be loaded.");
    } finally {
        setLoading(false);
    }
}

function renderDashboard(data) {
    dashboard.classList.remove("hidden");
    uploadPanel.classList.add("hidden");

    document.getElementById("fileName").textContent = data.meta.filename;
    document.getElementById("duration").textContent = `${formatNumber(data.meta.duration_seconds)} seconds`;
    document.getElementById("firstSeen").textContent = formatDate(data.meta.first_seen);

    document.getElementById("packetCount").textContent = formatNumber(data.summary.packets);
    document.getElementById("deviceCount").textContent = formatNumber(data.summary.devices);
    document.getElementById("protocolCount").textContent = formatNumber(data.summary.protocols);
    document.getElementById("alertCount").textContent = formatNumber(data.summary.alerts);

    renderProtocols(data.protocols);
    renderHosts(data.top_hosts);
    renderTimeline(data.timeline);
    renderAlerts(data.alerts);
    renderConversations(data.top_conversations);
}

function renderProtocols(protocols) {
    const container = document.getElementById("protocolChart");
    container.innerHTML = "";

    if (!protocols.length) {
        container.innerHTML = `<div class="empty-state">No protocols are available to display.</div>`;
        return;
    }

    const max = Math.max(...protocols.map((item) => item.count), 1);

    protocols.slice(0, 8).forEach((item) => {
        const row = document.createElement("div");
        row.className = "bar-row";
        const width = Math.max(4, (item.count / max) * 100);

        row.innerHTML = `
            <strong>${escapeHtml(item.name)}</strong>
            <div class="bar-track">
                <div class="bar-fill" style="width:${width}%"></div>
            </div>
            <span class="bar-count">${formatNumber(item.count)}</span>
        `;
        container.appendChild(row);
    });
}

function renderHosts(hosts) {
    const container = document.getElementById("topHosts");
    container.innerHTML = "";

    if (!hosts.length) {
        container.innerHTML = `<div class="empty-state">No IP addresses were discovered.</div>`;
        return;
    }

    hosts.slice(0, 8).forEach((item) => {
        const row = document.createElement("div");
        row.className = "host-item";
        row.innerHTML = `
            <code>${escapeHtml(item.host)}</code>
            <span>${formatNumber(item.packets)} packets</span>
        `;
        container.appendChild(row);
    });
}

function renderTimeline(points) {
    const container = document.getElementById("timelineChart");
    container.innerHTML = "";

    if (!points.length) {
        container.innerHTML = `<div class="empty-state">No timeline data is available.</div>`;
        return;
    }

    const sampled = points.length > 80
        ? points.filter((_, index) => index % Math.ceil(points.length / 80) === 0)
        : points;

    const max = Math.max(...sampled.map((item) => item.packets), 1);

    sampled.forEach((item) => {
        const bar = document.createElement("div");
        bar.className = "timeline-bar";
        bar.style.height = `${Math.max(8, (item.packets / max) * 160)}px`;
        bar.title = `${formatDate(item.timestamp)} — ${formatNumber(item.packets)} packets`;
        container.appendChild(bar);
    });
}

function renderAlerts(alerts) {
    const container = document.getElementById("alertsList");
    container.innerHTML = "";

    if (!alerts.length) {
        container.innerHTML = `
            <div class="empty-state">
                No alerts were detected by the current rule set.
            </div>
        `;
        return;
    }

    alerts.forEach((alert) => {
        const card = document.createElement("article");
        card.className = `alert-card ${alert.severity}`;

        card.innerHTML = `
            <div class="alert-head">
                <div class="alert-title">
                    <strong>${escapeHtml(alert.type)}</strong>
                    <code>${escapeHtml(alert.id)}</code>
                </div>
                <span class="severity ${escapeHtml(alert.severity)}">${escapeHtml(alert.severity)}</span>
            </div>
            <p>${escapeHtml(alert.reason)}</p>
            <div class="alert-meta">
                <div>
                    <span>Source</span>
                    <strong>${escapeHtml(alert.source || "—")}</strong>
                </div>
                <div>
                    <span>Destination</span>
                    <strong>${escapeHtml(alert.destination || "—")}</strong>
                </div>
                <div>
                    <span>Confidence</span>
                    <strong>${formatNumber(alert.confidence)}%</strong>
                </div>
            </div>
        `;
        container.appendChild(card);
    });
}

function renderConversations(items) {
    const tbody = document.getElementById("conversationsTable");
    tbody.innerHTML = "";

    if (!items.length) {
        tbody.innerHTML = `<tr><td colspan="3">No conversations are available to display.</td></tr>`;
        return;
    }

    items.forEach((item) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td><code>${escapeHtml(item.source)}</code></td>
            <td><code>${escapeHtml(item.destination)}</code></td>
            <td>${formatNumber(item.packets)}</td>
        `;
        tbody.appendChild(row);
    });
}

function setLoading(isLoading) {
    loading.classList.toggle("hidden", !isLoading);
    demoButton.disabled = isLoading;
}

function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
}

function hideError() {
    errorBox.classList.add("hidden");
}

function formatNumber(value) {
    return new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 }).format(value || 0);
}

function formatDate(value) {
    if (!value) return "—";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString("en-US");
}

function escapeHtml(value) {
    return String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}
