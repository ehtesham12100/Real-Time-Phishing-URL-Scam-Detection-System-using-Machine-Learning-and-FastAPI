// Phishing Detector - Frontend Logic

document.addEventListener('DOMContentLoaded', () => {
    fetchAnalytics();
    fetchHistory();
});

// Update top statistics
async function fetchAnalytics() {
    try {
        const res = await fetch('/api/analytics');
        if (!res.ok) return;
        const data = await res.json();
        const a = data.analytics;

        document.getElementById('stat-total-scans').innerText = a.total_scans;
        document.getElementById('stat-safe-count').innerText = a.safe_count;
        document.getElementById('stat-threats-count').innerText = a.phishing_count + a.suspicious_count;
        document.getElementById('stat-threat-rate').innerText = `${a.threat_rate}%`;
    } catch (e) {
        console.error("Failed to load statistics:", e);
    }
}

// Fetch scan history from SQLite
async function fetchHistory() {
    try {
        const res = await fetch('/api/history?limit=20');
        if (!res.ok) return;
        const data = await res.json();
        const tbody = document.getElementById('history-table-body');
        if (!tbody) return;

        tbody.innerHTML = '';
        if (data.scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="py-6 text-center text-slate-500 text-xs">No scans recorded yet. Enter a link above to get started.</td></tr>';
            return;
        }

        data.scans.forEach(s => {
            const tr = document.createElement('tr');
            tr.className = "hover:bg-slate-800/30 transition";

            let badgeClass = "badge-safe";
            if (s.verdict_level === 'danger') badgeClass = "badge-danger";
            else if (s.verdict_level === 'warning') badgeClass = "badge-warning";

            tr.innerHTML = `
                <td class="py-2.5 px-3 text-slate-500 font-mono">#${s.id}</td>
                <td class="py-2.5 px-3 text-slate-400 text-[11px]">${s.timestamp}</td>
                <td class="py-2.5 px-3 truncate max-w-xs text-slate-200" title="${s.url}">${s.url}</td>
                <td class="py-2.5 px-3 font-semibold ${s.verdict_level === 'danger' ? 'text-rose-400' : (s.verdict_level === 'warning' ? 'text-amber-400' : 'text-emerald-400')}">${s.risk_score}%</td>
                <td class="py-2.5 px-3"><span class="px-2 py-0.5 rounded text-xs font-medium ${badgeClass}">${s.verdict}</span></td>
                <td class="py-2.5 px-3 text-right">
                    <button type="button" onclick="inspectExtractedUrl('${s.url}')" class="text-xs px-2.5 py-1 rounded bg-slate-800 text-slate-300 hover:bg-slate-700">Check Again</button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error("Failed to load history:", e);
    }
}

async function clearHistory() {
    if (!confirm("Clear all scan history?")) return;
    try {
        await fetch('/api/clear-history', { method: 'POST' });
        fetchAnalytics();
        fetchHistory();
    } catch (e) {
        alert("Error: " + e.message);
    }
}

function exportCsv() {
    window.location.href = '/api/export-csv';
}

// Tab Switching
function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.add('hidden');
        tab.classList.remove('block');
    });

    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active-tab', 'border-b-2', 'border-blue-500', 'text-blue-400');
        btn.classList.add('text-slate-400');
    });

    const activeTab = document.getElementById(tabId);
    if (activeTab) {
        activeTab.classList.remove('hidden');
        activeTab.classList.add('block');
    }

    const activeBtn = document.getElementById(`btn-${tabId}`);
    if (activeBtn) {
        activeBtn.classList.add('active-tab', 'border-b-2', 'border-blue-500', 'text-blue-400');
        activeBtn.classList.remove('text-slate-400');
    }

    if (tabId === 'history-tab') {
        fetchHistory();
    }
}

// Preset Helpers
function fillUrl(url) {
    document.getElementById('target-url').value = url;
    document.getElementById('url-scan-form').dispatchEvent(new Event('submit'));
}

function fillTextSample(type) {
    const textarea = document.getElementById('phish-text');
    if (type === 'bank') {
        textarea.value = "URGENT: Your bank account has been locked due to suspicious activity. Please verify your login immediately within 24 hours at http://paypa1-security.com/login to prevent account suspension.";
    } else if (type === 'lottery') {
        textarea.value = "Congratulations! You have been selected to receive a $5,000 cash prize. Click here to claim your reward: http://free-bonus-claim.xyz/verify";
    } else {
        textarea.value = "Hi team, reminder that our project progress meeting is tomorrow at 10 AM in Conference Room B. See you there!";
    }
    document.getElementById('text-scan-form').dispatchEvent(new Event('submit'));
}

function fillBatchSample() {
    const textarea = document.getElementById('batch-urls');
    textarea.value = [
        "https://www.google.com",
        "https://www.github.com",
        "http://paypa1-security.com/login",
        "http://192.168.1.100/@login.bank.com",
        "https://amazon.com",
        "http://cheap-update-account.xyz/verify"
    ].join("\n");
}

// URL Scan Form
async function handleUrlScan(event) {
    event.preventDefault();
    const urlInput = document.getElementById('target-url').value.trim();
    if (!urlInput) return;

    const checkLive = document.getElementById('check-live-threat').checked;
    const loadingElem = document.getElementById('url-loading');
    const resultsElem = document.getElementById('url-results');
    const submitBtn = document.getElementById('scan-submit-btn');

    loadingElem.classList.remove('hidden');
    resultsElem.classList.add('hidden');
    submitBtn.disabled = true;

    try {
        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput, check_live_threat: checkLive })
        });

        if (!response.ok) {
            throw new Error(`Server returned error ${response.status}`);
        }

        const data = await response.json();
        renderUrlResults(data);

        fetchAnalytics();
        fetchHistory();
    } catch (err) {
        alert("Scan Error: " + err.message);
    } finally {
        loadingElem.classList.add('hidden');
        submitBtn.disabled = false;
    }
}

function renderUrlResults(data) {
    const analysis = data.analysis;
    const dns = data.dns;
    const threatIntel = data.threat_intel;
    const feats = analysis.features;

    const resultsElem = document.getElementById('url-results');
    resultsElem.classList.remove('hidden');

    const banner = document.getElementById('verdict-banner');
    const badge = document.getElementById('verdict-badge');
    const title = document.getElementById('verdict-title');
    const recommendation = document.getElementById('verdict-recommendation');
    const scoreVal = document.getElementById('risk-score-value');
    const probSubtext = document.getElementById('prob-subtext');

    scoreVal.innerText = `${analysis.risk_score}%`;
    title.innerText = analysis.verdict;
    recommendation.innerText = analysis.recommendation;

    banner.className = "border rounded-xl p-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 ";
    badge.className = "px-3 py-1 rounded-md text-xs font-bold uppercase ";

    if (analysis.verdict_level === 'danger') {
        banner.classList.add("bg-rose-950/20", "border-rose-900/50");
        badge.classList.add("badge-danger");
        scoreVal.className = "text-3xl font-extrabold text-rose-400";
        probSubtext.innerText = "High risk of phishing / fraud";
    } else if (analysis.verdict_level === 'warning') {
        banner.classList.add("bg-amber-950/20", "border-amber-900/50");
        badge.classList.add("badge-warning");
        scoreVal.className = "text-3xl font-extrabold text-amber-400";
        probSubtext.innerText = "Multiple suspicious patterns detected";
    } else {
        banner.classList.add("bg-emerald-950/20", "border-emerald-900/50");
        badge.classList.add("badge-safe");
        scoreVal.className = "text-3xl font-extrabold text-emerald-400";
        probSubtext.innerText = "Link looks normal and safe";
    }
    badge.innerText = analysis.verdict_level === 'danger' ? 'Phishing Risk' : (analysis.verdict_level === 'warning' ? 'Suspicious' : 'Safe');

    // Simple 4 indicators
    const brandElem = document.getElementById('stat-brand');
    if (feats.typosquat_flag) {
        brandElem.innerText = feats.brand_spoofed || "Yes (Fake Brand)";
        brandElem.className = "text-sm font-semibold text-rose-400 mt-1";
    } else {
        brandElem.innerText = "Clean";
        brandElem.className = "text-sm font-semibold text-emerald-400 mt-1";
    }

    const googleElem = document.getElementById('stat-google');
    if (threatIntel.flagged) {
        googleElem.innerText = "Threat Found";
        googleElem.className = "text-sm font-semibold text-rose-400 mt-1";
    } else {
        googleElem.innerText = "Clean";
        googleElem.className = "text-sm font-semibold text-emerald-400 mt-1";
    }

    const entropyElem = document.getElementById('stat-entropy');
    if (feats.domain_entropy > 3.6) {
        entropyElem.innerText = "High (Random text)";
        entropyElem.className = "text-sm font-semibold text-rose-400 mt-1";
    } else {
        entropyElem.innerText = "Normal";
        entropyElem.className = "text-sm font-semibold text-emerald-400 mt-1";
    }

    const dnsElem = document.getElementById('stat-dns');
    if (dns.resolves) {
        dnsElem.innerText = "Valid Domain";
        dnsElem.className = "text-sm font-semibold text-emerald-400 mt-1";
    } else {
        dnsElem.innerText = "Unresolved";
        dnsElem.className = "text-sm font-semibold text-amber-400 mt-1";
    }

    // Reasons list
    const contributionsList = document.getElementById('contributions-list');
    contributionsList.innerHTML = '';

    analysis.contributions.forEach(item => {
        const div = document.createElement('div');
        const isSafe = item.impact.includes("Safe");
        div.className = `p-3 rounded-lg border text-xs flex items-start space-x-2.5 ${isSafe ? 'bg-slate-900/40 border-slate-700/60 text-slate-300' : 'bg-slate-900 border-slate-700/80 text-slate-200'}`;
        
        div.innerHTML = `
            <i class="fa-solid ${isSafe ? 'fa-check text-emerald-400' : 'fa-triangle-exclamation text-amber-400'} mt-0.5"></i>
            <div>
                <span class="font-semibold text-white">${item.feature}:</span>
                <span class="text-slate-300 ml-1">${item.description}</span>
            </div>
        `;
        contributionsList.appendChild(div);
    });

    // Details table
    const tableBody = document.getElementById('raw-features-table');
    tableBody.innerHTML = '';

    const featureDefinitions = [
        { key: "has_ip", label: "IP Address in Domain", desc: "Using an IP address like 192.168.1.1 instead of a real website name" },
        { key: "count_at", label: "'@' Symbol", desc: "The @ symbol can confuse web browsers and redirect you elsewhere" },
        { key: "typosquat_flag", label: "Brand Lookalike", desc: "Checks if link mimics brands like PayPal, Google, or Apple" },
        { key: "domain_entropy", label: "Character Randomness", desc: "High randomness indicates auto-generated temporary scam links" },
        { key: "subdomains_count", label: "Subdomain Count", desc: "Multiple subdomains are often used to hide the real destination" },
        { key: "count_hyphens", label: "Hyphen Count (-)", desc: "Scammers frequently use hyphens like 'paypal-security-update'" },
        { key: "is_suspicious_tld", label: "Cheap / Risky Extension", desc: "Extensions like .xyz, .top, or .icu with high spam rates" },
        { key: "keyword_count", label: "Login / Account Keywords", desc: "Checks for words like login, verify, banking, update, or account" },
        { key: "url_length", label: "URL Length", desc: "Very long URLs designed to hide real addresses on mobile screens" }
    ];

    featureDefinitions.forEach(item => {
        const val = feats[item.key] !== undefined ? feats[item.key] : "-";
        const tr = document.createElement('tr');
        tr.className = "hover:bg-slate-800/30 transition";
        tr.innerHTML = `
            <td class="py-2 px-3 font-medium text-slate-200">${item.label}</td>
            <td class="py-2 px-3 font-mono font-semibold text-blue-400">${val}</td>
            <td class="py-2 px-3 text-slate-400">${item.desc}</td>
        `;
        tableBody.appendChild(tr);
    });

    resultsElem.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Message Scan
async function handleTextScan(event) {
    event.preventDefault();
    const text = document.getElementById('phish-text').value.trim();
    if (!text) return;

    try {
        const response = await fetch('/api/scan-text', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text: text })
        });

        const data = await response.json();
        const analysis = data.analysis;

        const results = document.getElementById('text-results');
        results.classList.remove('hidden');

        const banner = document.getElementById('text-verdict-banner');
        const badge = document.getElementById('text-verdict-badge');
        const title = document.getElementById('text-verdict-title');
        const score = document.getElementById('text-risk-score');

        score.innerText = `${analysis.risk_score}%`;
        title.innerText = analysis.verdict;

        banner.className = "border rounded-xl p-5 flex items-center justify-between ";
        badge.className = "px-2.5 py-0.5 rounded text-xs font-bold uppercase ";

        if (analysis.verdict_level === 'danger') {
            banner.classList.add("bg-rose-950/20", "border-rose-900/50");
            badge.classList.add("badge-danger");
        } else if (analysis.verdict_level === 'warning') {
            banner.classList.add("bg-amber-950/20", "border-amber-900/50");
            badge.classList.add("badge-warning");
        } else {
            banner.classList.add("bg-emerald-950/20", "border-emerald-900/50");
            badge.classList.add("badge-safe");
        }

        const urgencyList = document.getElementById('urgency-phrases-list');
        urgencyList.innerHTML = '';
        if (analysis.matched_urgency_phrases.length === 0) {
            urgencyList.innerHTML = '<li class="text-slate-500 italic">No suspicious urgency words found.</li>';
        } else {
            analysis.matched_urgency_phrases.forEach(phrase => {
                const li = document.createElement('li');
                li.className = "text-rose-300 font-medium";
                li.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-rose-400 mr-1.5"></i>"${phrase}"`;
                urgencyList.appendChild(li);
            });
        }

        const urlList = document.getElementById('extracted-urls-list');
        urlList.innerHTML = '';
        if (analysis.embedded_urls.length === 0) {
            urlList.innerHTML = '<li class="text-slate-500 italic">No links found in message.</li>';
        } else {
            analysis.embedded_urls.forEach(u => {
                const li = document.createElement('li');
                li.className = "flex items-center justify-between bg-slate-900 p-2 rounded border border-slate-700/60";
                li.innerHTML = `
                    <span class="truncate max-w-xs text-blue-300">${u}</span>
                    <button type="button" onclick="inspectExtractedUrl('${u}')" class="text-xs px-2 py-1 rounded bg-slate-800 text-blue-400 hover:bg-slate-700">Check Link</button>
                `;
                urlList.appendChild(li);
            });
        }

        results.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (err) {
        alert("Error: " + err.message);
    }
}

function inspectExtractedUrl(url) {
    switchTab('url-tab');
    document.getElementById('target-url').value = url;
    document.getElementById('url-scan-form').dispatchEvent(new Event('submit'));
}

// Batch Scan
async function handleBatchScan(event) {
    event.preventDefault();
    const raw = document.getElementById('batch-urls').value;
    const lines = raw.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    if (lines.length === 0) return;

    try {
        const response = await fetch('/api/batch-scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ urls: lines })
        });

        const data = await response.json();
        const resultsBox = document.getElementById('batch-results');
        const tbody = document.getElementById('batch-table-body');
        tbody.innerHTML = '';
        resultsBox.classList.remove('hidden');

        data.results.forEach(res => {
            const tr = document.createElement('tr');
            tr.className = "hover:bg-slate-800/30 transition";
            
            let badgeClass = "badge-safe";
            if (res.verdict_level === 'danger') badgeClass = "badge-danger";
            else if (res.verdict_level === 'warning') badgeClass = "badge-warning";

            tr.innerHTML = `
                <td class="py-2 px-3 truncate max-w-sm text-slate-200">${res.url}</td>
                <td class="py-2 px-3 font-semibold ${res.verdict_level === 'danger' ? 'text-rose-400' : (res.verdict_level === 'warning' ? 'text-amber-400' : 'text-emerald-400')}">${res.risk_score}%</td>
                <td class="py-2 px-3"><span class="px-2 py-0.5 rounded text-xs font-medium ${badgeClass}">${res.verdict}</span></td>
                <td class="py-2 px-3 text-right">
                    <button type="button" onclick="inspectExtractedUrl('${res.url}')" class="text-xs px-2 py-1 rounded bg-slate-800 text-blue-400 hover:bg-slate-700">Check</button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        resultsBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        fetchAnalytics();
        fetchHistory();
    } catch (err) {
        alert("Batch scan error: " + err.message);
    }
}
