</main>

<div id="toast"></div>

<script>
// User dropdown menu toggle
(function() {
    var btn = document.getElementById('userMenuBtn');
    var dd = document.getElementById('userDropdown');
    if (btn && dd) {
        btn.addEventListener('click', function(e) {
            dd.style.display = dd.style.display === 'none' ? 'block' : 'none';
            e.stopPropagation();
        });
        document.addEventListener('click', function() { dd.style.display = 'none'; });
    }
})();

// Dual clock — military + civilian
function updateClocks() {
    const now = new Date();
    const h = now.getHours(), m = now.getMinutes(), s = now.getSeconds();
    const pad = n => String(n).padStart(2, '0');

    document.getElementById('clockMil').textContent = pad(h) + ':' + pad(m) + ':' + pad(s);

    const h12 = h % 12 || 12;
    const ampm = h < 12 ? 'AM' : 'PM';
    document.getElementById('clockCiv').textContent = h12 + ':' + pad(m) + ':' + pad(s) + ' ' + ampm;
}
updateClocks();
setInterval(updateClocks, 1000);

// Toast notifications
function bdToast(msg, type = 'info', duration = 4000) {
    const el = document.createElement('div');
    el.className = 'toast-msg toast-' + type;
    el.textContent = msg;
    document.getElementById('toast').appendChild(el);
    setTimeout(() => el.remove(), duration);
}

// API call wrapper
async function bdApi(method, path, data = null) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (data) opts.body = JSON.stringify(data);
    try {
        const resp = await fetch(path, opts);
        const json = await resp.json();
        if (!json.ok && json.error) bdToast(json.error, 'error');
        return json;
    } catch (e) {
        bdToast('API error: ' + e.message, 'error');
        return { ok: false, error: e.message };
    }
}

// Logout
function bdLogout() {
    bdApi('POST', '/api/logout').then(() => {
        window.location.href = '/login.php';
    });
}

// Poll WAF status
async function pollWafStatus() {
    try {
        const data = await bdApi('GET', '/api/status');
        if (data.ok) {
            const pill = document.getElementById('wafPill');
            const text = document.getElementById('wafModeText');
            const mode = data.waf_mode || 'learning';
            text.textContent = mode.toUpperCase();
            pill.className = 'waf-pill waf-' + mode;
        }
    } catch (e) {}
}
pollWafStatus();
setInterval(pollWafStatus, 10000);
</script>
</body>
</html>
