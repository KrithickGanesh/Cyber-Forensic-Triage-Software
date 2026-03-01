/**
 * Cyber Forensic Triage Software — Frontend JavaScript
 * Handles scan progress, interactions, and dynamic UI updates.
 */

// ─── Sidebar Toggle ───
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('open');
}

// Close sidebar on outside click (mobile)
document.addEventListener('click', (e) => {
    const sidebar = document.getElementById('sidebar');
    const menuBtn = document.querySelector('.mobile-menu-btn');
    if (sidebar && sidebar.classList.contains('open') && 
        !sidebar.contains(e.target) && !menuBtn.contains(e.target)) {
        sidebar.classList.remove('open');
    }
});

// ─── Scan Progress ───
let scanInterval = null;

function startScan(caseId) {
    const btn = document.getElementById('startScanBtn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `
            <svg class="spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20">
                <circle cx="12" cy="12" r="10" stroke-dasharray="60" stroke-dashoffset="20"/>
            </svg>
            Initializing Scan...`;
    }

    fetch(`/case/${caseId}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'started') {
            // Show progress UI
            const promptEl = document.querySelector('.scan-start-prompt');
            const progressEl = document.getElementById('scanProgress');
            if (promptEl) promptEl.style.display = 'none';
            if (progressEl) progressEl.style.display = 'block';
            
            // Start polling
            pollScanProgress(caseId);
        } else {
            alert(data.error || 'Failed to start scan');
            if (btn) {
                btn.disabled = false;
                btn.textContent = 'Start Forensic Scan';
            }
        }
    })
    .catch(err => {
        console.error('Scan start error:', err);
        alert('Failed to start scan. Please try again.');
        if (btn) {
            btn.disabled = false;
            btn.textContent = 'Start Forensic Scan';
        }
    });
}

function pollScanProgress(caseId) {
    scanInterval = setInterval(() => {
        fetch(`/case/${caseId}/scan/status`)
            .then(res => res.json())
            .then(data => {
                updateProgressUI(data);
                
                if (data.status === 'completed') {
                    clearInterval(scanInterval);
                    setTimeout(() => {
                        window.location.reload();
                    }, 1500);
                } else if (data.status === 'error') {
                    clearInterval(scanInterval);
                    alert('Scan encountered an error: ' + (data.error || 'Unknown error'));
                    window.location.reload();
                }
            })
            .catch(err => {
                console.error('Poll error:', err);
            });
    }, 1000);
}

function updateProgressUI(data) {
    // Update progress bar
    const bar = document.getElementById('progressBar');
    const text = document.getElementById('progressText');
    const percent = document.getElementById('progressPercent');
    
    if (bar) bar.style.width = `${data.progress || 0}%`;
    if (percent) percent.textContent = `${data.progress || 0}%`;
    
    if (text) {
        if (data.current_file) {
            text.textContent = `${data.step}: ${data.current_file}`;
        } else {
            text.textContent = data.step || 'Processing...';
        }
    }
    
    // Update step indicators
    const stepNum = data.step_number || 1;
    for (let i = 1; i <= 5; i++) {
        const step = document.getElementById(`step${i}`);
        if (step) {
            step.classList.remove('active', 'done');
            if (i < stepNum) {
                step.classList.add('done');
            } else if (i === stepNum) {
                step.classList.add('active');
            }
        }
    }
}

// ─── Auto-poll for active scans ───
document.addEventListener('DOMContentLoaded', () => {
    // Check if we're on a case page with an active scan
    if (typeof caseId !== 'undefined' && caseId) {
        fetch(`/case/${caseId}/scan/status`)
            .then(res => res.json())
            .then(data => {
                if (data.status === 'scanning') {
                    const promptEl = document.querySelector('.scan-start-prompt');
                    const progressEl = document.getElementById('scanProgress');
                    if (promptEl) promptEl.style.display = 'none';
                    if (progressEl) progressEl.style.display = 'block';
                    pollScanProgress(caseId);
                }
            })
            .catch(() => {});
    }
    
    // Auto-dismiss flash messages
    const flashMsgs = document.querySelectorAll('.flash-msg');
    flashMsgs.forEach(msg => {
        setTimeout(() => {
            msg.style.opacity = '0';
            msg.style.transform = 'translateY(-10px)';
            setTimeout(() => msg.remove(), 300);
        }, 5000);
    });
});

// ─── Spinner Animation CSS ───
const style = document.createElement('style');
style.textContent = `
    .spin { animation: spin 1s linear infinite; }
    @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
`;
document.head.appendChild(style);
