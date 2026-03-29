/**
 * VPN vs Non-VPN Traffic Classification Dashboard
 * Vanilla JS - API calls, charts, theme, navigation
 */
(function () {
  'use strict';

  if (!localStorage.getItem('vpn_user')) {
    window.location.href = '/login';
    return;
  }
  const API_BASE = window.location.origin;
  const MAX_PREDICTION_HISTORY = 20;
  const MAX_MANUAL_HISTORY = 10;

  let predictionHistory = [];
  let liveChart = null;
  let classChart = null;
  let comparisonChart = null;
  let topIpsChart = null;
  let topPortsChart = null;
  let lastMetrics = null;
  let bulkData = null;
  let csvFile = null;
  let currentBulkFilter = 'all';
  let currentBulkSearch = '';

  let capturedFlows = [];

  const $ = (sel, ctx = document) => ctx.querySelector(sel);
  const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

  /* ---------- Theme ---------- */
  function initTheme() {
    const saved = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', saved);
    $('#themeToggle')?.setAttribute('aria-label', saved === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
  }

  function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme') || 'light';
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    $('#themeToggle')?.setAttribute('aria-label', next === 'dark' ? 'Switch to light mode' : 'Switch to dark mode');
    updateChartsTheme();
  }

  $('#themeToggle')?.addEventListener('click', toggleTheme);

  /* ---------- Auth ---------- */
  const userBadge = $('#userBadge');
  const logoutBtn = $('#logoutBtn');
  try {
    const user = JSON.parse(localStorage.getItem('vpn_user') || '{}');
    if (userBadge && user.username) userBadge.textContent = user.username;
  } catch (_) {}
  logoutBtn?.addEventListener('click', () => {
    localStorage.removeItem('vpn_user');
    window.location.href = '/login';
  });

  /* ---------- Navigation ---------- */
  function showPage(pageId) {
    $$('.page').forEach(p => p.classList.remove('active'));
    $$('.nav-item').forEach(n => n.classList.remove('active'));
    const page = $(`#page-${pageId}`);
    const nav = $(`.nav-item[data-page="${pageId}"]`);
    if (page) page.classList.add('active');
    if (nav) nav.classList.add('active');
    if (pageId === 'metrics') loadMetrics();
    if (pageId === 'overview') loadOverview();
    if (pageId === 'anomaly' && anomalyData) renderThreatDashboard(anomalyData);
    if (pageId === 'livecapture') { /* page visible */ }
    if (pageId === 'live') renderClassificationHistory();
  }

  $$('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => showPage(btn.dataset.page));
  });

  /* ---------- Toast & Notifications ---------- */
  // Base64 encoded short alarm ping
  const alertAudio = new Audio('data:audio/mp3;base64,//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq//NExAAAAANIAAAAAExBTUUzLjEwMKqqqqqqqqqqqqqqqqqqqq');
  
  if ("Notification" in window && Notification.permission !== "granted" && Notification.permission !== "denied") {
    Notification.requestPermission();
  }

  function toast(message, type = 'info') {
    const el = $('#toast');
    if (!el) return;
    el.textContent = message;
    el.className = `toast ${type}`;
    el.classList.add('show');
    
    if (type === 'error') {
      alertAudio.play().catch(e => console.log('Audio play blocked', e));
      if ("Notification" in window && Notification.permission === "granted") {
        new Notification("Critical Threat Detected", { body: message });
      }
    }
    
    setTimeout(() => el.classList.remove('show'), 3500);
  }

  /* ---------- API ---------- */
  async function apiPredict(data) {
    const res = await fetch(`${API_BASE}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  }

  async function apiPredictBulk(file) {
    const form = new FormData();
    form.append('file', file);
    const res = await fetch(`${API_BASE}/predict-bulk`, {
      method: 'POST',
      body: form
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  }

  async function apiMetrics() {
    const res = await fetch(`${API_BASE}/metrics`);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async function apiOverview() {
    const res = await fetch(`${API_BASE}/overview`);
    if (!res.ok) throw new Error('Failed to load overview');
    return res.json();
  }

  async function apiSample() {
    const res = await fetch(`${API_BASE}/sample`);
    if (!res.ok) throw new Error('Could not load sample');
    return res.json();
  }

  /* ---------- Live Classification ---------- */
  const liveForm = $('#liveForm');
  const classifyBtn = $('#classifyBtn');
  const loadSampleBtn = $('#loadSampleBtn');
  const liveResultCard = $('#liveResultCard');
  const cnnBadge = $('#cnnBadge');
  const lstmBadge = $('#lstmBadge');
  const ninBadge = $('#ninBadge');
  const cnnConf = $('#cnnConf');
  const lstmConf = $('#lstmConf');
  const ninConf = $('#ninConf');
  const liveResultExplanation = $('#liveResultExplanation');
  const classificationHistoryList = $('#classificationHistoryList');
  let realSampleData = null;  // Full feature dict from Load Real Sample

  loadSampleBtn?.addEventListener('click', async () => {
    loadSampleBtn.setAttribute('disabled', 'true');
    loadSampleBtn.textContent = 'Loading...';
    try {
      realSampleData = await apiSample();
      const visible = ['Src Port', 'Dst Port', 'Protocol', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
        'Total Length of Fwd Packet', 'Total Length of Bwd Packet', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean'];
      visible.forEach(name => {
        const inp = liveForm?.querySelector(`input[name="${name}"]`);
        if (inp) inp.value = realSampleData[name] ?? '';
      });
      toast('Loaded real traffic sample from ISCX dataset', 'success');
    } catch (err) {
      toast('Failed to load sample: ' + err.message, 'error');
    } finally {
      loadSampleBtn.removeAttribute('disabled');
      loadSampleBtn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> Load Real Sample';
    }
  });

  liveForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(liveForm);
    const FEATURE_NAMES = [
      'Src Port', 'Dst Port', 'Protocol', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
      'Total Length of Fwd Packet', 'Total Length of Bwd Packet', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean'
    ];
    let data;
    if (realSampleData) {
      data = { ...realSampleData };
      FEATURE_NAMES.forEach(name => {
        const val = formData.get(name);
        if (val !== '' && val !== null) data[name] = parseFloat(val) || 0;
      });
    } else {
      data = {};
      for (const name of FEATURE_NAMES) {
        const val = formData.get(name);
        data[name] = val !== '' ? parseFloat(val) || 0 : 0;
      }
      for (const col of getRemainingFeatureDefaults()) {
        if (!(col in data)) data[col] = 0;
      }
    }

    classifyBtn?.classList.add('loading');
    classifyBtn?.setAttribute('disabled', 'true');
    try {
      const result = await apiPredict(data);
      const preds = result.predictions || result;
      const models = ['cnn', 'lstm', 'nin'];
      const badges = [cnnBadge, lstmBadge, ninBadge];
      const confs = [cnnConf, lstmConf, ninConf];
      models.forEach((m, i) => {
        const p = preds[m] || preds[m.toUpperCase()];
        if (p) {
          badges[i].textContent = p.label;
          badges[i].className = 'result-badge ' + (p.label === 'VPN' ? 'vpn' : 'non-vpn');
          confs[i].textContent = (p.confidence * 100).toFixed(1) + '%';
        }
      });
      liveResultCard?.removeAttribute('hidden');
      const lstmP = preds.lstm || preds.LSTM;
      const vpnProb = lstmP && lstmP.label === 'VPN' ? lstmP.confidence : (lstmP ? 1 - lstmP.confidence : 0);
      predictionHistory.push(vpnProb);
      if (predictionHistory.length > MAX_PREDICTION_HISTORY) predictionHistory.shift();
      updateLiveChart();
      
      // Save history
      saveClassificationHistory(data);
      renderClassificationHistory();
      
      // Explain
      if (liveResultExplanation) {
        liveResultExplanation.innerHTML = `<strong>Analysis:</strong> ${explainPrediction(data, lstmP?.label)}`;
      }
      
      toast('CNN, LSTM, NIN predictions complete', 'success');
    } catch (err) {
      toast('Classification failed: ' + err.message, 'error');
    } finally {
      classifyBtn?.classList.remove('loading');
      classifyBtn?.removeAttribute('disabled');
    }
  });

  function getRemainingFeatureDefaults() {
    const used = [
      'Src Port', 'Dst Port', 'Protocol', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
      'Total Length of Fwd Packet', 'Total Length of Bwd Packet', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean'
    ];
    const all = [
      'Src Port', 'Dst Port', 'Protocol', 'Flow Duration', 'Total Fwd Packet', 'Total Bwd packets',
      'Total Length of Fwd Packet', 'Total Length of Bwd Packet', 'Fwd Packet Length Max', 'Fwd Packet Length Min',
      'Fwd Packet Length Mean', 'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
      'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
      'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std',
      'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
      'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
      'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Min', 'Packet Length Max', 'Packet Length Mean',
      'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
      'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
      'Average Packet Size', 'Fwd Segment Size Avg', 'Bwd Segment Size Avg', 'Fwd Bytes/Bulk Avg',
      'Fwd Packet/Bulk Avg', 'Fwd Bulk Rate Avg', 'Bwd Bytes/Bulk Avg', 'Bwd Packet/Bulk Avg', 'Bwd Bulk Rate Avg',
      'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
      'FWD Init Win Bytes', 'Bwd Init Win Bytes', 'Fwd Act Data Pkts', 'Fwd Seg Size Min', 'Active Mean',
      'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
    ];
    return all.filter(c => !used.includes(c));
  }
  
  function explainPrediction(features, label) {
    let reasons = [];
    const duration = features['Flow Duration'] || 0;
    const fwdPkts = features['Total Fwd Packet'] || 0;
    const bwdPkts = features['Total Bwd packets'] || 0;
    
    if (label === 'VPN') {
      if (duration > 100000000) reasons.push("Extremely long flow duration is typical of VPN tunnels.");
      else if (duration > 10000000) reasons.push("Long flow duration suggests an active VPN session.");
      
      if (fwdPkts > 1000 || bwdPkts > 1000) reasons.push("High packet volume is characteristic of encapsulated VPN traffic.");
      
      if (features['Flow Bytes/s'] > 10000) reasons.push("High byte transfer rate points to active streaming or file transfer over VPN.");
      
      if (reasons.length === 0) reasons.push("Deep traffic traits (packet inter-arrival times, length variance) match known VPN signatures.");
    } else {
      if (duration < 500000) reasons.push("Short flow duration is typical of standard clear-text web requests.");
      if (fwdPkts < 10 && bwdPkts < 10) reasons.push("Low packet exchange is usually seen in simple non-VPN API/DNS queries.");
      if (reasons.length === 0) reasons.push("Packet payload heuristics and timing align with standard Non-VPN baseline traffic.");
    }
    return reasons.join(' ');
  }

  function saveClassificationHistory(data) {
    try {
      let history = JSON.parse(localStorage.getItem('vpn_classification_history') || '[]');
      const entry = {
        timestamp: new Date().toISOString(),
        data: data
      };
      history.unshift(entry);
      if (history.length > MAX_MANUAL_HISTORY) {
        history = history.slice(0, MAX_MANUAL_HISTORY);
      }
      localStorage.setItem('vpn_classification_history', JSON.stringify(history));
    } catch (e) {
      console.error('Failed to save history', e);
    }
  }

  function renderClassificationHistory() {
    if (!classificationHistoryList) return;
    try {
      const history = JSON.parse(localStorage.getItem('vpn_classification_history') || '[]');
      if (history.length === 0) {
        classificationHistoryList.innerHTML = '<div style="font-size: 0.9em; color: var(--text-muted); text-align: center; padding: 20px;">No recent history</div>';
        return;
      }
      
      classificationHistoryList.innerHTML = '';
      history.forEach((item, index) => {
        const time = new Date(item.timestamp).toLocaleTimeString();
        const destPort = item.data['Dst Port'] || 'Unknown';
        const protocol = item.data['Protocol'] || 'Unknown';
        const el = document.createElement('div');
        el.style.cssText = 'padding: 8px 12px; border: 1px solid var(--border); border-radius: 4px; cursor: pointer; background: var(--bg-card); transition: background 0.2s; font-size: 0.85rem;';
        el.innerHTML = `<strong>${time}</strong><br>Dst Port: ${destPort} | Proto: ${protocol}`;
        el.addEventListener('mouseover', () => el.style.background = 'var(--bg-body)');
        el.addEventListener('mouseout', () => el.style.background = 'var(--bg-card)');
        el.addEventListener('click', () => {
          Object.keys(item.data).forEach(key => {
            const inp = liveForm?.querySelector(`input[name="${key}"]`);
            if (inp) inp.value = item.data[key];
          });
          toast('Loaded from history', 'info');
        });
        classificationHistoryList.appendChild(el);
      });
    } catch (e) {
      console.error('Failed to load history', e);
    }
  }

  function updateLiveChart() {
    const canvas = $('#liveChart');
    if (!canvas || predictionHistory.length === 0) return;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const gridColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.06)';
    const textColor = isDark ? '#94a3b8' : '#5c6370';

    if (liveChart) liveChart.destroy();
    liveChart = new Chart(canvas, {
      type: 'line',
      data: {
        labels: predictionHistory.map((_, i) => (i + 1).toString()),
        datasets: [{
          label: 'VPN Probability',
          data: predictionHistory.map(p => (p * 100).toFixed(1)),
          borderColor: '#4f46e5',
          backgroundColor: 'rgba(79, 70, 229, 0.1)',
          fill: true,
          tension: 0.3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        layout: { padding: { top: 10, right: 15, bottom: 5, left: 5 } },
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { color: gridColor },
            ticks: { color: textColor, maxTicksLimit: 10 }
          },
          y: {
            min: 0,
            max: 100,
            grid: { color: gridColor },
            ticks: { color: textColor }
          }
        }
      }
    });
  }

  function updateChartsTheme() {
    if (liveChart && predictionHistory.length > 0) updateLiveChart();
    if ($('#page-overview')?.classList?.contains('active')) loadOverview();
    if (anomalyData && $('#page-anomaly')?.classList?.contains('active')) renderThreatDashboard(anomalyData);
    if (lastMetrics) {
      const dist = lastMetrics.class_distribution || {};
      renderClassChart(dist);
      renderComparisonChart(lastMetrics);
      renderMetricsRadarChart(lastMetrics);
      renderMetricsBarChart(lastMetrics);
    }
  }

  /* ---------- CSV Upload ---------- */
  const uploadZone = $('#uploadZone');
  const csvInput = $('#csvInput');
  const previewTableWrapper = $('#previewTableWrapper');
  const previewTable = $('#previewTable');
  const runBulkBtn = $('#runBulkBtn');
  const bulkResultCard = $('#bulkResultCard');
  const bulkResultSummary = $('#bulkResultSummary');
  const bulkResultTable = $('#bulkResultTable');
  const downloadBtn = $('#downloadBtn');

  function parseCSV(text) {
    const lines = text.trim().split('\n');
    if (lines.length < 2) return null;
    const headers = lines[0].split(',').map(h => h.trim());
    const rows = [];
    for (let i = 1; i < Math.min(lines.length, 11); i++) {
      const values = lines[i].split(',').map(v => v.trim());
      const row = {};
      headers.forEach((h, j) => { row[h] = values[j] ?? ''; });
      rows.push(row);
    }
    return { headers, rows };
  }

  uploadZone?.addEventListener('click', () => csvInput?.click());
  uploadZone?.addEventListener('dragover', (e) => { e.preventDefault(); uploadZone?.classList.add('dragover'); });
  uploadZone?.addEventListener('dragleave', () => uploadZone?.classList.remove('dragover'));
  uploadZone?.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone?.classList.remove('dragover');
    const file = e.dataTransfer?.files?.[0];
    if (file?.name?.toLowerCase().endsWith('.csv')) handleFile(file);
  });

  csvInput?.addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (file) handleFile(file);
  });

  function handleFile(file) {
    csvFile = file;
    bulkData = null;
    bulkResultCard?.setAttribute('hidden', '');
    runBulkBtn?.removeAttribute('disabled');

    const reader = new FileReader();
    reader.onload = () => {
      const parsed = parseCSV(reader.result);
      if (!parsed) {
        toast('Invalid CSV format', 'error');
        return;
      }
      renderPreviewTable(parsed.headers, parsed.rows);
      previewTableWrapper?.removeAttribute('hidden');
    };
    reader.readAsText(file);
  }

  function renderPreviewTable(headers, rows) {
    if (!previewTable) return;
    let html = '<thead><tr>';
    headers.slice(0, 8).forEach(h => { html += `<th>${escapeHtml(h)}</th>`; });
    html += '</tr></thead><tbody>';
    rows.forEach(row => {
      html += '<tr>';
      headers.slice(0, 8).forEach(h => { html += `<td>${escapeHtml(String(row[h] ?? ''))}</td>`; });
      html += '</tr>';
    });
    html += '</tbody>';
    previewTable.innerHTML = html;
  }

  function escapeHtml(s) {
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
  }
  
  $('#bulkFilterSelect')?.addEventListener('change', (e) => {
    currentBulkFilter = e.target.value;
    applyBulkFilters();
  });

  $('#bulkSearchInput')?.addEventListener('input', (e) => {
    currentBulkSearch = e.target.value.toLowerCase();
    applyBulkFilters();
  });
  
  function applyBulkFilters() {
    if (!bulkData || !bulkData.data) return;
    
    const filtered = bulkData.data.filter(row => {
      // Filter by VPN/NonVPN (using LSTM prediction as primary indicator)
      if (currentBulkFilter !== 'all') {
        const pred = (row.LSTM_Prediction || row.CNN_Prediction || row.NIN_Prediction || '').toLowerCase();
        if (currentBulkFilter === 'vpn' && pred !== 'vpn') return false;
        if (currentBulkFilter === 'nonvpn' && pred !== 'non-vpn') return false;
      }
      
      // Free text search
      if (currentBulkSearch) {
        return Object.values(row).some(val => String(val).toLowerCase().includes(currentBulkSearch));
      }
      
      return true;
    });
    
    bulkResultSummary.textContent = `Showing ${filtered.length} of ${bulkData.total} rows.`;
    renderBulkResultTable(filtered);
  }

  runBulkBtn?.addEventListener('click', async () => {
    if (!csvFile) return;
    runBulkBtn.classList.add('loading');
    runBulkBtn.setAttribute('disabled', 'true');
    try {
      const result = await apiPredictBulk(csvFile);
      bulkData = result;
      currentBulkFilter = 'all';
      currentBulkSearch = '';
      if ($('#bulkFilterSelect')) $('#bulkFilterSelect').value = 'all';
      if ($('#bulkSearchInput')) $('#bulkSearchInput').value = '';
      
      applyBulkFilters();
      bulkResultCard?.removeAttribute('hidden');
      toast(`Bulk classification complete: ${result.total} rows`, 'success');
    } catch (err) {
      toast('Bulk classification failed: ' + err.message, 'error');
    } finally {
      runBulkBtn.classList.remove('loading');
      runBulkBtn.removeAttribute('disabled');
    }
  });

  function renderBulkResultTable(data) {
    if (!bulkResultTable || !data?.length) return;
    const keys = Object.keys(data[0]);
    let html = '<thead><tr>';
    keys.forEach(k => { html += `<th>${escapeHtml(k)}</th>`; });
    html += '</tr></thead><tbody>';
    data.slice(0, 50).forEach(row => {
      html += '<tr>';
      keys.forEach(k => { html += `<td>${escapeHtml(String(row[k] ?? ''))}</td>`; });
      html += '</tr>';
    });
    if (data.length > 50) {
      html += `<tr><td colspan="${keys.length}" style="text-align:center;color:var(--text-muted)">... and ${data.length - 50} more rows</td></tr>`;
    }
    html += '</tbody>';
    bulkResultTable.innerHTML = html;
  }

  downloadBtn?.addEventListener('click', () => {
    if (!bulkData?.data?.length) { toast('No data to download', 'error'); return; }
    const keys = Object.keys(bulkData.data[0]);
    const csv = [keys.join(',')].concat(
      bulkData.data.map(row => keys.map(k => {
        const v = row[k];
        const s = String(v ?? '');
        return s.includes(',') || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s;
      }).join(','))
    ).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'predictions.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
    toast('Download started', 'success');
  });

  /* ---------- Metrics Dashboard ---------- */
  function loadMetrics() {
    apiMetrics().then(renderMetrics).catch(() => {
      renderMetrics(DEFAULT_METRICS);
      toast('Using default metrics (API unavailable)', 'info');
    });
  }

  const DEFAULT_METRICS = {
    class_distribution: { VPN: 3579, 'Non-VPN': 14004 },
    cnn: { accuracy: 0.9694, precision: 0.97, recall: 0.97, f1: 0.97, confusion_matrix: [[13724, 280], [322, 3257]] },
    lstm: { accuracy: 0.9882, precision: 0.99, recall: 0.99, f1: 0.99, confusion_matrix: [[13746, 258], [72, 3507]] },
    nin: { accuracy: 0.9485, precision: 0.95, recall: 0.95, f1: 0.95, confusion_matrix: [[13670, 334], [573, 3006]] }
  };

  function renderConfusionMatrix(elId, cm) {
    const el = $(elId);
    if (!el || !Array.isArray(cm) || cm.length < 2) return;
    el.innerHTML = `
      <table class="cm-table">
        <thead>
          <tr><th></th><th>Non-VPN</th><th>VPN</th></tr>
        </thead>
        <tbody>
          <tr>
            <th>Non-VPN</th>
            <td class="tn">${cm[0][0].toLocaleString()}</td>
            <td class="fp">${cm[0][1].toLocaleString()}</td>
          </tr>
          <tr>
            <th>VPN</th>
            <td class="fn">${cm[1][0].toLocaleString()}</td>
            <td class="tp">${cm[1][1].toLocaleString()}</td>
          </tr>
        </tbody>
      </table>
    `;
  }

  function renderMetrics(m) {
    lastMetrics = m;
    ['cnn', 'lstm', 'nin'].forEach(name => {
      const mod = m[name] || {};
      $(`#${name}Accuracy`).textContent = ((mod.accuracy || 0) * 100).toFixed(2) + '%';
      $(`#${name}Precision`).textContent = ((mod.precision || 0) * 100).toFixed(2) + '%';
      $(`#${name}Recall`).textContent = ((mod.recall || 0) * 100).toFixed(2) + '%';
      $(`#${name}F1`).textContent = ((mod.f1 || 0) * 100).toFixed(2) + '%';
      renderConfusionMatrix(`#${name}ConfusionMatrix`, mod.confusion_matrix || []);
    });
    const dist = m.class_distribution || { VPN: 0, 'Non-VPN': 0 };
    renderClassChart(dist);
    renderComparisonChart(m);
    renderMetricsRadarChart(m);
    renderMetricsBarChart(m);
  }

  function renderClassChart(dist) {
    const canvas = $('#classChart');
    if (!canvas) return;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDark ? '#94a3b8' : '#5c6370';

    if (classChart) classChart.destroy();
    classChart = new Chart(canvas, {
      type: 'bar',
      data: {
        labels: ['VPN', 'Non-VPN'],
        datasets: [{
          label: 'Count',
          data: [dist.VPN ?? 0, dist['Non-VPN'] ?? 0],
          backgroundColor: ['#ef4444', '#10b981'],
          borderWidth: 0
        }]
      },
      options: {
        responsive: true,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: { ticks: { color: textColor } },
          y: { ticks: { color: textColor } }
        }
      }
    });
  }

  function renderComparisonChart(m) {
    const canvas = $('#comparisonChart');
    if (!canvas) return;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDark ? '#94a3b8' : '#5c6370';
    const acc = [m.cnn?.accuracy || 0, m.lstm?.accuracy || 0, m.nin?.accuracy || 0].map(v => Number((v * 100).toFixed(1)));
    if (comparisonChart) comparisonChart.destroy();
    comparisonChart = new Chart(canvas, {
      type: 'bar',
      data: {
        labels: ['CNN', 'LSTM', 'NIN'],
        datasets: [{ label: 'Accuracy %', data: acc, backgroundColor: ['#6366f1', '#4f46e5', '#818cf8'] }]
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: textColor } },
          y: { min: 90, max: 100, ticks: { color: textColor } }
        }
      }
    });
  }

  let metricsRadarChart = null;
  let metricsBarChart = null;

  function renderMetricsRadarChart(m) {
    const canvas = $('#metricsRadarChart');
    if (!canvas) return;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDark ? '#94a3b8' : '#5c6370';
    const labels = ['Accuracy', 'Precision', 'Recall', 'F1'];
    const toPct = v => v ? Number((v * 100).toFixed(1)) : 0;
    if (metricsRadarChart) metricsRadarChart.destroy();
    metricsRadarChart = new Chart(canvas, {
      type: 'radar',
      data: {
        labels,
        datasets: [
          { label: 'CNN', data: [toPct(m.cnn?.accuracy), toPct(m.cnn?.precision), toPct(m.cnn?.recall), toPct(m.cnn?.f1)], borderColor: '#6366f1', backgroundColor: 'rgba(99,102,241,0.2)' },
          { label: 'LSTM', data: [toPct(m.lstm?.accuracy), toPct(m.lstm?.precision), toPct(m.lstm?.recall), toPct(m.lstm?.f1)], borderColor: '#4f46e5', backgroundColor: 'rgba(79,70,229,0.2)' },
          { label: 'NIN', data: [toPct(m.nin?.accuracy), toPct(m.nin?.precision), toPct(m.nin?.recall), toPct(m.nin?.f1)], borderColor: '#818cf8', backgroundColor: 'rgba(129,140,248,0.2)' }
        ]
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: textColor } } },
        scales: { r: { ticks: { color: textColor }, pointLabels: { color: textColor } } }
      }
    });
  }

  function renderMetricsBarChart(m) {
    const canvas = $('#metricsBarChart');
    if (!canvas) return;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDark ? '#94a3b8' : '#5c6370';
    const toPct = v => v ? Number((v * 100).toFixed(1)) : 0;
    if (metricsBarChart) metricsBarChart.destroy();
    metricsBarChart = new Chart(canvas, {
      type: 'bar',
      data: {
        labels: ['CNN', 'LSTM', 'NIN'],
        datasets: [
          { label: 'Precision', data: [toPct(m.cnn?.precision), toPct(m.lstm?.precision), toPct(m.nin?.precision)], backgroundColor: '#10b981' },
          { label: 'Recall', data: [toPct(m.cnn?.recall), toPct(m.lstm?.recall), toPct(m.nin?.recall)], backgroundColor: '#f59e0b' },
          { label: 'F1', data: [toPct(m.cnn?.f1), toPct(m.lstm?.f1), toPct(m.nin?.f1)], backgroundColor: '#6366f1' }
        ]
      },
      options: {
        responsive: true,
        plugins: { legend: { labels: { color: textColor } } },
        scales: {
          x: { ticks: { color: textColor } },
          y: { min: 90, max: 100, ticks: { color: textColor } }
        }
      }
    });
  }

  /* ---------- Live Capture ---------- */
  let liveCaptureInterval = null;
  let liveCaptureCount = 0;
  const LIVE_CAPTURE_INTERVAL_MS = 2500;
  const liveCaptureStartBtn = $('#liveCaptureStart');
  const liveCaptureStopBtn = $('#liveCaptureStop');
  const liveCaptureStats = $('#liveCaptureStats');
  const liveCaptureList = $('#liveCaptureList');
  const liveCaptureResultCard = $('#liveCaptureResultCard');
  const liveCaptureResult = $('#liveCaptureResult');

  // Matrix Mode
  const matrixToggleBtn = $('#matrixToggleBtn');
  matrixToggleBtn?.addEventListener('click', () => {
    const streamContainer = $('.live-capture-stream');
    if (streamContainer) {
      streamContainer.classList.toggle('matrix-mode');
      const isMatrix = streamContainer.classList.contains('matrix-mode');
      matrixToggleBtn.style.color = isMatrix ? '#000' : '#10b981';
      matrixToggleBtn.style.backgroundColor = isMatrix ? '#10b981' : 'transparent';
      matrixToggleBtn.textContent = isMatrix ? 'Terminal Active' : 'Matrix Mode';
    }
  });

  // Hex Dump Modal
  const hexModal = $('#hexModal');
  const hexModalClose = $('#hexModalClose');
  const hexDumpContainer = $('#hexDumpContainer');
  const hexModalFlowInfo = $('#hexModalFlowInfo');
  const hexModalProtocol = $('#hexModalProtocol');
  
  hexModalClose?.addEventListener('click', () => {
    hexModal?.setAttribute('hidden', 'true');
  });

  function showHexDump(sample) {
    if (!hexModal) return;
    const src = sample['Src IP'] ?? sample.Src_IP ?? 'Unknown';
    const dst = sample['Dst IP'] ?? sample.Dst_IP ?? 'Unknown';
    const protoRaw = String(sample['Protocol'] || 'Unknown');
    let proto = protoRaw;
    if (protoRaw === '6') proto = 'TCP';
    else if (protoRaw === '17') proto = 'UDP';
    else if (protoRaw === '1' || protoRaw === '58') proto = 'ICMP';
    
    hexModalFlowInfo.textContent = `${src}:${sample['Src Port'] || '*'}  →  ${dst}:${sample['Dst Port'] || '*'}`;
    hexModalProtocol.textContent = `PROTO: ${proto}`;
    
    let hex = '';
    const lines = 12 + Math.floor(Math.random() * 8);
    for (let i = 0; i < lines; i++) {
      let offset = i.toString(16).padStart(4, '0') + '0  ';
      let bytes = '';
      let ascii = '';
      for (let j = 0; j < 16; j++) {
        const val = Math.floor(Math.random() * 256);
        bytes += val.toString(16).padStart(2, '0') + ' ';
        ascii += (val >= 32 && val <= 126) ? String.fromCharCode(val) : '.';
      }
      hex += offset + bytes + ' |' + ascii + '|\\n';
    }
    hexDumpContainer.textContent = hex;
    hexModal.removeAttribute('hidden');
  }

  async function streamFlow() {
    try {
      const sample = await apiSample();
      liveCaptureCount++;
      if (liveCaptureStats) liveCaptureStats.textContent = liveCaptureCount + ' flows in stream';
      
      const src = sample['Src IP'] ?? sample.Src_IP ?? '—';
      const dst = sample['Dst IP'] ?? sample.Dst_IP ?? '—';
      const sport = sample['Src Port'] ?? sample['Src Port'] ?? '—';
      const dport = sample['Dst Port'] ?? sample['Dst Port'] ?? '—';
      const time = new Date().toLocaleTimeString();
      const esc = s => { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; };

      const row = document.createElement('div');
      row.className = 'live-capture-item';
      row.dataset.flow = JSON.stringify(sample);
      
      row.innerHTML = `<span class="live-capture-time">${esc(time)}</span>
        <span class="live-capture-flow" style="display: flex; gap: 8px;">
          <span>${esc(src)}</span><span style="color:var(--text-muted)">:</span><span style="color:var(--cyan)">${esc(sport)}</span>
          <span style="color:var(--text-muted)">→</span>
          <span>${esc(dst)}</span><span style="color:var(--text-muted)">:</span><span style="color:var(--cyan)">${esc(dport)}</span>
        </span>
        <button class="btn btn-primary btn-sm live-capture-btn">Capture</button>`;
      
      row.querySelector('.live-capture-btn').addEventListener('click', () => captureFlow(sample, row));
      row.addEventListener('click', (e) => {
        if (e.target.tagName !== 'BUTTON') showHexDump(sample);
      });
      row.style.cursor = 'pointer';

      // Apply search filter if active
      const searchVal = $('#liveCaptureSearch')?.value.toLowerCase().trim() || '';
      if (searchVal && !row.textContent.toLowerCase().includes(searchVal)) {
        row.style.display = 'none';
      }

      liveCaptureList?.insertBefore(row, liveCaptureList.firstChild);
      const maxItems = 50;
      while (liveCaptureList?.children.length > maxItems) liveCaptureList.removeChild(liveCaptureList.lastChild);

    } catch (err) {
      toast('Stream failed: ' + err.message, 'error');
    }
  }

  const liveCaptureExplanation = $('#liveCaptureExplanation');

  async function captureFlow(sample, rowEl) {
    const btn = rowEl?.querySelector('.live-capture-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Classifying...'; }
    try {
      const result = await apiPredict(sample);
      const cnn = result.predictions?.cnn ?? {};
      const lstm = result.predictions?.lstm ?? {};
      const nin = result.predictions?.nin ?? {};
      const esc = s => { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; };
      
      const getBadgeClass = (label) => label === 'VPN' ? 'vpn' : 'non-vpn';

      liveCaptureResult.innerHTML = `
        <div class="model-results compact" style="margin-bottom: 15px;">
          <div class="model-result"><span class="model-name">CNN</span><span class="result-badge ${getBadgeClass(cnn.label)}">${esc(cnn.label || '—')}</span><span class="result-confidence">${((cnn.confidence || 0) * 100).toFixed(1)}%</span></div>
          <div class="model-result"><span class="model-name">LSTM</span><span class="result-badge ${getBadgeClass(lstm.label)}">${esc(lstm.label || '—')}</span><span class="result-confidence">${((lstm.confidence || 0) * 100).toFixed(1)}%</span></div>
          <div class="model-result"><span class="model-name">NIN</span><span class="result-badge ${getBadgeClass(nin.label)}">${esc(nin.label || '—')}</span><span class="result-confidence">${((nin.confidence || 0) * 100).toFixed(1)}%</span></div>
        </div>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 8px; font-size: 0.85em; color: var(--text-muted); background: var(--bg-body); padding: 12px; border-radius: 6px; border: 1px solid var(--border);">
          <div><strong>Src Port:</strong> ${esc(sample['Src Port'] ?? '—')}</div>
          <div><strong>Dst Port:</strong> ${esc(sample['Dst Port'] ?? '—')}</div>
          <div><strong>Protocol:</strong> ${esc(sample['Protocol'] ?? '—')}</div>
          <div><strong>Flow Duration:</strong> ${sample['Flow Duration'] ? (sample['Flow Duration'] / 1000).toFixed(2) + ' ms' : '—'}</div>
          <div><strong>Avg Packet Size:</strong> ${sample['Average Packet Size'] ? sample['Average Packet Size'].toFixed(2) + ' B' : '—'}</div>
          <div><strong>Total Fwd Pkts:</strong> ${esc(sample['Total Fwd Packet'] ?? '—')}</div>
        </div>`;
      
      liveCaptureResultCard?.removeAttribute('hidden');
      
      if (liveCaptureExplanation) {
        liveCaptureExplanation.innerHTML = `<strong>Analysis:</strong> ${explainPrediction(sample, lstm?.label)}`;
      }
      
      // Calculate max confidence across all 3 models
      const maxConf = Math.max(cnn.confidence || 0, lstm.confidence || 0, nin.confidence || 0) * 100;
      const threshold = parseInt($('#confidenceThreshold')?.value || '0', 10);
      
      if (maxConf < threshold) {
         toast(`Prediction confidence (${maxConf.toFixed(0)}%) below threshold. Flow ignored.`, 'info');
         if (btn) { btn.textContent = 'Capture'; btn.disabled = false; btn.classList.remove('captured'); }
         return; // Abort saving
      }

      // Track captured flow
      capturedFlows.push({
        ...sample,
        CNN_Prediction: cnn.label,
        CNN_Confidence: cnn.confidence,
        LSTM_Prediction: lstm.label,
        LSTM_Confidence: lstm.confidence,
        NIN_Prediction: nin.label,
        NIN_Confidence: nin.confidence
      });
      
      // Auto-update real-time charts if toggle is active
      const dsSwitch = $('#dataSourceSwitch');
      if (dsSwitch && dsSwitch.checked && $('#page-overview')?.classList?.contains('active')) {
         updateRealTimeOverview();
      }
      
      if (btn) { btn.textContent = 'Captured'; btn.classList.add('captured'); }
      toast('Classification complete', 'success');
    } catch (err) {
      toast('Classification failed: ' + err.message, 'error');
      if (btn) { btn.disabled = false; btn.textContent = 'Capture'; }
    }
  }

  liveCaptureStartBtn?.addEventListener('click', () => {
    liveCaptureStartBtn.classList.add('loading');
    liveCaptureStartBtn.setAttribute('disabled', 'true');
    liveCaptureStopBtn?.removeAttribute('disabled');
    liveCaptureCount = 0;
    if (liveCaptureStats) liveCaptureStats.textContent = '0 flows in stream';
    liveCaptureInterval = setInterval(streamFlow, LIVE_CAPTURE_INTERVAL_MS);
    streamFlow();
  });

  liveCaptureStopBtn?.addEventListener('click', () => {
    if (liveCaptureInterval) clearInterval(liveCaptureInterval);
    liveCaptureInterval = null;
    liveCaptureStartBtn?.classList.remove('loading');
    liveCaptureStartBtn?.removeAttribute('disabled');
    liveCaptureStopBtn?.setAttribute('disabled', 'true');
  });
  
  $('#downloadCaptureBtn')?.addEventListener('click', () => {
    if (capturedFlows.length === 0) {
      toast('No flows captured yet', 'info');
      return;
    }
    const keys = Object.keys(capturedFlows[0]);
    const csv = [keys.join(',')].concat(
      capturedFlows.map(row => keys.map(k => {
        const v = row[k];
        const s = String(v ?? '');
        return s.includes(',') || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s;
      }).join(','))
    ).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'live_captures.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
    toast('Download started', 'success');
  });

  $('#clearCaptureBtn')?.addEventListener('click', () => {
    capturedFlows.length = 0; // Empty the array cleanly
    liveCaptureCount = 0;
    if (liveCaptureStats) liveCaptureStats.textContent = '0 flows in stream';
    if (liveCaptureList) liveCaptureList.innerHTML = '';
    if (liveCaptureResult) liveCaptureResult.innerHTML = '';
    if (liveCaptureExplanation) liveCaptureExplanation.innerHTML = '';
    liveCaptureResultCard?.setAttribute('hidden', 'true');
    // Force view updates
    if ($('#dataSourceSwitch')?.checked) {
       updateRealTimeOverview();
    }
    toast('Capture history cleared', 'success');
  });

  $('#liveCaptureSearch')?.addEventListener('input', (e) => {
    const val = e.target.value.toLowerCase().trim();
    const rows = liveCaptureList?.querySelectorAll('.live-capture-item');
    rows?.forEach(row => {
      row.style.display = (!val || row.textContent.toLowerCase().includes(val)) ? 'flex' : 'none';
    });
  });

  const confSlider = $('#confidenceThreshold');
  const confValue = $('#confidenceThresholdValue');
  if (confSlider && confValue) {
      confSlider.addEventListener('input', (e) => {
          confValue.textContent = e.target.value + '%';
      });
  }

  /* ---------- Threat & Anomaly Detection ---------- */
  let anomalyFile = null;
  let anomalyData = null;
  let anomalyTimelineChart = null;
  const anomalyUploadZone = $('#anomalyUploadZone');
  const anomalyCsvInput = $('#anomalyCsvInput');
  const runAnomalyBtn = $('#runAnomalyBtn');
  const threatUploadCard = $('#threatUploadCard');
  const threatDashboard = $('#threatDashboard');
  const anomalyList = $('#anomalyList');
  const downloadAnomalyBtn = $('#downloadAnomalyBtn');
  const newAnomalyBtn = $('#newAnomalyBtn');

  function getFlowType(row) {
    const pred = row.CNN_Pred || row.LSTM_Pred || row.NIN_Pred || '';
    const label = (row.Label || '').toString().toUpperCase();
    const base = pred === 'VPN' ? 'VPN' : 'NonVPN';
    let suffix = 'Flow';
    if (label.includes('STREAMING')) suffix = 'Streaming';
    else if (label.includes('BROWS') || label.includes('BROWSE')) suffix = 'Browsing';
    else if (label.includes('FILE') || label.includes('TRANSFER')) suffix = 'File Transfer';
    else if (label.includes('VOIP') || label.includes('VOICE') || label.includes('AUDIO')) suffix = 'Streaming';
    else if (label.includes('GAMING') || label.includes('GAME')) suffix = 'Gaming';
    return base + '_' + suffix + ' Flow';
  }

  function getFlowId(row) {
    const id = row['Flow ID'] ?? row.Flow_ID ?? '';
    const s = String(id);
    return s.length > 8 ? s.slice(0, 8) + '...' : s;
  }

  function getTarget(row) {
    if (!row) return '—';
    const v = row['Dst IP'] ?? row.Dst_IP ?? row['Destination IP'] ?? row.Destination;
    if (v != null && String(v).trim()) return String(v);
    const keys = Object.keys(row);
    const dstKey = keys.find(k => /dst|destination/i.test(k) && /ip|addr/i.test(k));
    if (dstKey && row[dstKey] != null) return String(row[dstKey]);
    return '—';
  }

  function getConfidence(row) {
    const c = row.CNN_Conf ?? row.LSTM_Conf ?? row.NIN_Conf ?? 0;
    const confs = [row.CNN_Conf, row.LSTM_Conf, row.NIN_Conf].filter(x => x != null);
    const minConf = confs.length ? Math.min(...confs) : c;
    return (minConf * 100).toFixed(1);
  }

  function renderThreatDashboard(data) {
    if (!threatDashboard) return;
    threatUploadCard?.setAttribute('hidden', '');
    threatDashboard.removeAttribute('hidden');

    const total = data.total || 1;
    const count = data.anomaly_count ?? 0;
    const threatPct = Math.min(100, Math.round((count / total) * 100));

    const gaugeFill = $('#threatGaugeFill');
    const gaugeValue = $('#threatGaugeValue');
    const gaugeLabel = $('#threatGaugeLabel');
    if (gaugeFill) gaugeFill.style.height = threatPct + '%';
    if (gaugeValue) gaugeValue.textContent = threatPct + '%';
    if (gaugeLabel) gaugeLabel.textContent = threatPct >= 50 ? 'ELEVATED' : threatPct >= 20 ? 'MODERATE' : 'NORMAL';

    const times = ['10:00', '10:15', '10:30', '10:45', '11:00', '11:15'];
    const n = times.length;
    const timelineData = new Array(n).fill(0);
    const anomalies = data.anomalies || [];
    anomalies.forEach((_, i) => {
      const idx = Math.min(Math.floor((i / Math.max(1, anomalies.length)) * n), n - 1);
      timelineData[idx]++;
    });
    if (timelineData.every(x => x === 0) && anomalies.length > 0) timelineData[Math.floor(n / 2)] = anomalies.length;

    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDark ? '#94a3b8' : '#5c6370';
    const gridColor = isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';

    if (anomalyTimelineChart) anomalyTimelineChart.destroy();
    const timelineCanvas = $('#anomalyTimelineChart');
    if (timelineCanvas) {
      anomalyTimelineChart = new Chart(timelineCanvas, {
        type: 'line',
        data: {
          labels: times,
          datasets: [{
            label: 'Anomaly Events',
            data: timelineData,
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239, 68, 68, 0.2)',
            fill: true,
            tension: 0.3
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: gridColor }, ticks: { color: textColor } },
            y: { grid: { color: gridColor }, ticks: { color: textColor }, beginAtZero: true }
          }
        }
      });
    }

    const esc = s => { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; };
    const items = (anomalies.slice(0, 50) || []).map(row => {
      const flowType = esc(getFlowType(row));
      const id = esc(getFlowId(row));
      const target = esc(getTarget(row));
      const conf = getConfidence(row);
      const mitigation = esc(row.Mitigation_Strategy || 'Monitor endpoint activity and log for further behavioral analysis.');
      return `<div class="anomaly-item">
        <span class="anomaly-item-icon"></span>
        <span class="anomaly-item-flow">${flowType}</span>
        <span class="anomaly-item-id">${id}</span>
        <span class="anomaly-item-target">Target: ${target}</span>
        <span class="anomaly-item-risk">HIGH RISK</span>
        <span class="anomaly-item-confidence">${conf}% Confidence</span>
        <div class="anomaly-item-mitigation" style="flex-basis: 100%; margin-top: 8px; font-size: 0.82em; color: var(--warning); font-family: 'JetBrains Mono', monospace; border-top: 1px dashed rgba(255, 184, 0, 0.2); padding-top: 8px;">
          <strong>Mitigation:</strong> ${mitigation}
        </div>
      </div>`;
    }).join('');
    anomalyList.innerHTML = items || '<p class="anomaly-empty">No critical anomalies detected.</p>';
  }

  function updateAnomalyUploadUI() {
    const text = $('#anomalyUploadText');
    const fn = $('#anomalyFileName');
    if (anomalyFile) {
      if (text) text.textContent = 'Selected:';
      if (fn) { fn.textContent = anomalyFile.name; fn.removeAttribute('hidden'); }
      anomalyUploadZone?.classList.add('has-file');
    } else {
      if (text) text.textContent = 'Drop CSV file here or click to browse';
      if (fn) { fn.textContent = ''; fn.setAttribute('hidden', ''); }
      anomalyUploadZone?.classList.remove('has-file');
    }
  }

  anomalyUploadZone?.addEventListener('click', () => anomalyCsvInput?.click());
  anomalyUploadZone?.addEventListener('dragover', (e) => { e.preventDefault(); anomalyUploadZone?.classList.add('dragover'); });
  anomalyUploadZone?.addEventListener('dragleave', () => anomalyUploadZone?.classList.remove('dragover'));
  anomalyUploadZone?.addEventListener('drop', (e) => {
    e.preventDefault();
    anomalyUploadZone?.classList.remove('dragover');
    const file = e.dataTransfer?.files?.[0];
    if (file?.name?.toLowerCase().endsWith('.csv')) { anomalyFile = file; runAnomalyBtn?.removeAttribute('disabled'); updateAnomalyUploadUI(); }
  });
  anomalyCsvInput?.addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (file) { anomalyFile = file; runAnomalyBtn?.removeAttribute('disabled'); updateAnomalyUploadUI(); }
  });

  runAnomalyBtn?.addEventListener('click', async () => {
    if (!anomalyFile) return;
    runAnomalyBtn.classList.add('loading');
    runAnomalyBtn.setAttribute('disabled', 'true');
    try {
      const form = new FormData();
      form.append('file', anomalyFile);
      const res = await fetch(`${API_BASE}/detect-anomalies`, { method: 'POST', body: form });
      if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || 'Failed');
      anomalyData = await res.json();
      renderThreatDashboard(anomalyData);
      toast(`Found ${anomalyData.anomaly_count} anomalies`, 'success');
    } catch (err) {
      toast('Anomaly detection failed: ' + err.message, 'error');
    } finally {
      runAnomalyBtn.classList.remove('loading');
      runAnomalyBtn.removeAttribute('disabled');
    }
  });

  newAnomalyBtn?.addEventListener('click', () => {
    anomalyData = null;
    anomalyFile = null;
    anomalyCsvInput.value = '';
    runAnomalyBtn?.setAttribute('disabled', 'true');
    threatDashboard?.setAttribute('hidden', '');
    threatUploadCard?.removeAttribute('hidden');
    updateAnomalyUploadUI();
  });

  downloadAnomalyBtn?.addEventListener('click', () => {
    if (!anomalyData?.anomalies?.length) { toast('No anomalies to download', 'error'); return; }
    const keys = Object.keys(anomalyData.anomalies[0]);
    const csv = [keys.join(',')].concat(anomalyData.anomalies.map(row => keys.map(k => {
      const v = row[k];
      const s = String(v ?? '');
      return s.includes(',') || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s;
    }).join(','))).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'anomalies.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
    toast('Download started', 'success');
  });

  /* ---------- System Overview ---------- */
  let flowDensityChart = null;
  let trafficDistChart = null;
  let trafficTypeChart = null;
  let protocolDistChart = null;

  let lastOverviewData = null;

  function loadOverview() {
    const dataSourceSwitch = $('#dataSourceSwitch');
    if (dataSourceSwitch && dataSourceSwitch.checked) {
      updateRealTimeOverview();
      return;
    }
    
    apiOverview().then(d => { lastOverviewData = d; renderOverview(d); }).catch(() => {
      lastOverviewData = null;
      renderOverview({ total_flows: 0, vpn_percent: 0, non_vpn_percent: 0, anomalies: null, flow_density: [], traffic_types: {} });
      toast('Overview unavailable. Ensure ISCX_Data.csv exists and API is running.', 'error');
    });
  }

  function updateRealTimeOverview() {
    if (capturedFlows.length === 0) {
      const emptyData = { total_flows: 0, vpn_percent: 0, non_vpn_percent: 0, anomalies: 0, flow_density: Array(12).fill(0), traffic_types: {}, top_ips: {}, top_ports: {}, top_protocols: {} };
      lastOverviewData = emptyData;
      renderOverview(emptyData);
      return;
    }

    let vpnCount = 0;
    const trafficTypes = {};
    const topIps = {};
    const topPorts = {};
    const topProtocols = {};

    capturedFlows.forEach(flow => {
      // If ANY of the three models flag this as VPN, track it as VPN traffic.
      const isVpn = flow.CNN_Prediction === 'VPN' || flow.LSTM_Prediction === 'VPN' || flow.NIN_Prediction === 'VPN';
      if (isVpn) vpnCount++;
      
      const type = isVpn ? 'Streaming (VPN)' : 'Browsing';
      trafficTypes[type] = (trafficTypes[type] || 0) + 1;
      
      const ip = flow['Dst IP'] || flow['Dst_IP'] || 'Unknown';
      topIps[ip] = (topIps[ip] || 0) + 1;
      
      const port = flow['Dst Port'] || flow['Dst_Port'] || 'Unknown';
      topPorts[port] = (topPorts[port] || 0) + 1;
      
      const rawProto = String(flow['Protocol'] || 'Unknown');
      let protoName = rawProto;
      if (rawProto === '6') protoName = 'TCP';
      else if (rawProto === '17') protoName = 'UDP';
      else if (rawProto === '1' || rawProto === '58') protoName = 'ICMP';
      topProtocols[protoName] = (topProtocols[protoName] || 0) + 1;
    });

    // Sort Top IPs & Ports
    const sortedIps = Object.fromEntries(Object.entries(topIps).sort(([,a],[,b]) => b-a).slice(0, 5));
    const sortedPorts = Object.fromEntries(Object.entries(topPorts).sort(([,a],[,b]) => b-a).slice(0, 5));

    // Simple pseudo flow-density (just spreading recent capture counts for visual effect)
    const density = Array(12).fill(0);
    const chunk = Math.max(1, Math.floor(capturedFlows.length / 12));
    for (let i = 0; i < capturedFlows.length; i++) {
       const bucket = Math.min(11, Math.floor(i / chunk));
       density[bucket]++;
    }

    // Generate real-time labels (last 12 captures or minutes)
    const timeLabels = [];
    const now = new Date();
    for (let i = 11; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 60000); // Past 12 mins
      timeLabels.push(d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
    }

    const realTimeData = {
      total_flows: capturedFlows.length,
      vpn_percent: Math.round((vpnCount / capturedFlows.length) * 100) || 0,
      non_vpn_percent: 100 - (Math.round((vpnCount / capturedFlows.length) * 100) || 0),
      anomalies: 0,
      flow_density: density,
      time_labels: timeLabels,
      traffic_types: trafficTypes,
      top_ips: sortedIps,
      top_ports: sortedPorts
    };

    lastOverviewData = realTimeData;
    renderOverview(realTimeData);
  }

  // Handle Data Source Toggle
  let dashboardLiveInterval = null;
  let isDashboardSyncPaused = false;
  
  const pauseSyncBtn = $('#pauseSyncBtn');
  if (pauseSyncBtn) {
     pauseSyncBtn.addEventListener('click', () => {
         isDashboardSyncPaused = !isDashboardSyncPaused;
         if (isDashboardSyncPaused) {
             pauseSyncBtn.textContent = 'Resume Sync';
             pauseSyncBtn.style.color = '#f59e0b';
             pauseSyncBtn.style.borderColor = 'rgba(245,158,11,0.3)';
         } else {
             pauseSyncBtn.textContent = 'Pause Sync';
             pauseSyncBtn.removeAttribute('style');
             updateRealTimeOverview(); // immediately push
         }
     });
  }
  
  const dataSourceSwitch = $('#dataSourceSwitch');
  const dataSourceLabel = $('#dataSourceLabel');
  if (dataSourceSwitch) {
    dataSourceSwitch.addEventListener('change', (e) => {
      if (e.target.checked) {
        dataSourceLabel.textContent = 'Live Capture (Real-time)';
        if (pauseSyncBtn) pauseSyncBtn.style.display = 'inline-block';
        updateRealTimeOverview();
        
        // Start background capture so dash updates lively
        if (dashboardLiveInterval) clearInterval(dashboardLiveInterval);
        dashboardLiveInterval = setInterval(async () => {
           try {
               // Only run if active
               if (!$('#page-overview')?.classList?.contains('active') || !dataSourceSwitch.checked || isDashboardSyncPaused) return;
               
               const sample = await apiSample();
               const result = await apiPredict(sample);

               const cnnLabel = result.predictions?.cnn?.label;
               const cnnConf = result.predictions?.cnn?.confidence || 0;

               capturedFlows.push({
                 ...sample,
                 CNN_Prediction: cnnLabel,
                 CNN_Confidence: cnnConf,
                 LSTM_Prediction: result.predictions?.lstm?.label,
                 LSTM_Confidence: result.predictions?.lstm?.confidence,
                 NIN_Prediction: result.predictions?.nin?.label,
                 NIN_Confidence: result.predictions?.nin?.confidence
               });

               // Threat Alert Toast: Very confident NON-VPN traffic
               if (cnnLabel === 'NON-VPN' && cnnConf > 0.98) {
                    const targetIp = sample['Dst IP'] || sample.Dst_IP || sample.Destination || 'Unknown IP';
                    toast(`Threat Alert: Anomalous Non-VPN flow to ${targetIp} (${(cnnConf * 100).toFixed(1)}%)`, 'error');
                    
                    const orb = $('#globalThreatOrb');
                    if (orb) {
                        orb.className = 'threat-orb pulse-critical';
                        setTimeout(() => { if (orb.className.includes('critical')) orb.className = 'threat-orb pulse-normal'; }, 5000);
                    }
               } else if (cnnConf < 0.6) {
                    const orb = $('#globalThreatOrb');
                    if (orb && !orb.className.includes('critical')) {
                        orb.className = 'threat-orb pulse-warning';
                        setTimeout(() => { if (orb.className.includes('warning')) orb.className = 'threat-orb pulse-normal'; }, 5000);
                    }
               }

               if (capturedFlows.length > 200) capturedFlows.shift();
               if (!isDashboardSyncPaused) updateRealTimeOverview();
           } catch(err) {}
        }, 3000);
      } else {
        dataSourceLabel.textContent = 'ISCX Dataset';
        if (pauseSyncBtn) pauseSyncBtn.style.display = 'none';
        if (dashboardLiveInterval) {
           clearInterval(dashboardLiveInterval);
           dashboardLiveInterval = null;
        }
        loadOverview();
      }
    });
  }

  function renderOverview(data) {
    $('#totalFlows').textContent = data.total_flows?.toLocaleString() ?? '0';
    $('#vpnPercent').textContent = (data.vpn_percent ?? 0) + '%';
    $('#nonVpnPercent').textContent = (data.non_vpn_percent ?? 0) + '%';
    $('#criticalAnomalies').textContent = data.anomalies != null ? data.anomalies : '—';

    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const textColor = isDark ? '#94a3b8' : '#5c6370';
    const gridColor = isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';

    const times = data.time_labels || ['10:00', '10:05', '10:10', '10:15', '10:20', '10:25', '10:30', '10:35', '10:40', '10:45', '10:50', '10:55'];
    if (flowDensityChart) flowDensityChart.destroy();
    flowDensityChart = new Chart($('#flowDensityChart'), {
      type: 'line',
      data: {
        labels: times,
        datasets: [{
          label: 'Flow Density',
          data: data.flow_density || [],
          borderColor: '#6366f1',
          backgroundColor: 'rgba(99, 102, 241, 0.2)',
          fill: true,
          tension: 0.3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: gridColor }, ticks: { color: textColor } },
          y: { grid: { color: gridColor }, ticks: { color: textColor } }
        }
      }
    });

    const pcanvas = $('#protocolDistChart');
    if (pcanvas) {
      if (protocolDistChart) protocolDistChart.destroy();
      const protoData = data.top_protocols || { 'TCP': 100, 'UDP': 45 };
      const labels = Object.keys(protoData);
      const vals = Object.values(protoData);
      protocolDistChart = new Chart(pcanvas, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [{
            data: vals,
            backgroundColor: ['#10b981', '#f59e0b', '#8b5cf6', '#64748b'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: {
            legend: { position: 'right', labels: { color: textColor, padding: 20 } },
            tooltip: { backgroundColor: isDark ? 'rgba(15,23,42,0.95)' : 'rgba(255,255,255,0.95)', titleColor: textColor, bodyColor: textColor, borderColor: gridColor, borderWidth: 1 }
          },
          cutout: '70%'
        }
      });
    }

    const vpn = data.vpn_percent ?? 20;
    const nonVpn = data.non_vpn_percent ?? 80;
    if (trafficDistChart) trafficDistChart.destroy();
    trafficDistChart = new Chart($('#trafficDistChart'), {
      type: 'doughnut',
      data: {
        labels: ['Non-VPN Traffic', 'VPN Traffic'],
        datasets: [{ data: [nonVpn, vpn], backgroundColor: ['#6366f1', '#f59e0b'], borderWidth: 0 }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: textColor } } }
      }
    });

    const types = data.traffic_types || {};
    const labels = Object.keys(types);
    const values = Object.values(types);
    if (trafficTypeChart) trafficTypeChart.destroy();
    trafficTypeChart = new Chart($('#trafficTypeChart'), {
      type: 'bar',
      data: {
        labels,
        datasets: [{ label: 'Count', data: values, backgroundColor: ['#6366f1', '#818cf8', '#a5b4fc', '#c7d2fe', '#e0e7ff'] }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { color: gridColor }, ticks: { color: textColor } },
          y: { grid: { color: gridColor }, ticks: { color: textColor } }
        }
      }
    });

    // Top Talkers: IPs
    const ipsCanvas = $('#topIpsChart');
    if (ipsCanvas && data.top_ips) {
      if (topIpsChart) topIpsChart.destroy();
      topIpsChart = new Chart(ipsCanvas, {
        type: 'bar',
        data: {
          labels: Object.keys(data.top_ips),
          datasets: [{
            label: 'Flows',
            data: Object.values(data.top_ips),
            backgroundColor: '#f59e0b',
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: gridColor }, ticks: { color: textColor } },
            y: { grid: { color: gridColor }, ticks: { color: textColor } }
          }
        }
      });
    }

    // Top Talkers: Ports
    const portsCanvas = $('#topPortsChart');
    if (portsCanvas && data.top_ports) {
      if (topPortsChart) topPortsChart.destroy();
      topPortsChart = new Chart(portsCanvas, {
        type: 'bar',
        data: {
          labels: Object.keys(data.top_ports),
          datasets: [{
            label: 'Flows',
            data: Object.values(data.top_ports),
            backgroundColor: '#6366f1',
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: gridColor }, ticks: { color: textColor } },
            y: { grid: { color: gridColor }, ticks: { color: textColor } }
          }
        }
      });
    }
  }

  /* ---------- Model Status ---------- */
  async function checkModelStatus() {
    const badge = $('#modelBadge');
    if (!badge) return;
    try {
      const res = await fetch(`${API_BASE}/status`);
      const data = await res.json();
      if (data.loaded && data.models?.length) {
        badge.textContent = data.models.join(' | ') + ' model';
        badge.classList.add('loaded');
        badge.classList.remove('error');
      } else {
        badge.textContent = 'No model';
        badge.classList.add('error');
      }
    } catch {
      badge.textContent = 'API offline';
      badge.classList.add('error');
    }
  }

  /* ---------- Init ---------- */
  initTheme();
  checkModelStatus();
  if ($('#page-overview')?.classList?.contains('active')) loadOverview();
})();
