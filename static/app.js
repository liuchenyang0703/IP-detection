const input = document.querySelector('#networks');
const button = document.querySelector('#scanButton');
const results = document.querySelector('#results');
const emptyState = document.querySelector('#emptyState');
const summary = document.querySelector('#resultSummary');
const commandTarget = document.querySelector('#commandTarget');
const searchPanel = document.querySelector('#searchPanel');
const ipSearch = document.querySelector('#ipSearch');
const searchButton = document.querySelector('#searchButton');
const searchFeedback = document.querySelector('#searchFeedback');
const localIp = document.querySelector('#localIp');
const localNetwork = document.querySelector('#localNetwork');
const localMac = document.querySelector('#localMac');
const localInterface = document.querySelector('#localInterface');
const scanDuration = document.querySelector('#scanDuration');
const exportTools = document.querySelector('#exportTools');
const exportFormat = document.querySelector('#exportFormat');
const exportButton = document.querySelector('#exportButton');
let lastResults = [];
let visibleResults = [];
let lastNetworks = [];
let durationTimer = null;
let durationStartedAt = 0;

const escapeHtml = (value) => String(value ?? '')
  .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
  .replaceAll('"', '&quot;').replaceAll("'", '&#039;');

function getNetworks() {
  return [...new Set(input.value.split(/[\n,，]+/).map(item => item.trim()).filter(Boolean))];
}

function updateTargetCount() {
  const count = getNetworks().length;
  commandTarget.textContent = count ? `${count} 个目标网段` : '等待输入目标';
}

function formatDuration(milliseconds) {
  const value = Math.max(0, milliseconds);
  if (value < 1000) return `${Math.round(value)} ms`;
  if (value < 60000) return `${(value / 1000).toFixed(value < 10000 ? 2 : 1)} s`;
  const minutes = Math.floor(value / 60000);
  const seconds = ((value % 60000) / 1000).toFixed(1);
  return `${minutes} m ${seconds} s`;
}

function startDurationTimer() {
  if (durationTimer) clearInterval(durationTimer);
  durationStartedAt = performance.now();
  scanDuration.textContent = '0 ms';
  durationTimer = setInterval(() => {
    scanDuration.textContent = formatDuration(performance.now() - durationStartedAt);
  }, 50);
}

function stopDurationTimer(finalMilliseconds) {
  if (durationTimer) clearInterval(durationTimer);
  durationTimer = null;
  const elapsed = finalMilliseconds ?? (performance.now() - durationStartedAt);
  scanDuration.textContent = formatDuration(elapsed);
  return elapsed;
}

function hostRow(host, index) {
  const name = host.hostname || '未识别主机名';
  return `<tr>
    <td>${index + 1}</td>
    <td class="ip-cell">${escapeHtml(host.ip)}</td>
    <td>${escapeHtml(name)}</td>
    <td>${escapeHtml(host.mac || '-')}</td>
    <td>${escapeHtml(host.vendor || '-')}</td>
    <td><span class="online-badge"><i></i>在线</span></td>
  </tr>`;
}

function resultCard(result) {
  if (result.status !== 'success') {
    return `<section class="subnet-block error-card">
      <div class="subnet-title"><strong>${escapeHtml(result.network)}</strong><span>检测失败</span></div>
      <div class="error-message">${escapeHtml(result.error || '扫描失败')}</div>
    </section>`;
  }
  const rows = result.hosts.length
    ? result.hosts.map(hostRow).join('')
    : '<tr><td colspan="6" class="no-hosts">此网段暂未发现在线设备</td></tr>';
  return `<section class="subnet-block">
    <div class="subnet-title"><strong>${escapeHtml(result.network)}</strong><span>共 ${result.count} 台在线设备</span></div>
    <div class="table-wrap"><table>
      <thead><tr><th>序号</th><th>IP 地址</th><th>主机名</th><th>MAC 地址</th><th>设备厂商</th><th>状态</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  </section>`;
}

async function checkHealth() {
  const text = document.querySelector('#systemText');
  const dot = document.querySelector('#statusDot');
  try {
    const response = await fetch('/api/health');
    const data = await response.json();
    text.textContent = data.nmap ? '扫描引擎已就绪' : '未检测到 Nmap';
    dot.classList.toggle('offline', !data.nmap);
  } catch {
    text.textContent = '服务连接异常';
    dot.classList.add('offline');
  }
}

async function showLocalNetwork() {
  try {
    const response = await fetch('/api/local-network');
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '获取失败');
    localIp.textContent = data.ip;
    localNetwork.textContent = data.network;
    localMac.textContent = data.mac || '未获取到';
    localInterface.textContent = data.interface || '-';
    if (!input.value.trim()) {
      input.value = data.network;
      updateTargetCount();
    }
  } catch (error) {
    [localIp, localNetwork, localMac, localInterface].forEach(element => {
      element.textContent = error.message;
      element.classList.add('error-text');
    });
  }
}

function searchIp() {
  const query = ipSearch.value.trim();
  searchFeedback.className = 'search-feedback';

  if (!query) {
    visibleResults = lastResults;
    results.innerHTML = visibleResults.map(resultCard).join('');
    searchFeedback.innerHTML = '';
    return;
  }
  if (!/^[0-9.]+$/.test(query)) {
    searchFeedback.innerHTML = '<strong>IP 搜索只能包含数字和点</strong>';
    searchFeedback.classList.add('not-found');
    return;
  }

  const filtered = lastResults
    .filter(result => result.status === 'success')
    .map(result => {
      const hosts = (result.hosts || []).filter(host => host.ip.includes(query));
      return {...result, hosts, count: hosts.length};
    })
    .filter(result => result.hosts.length);
  const count = filtered.reduce((total, result) => total + result.hosts.length, 0);

  if (count) {
    visibleResults = filtered;
    results.innerHTML = visibleResults.map(resultCard).join('');
    searchFeedback.innerHTML = `<span class="search-state">找到 ${count} 个匹配的在线 IP</span>`;
    searchFeedback.classList.add('found');
  } else {
    visibleResults = [];
    results.innerHTML = '<div class="empty-state">没有匹配的 IP</div>';
    searchFeedback.innerHTML = `<strong>${escapeHtml(query)} 暂时没被使用</strong><span>本次扫描结果中未发现匹配的在线 IP</span>`;
    searchFeedback.classList.add('not-found');
  }
}

async function exportResults() {
  if (!lastResults.length) return;
  exportButton.disabled = true;
  exportButton.textContent = '生成中…';
  try {
    const response = await fetch('/api/export', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        format: exportFormat.value,
        networks: lastNetworks,
        results: visibleResults,
        search: ipSearch.value.trim(),
      }),
    });
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || '导出失败');
    }
    const blob = await response.blob();
    const disposition = response.headers.get('Content-Disposition') || '';
    const match = disposition.match(/filename="?([^";]+)"?/i);
    const filename = match ? match[1] : `ip-scan.${exportFormat.value}`;
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    searchFeedback.innerHTML = `<strong>${escapeHtml(error.message)}</strong>`;
    searchFeedback.className = 'search-feedback not-found';
  } finally {
    exportButton.disabled = false;
    exportButton.textContent = '导出';
  }
}

async function startScan() {
  if (button.disabled) return;
  const networks = getNetworks();
  if (!networks.length) {
    input.focus();
    summary.textContent = '请先输入至少一个网段';
    return;
  }

  button.disabled = true;
  input.disabled = true;
  startDurationTimer();
  button.querySelector('.button-label').textContent = '检测中';
  searchPanel.hidden = true;
  exportTools.hidden = true;
  searchFeedback.innerHTML = '';
  ipSearch.value = '';
  emptyState.hidden = true;
  results.innerHTML = `<div class="scanning">
    <p>正在并行探测 ${networks.length} 个网段，请稍候…</p>
    <div class="progress-track"><div class="progress-bar"></div></div>
  </div>`;
  summary.textContent = '任务执行中';

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({networks}),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '请求失败');

    const online = data.results.reduce((total, item) => total + (item.count || 0), 0);
    stopDurationTimer(data.elapsed_ms);
    lastResults = data.results;
    visibleResults = lastResults;
    lastNetworks = networks;
    results.innerHTML = visibleResults.map(resultCard).join('');
    summary.textContent = `完成 ${lastResults.length} 个网段 · 发现 ${online} 台在线设备`;
    searchPanel.hidden = false;
    exportTools.hidden = false;
  } catch (error) {
    const elapsed = stopDurationTimer();
    scanDuration.textContent = `${formatDuration(elapsed)}（失败）`;
    results.innerHTML = `<div class="request-error"><strong>扫描未完成</strong><p>${escapeHtml(error.message)}</p></div>`;
    summary.textContent = '任务失败';
  } finally {
    if (durationTimer) stopDurationTimer();
    button.disabled = false;
    input.disabled = false;
    button.querySelector('.button-label').textContent = '检测';
  }
}

input.addEventListener('input', updateTargetCount);
button.addEventListener('click', startScan);
searchButton.addEventListener('click', searchIp);
exportButton.addEventListener('click', exportResults);
ipSearch.addEventListener('keydown', event => {
  if (event.key === 'Enter') searchIp();
});
ipSearch.addEventListener('input', () => {
  if (!ipSearch.value.trim()) searchIp();
});
input.addEventListener('keydown', event => {
  if (event.key === 'Enter') {
    event.preventDefault();
    startScan();
  }
});

updateTargetCount();
checkHealth();
showLocalNetwork();
