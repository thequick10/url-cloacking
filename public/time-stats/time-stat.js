// Timing Stat Feature JS

let timingData = [];
let filteredData = [];
let autoRefreshInterval = null;

async function fetchTimingData() {
  try {
    const res = await fetch('/time-stats');
    if (!res.ok) throw new Error('Failed to fetch timing stats');
    timingData = await res.json();
    filteredData = [...timingData];
    renderStats();
    renderTable();
  } catch (e) {
    timingData = [];
    filteredData = [];
    renderStats();
    renderTable();
  }
}

document.addEventListener('DOMContentLoaded', () => {
  fetchTimingData();
  setupControls();
  startAutoRefresh();
});

function formatHumanTime(ms) {
  if (ms < 1000) return ms + ' ms';
  let s = Math.floor(ms / 1000);
  const msRemainder = ms % 1000;
  const h = Math.floor(s / 3600);
  s = s % 3600;
  const m = Math.floor(s / 60);
  s = s % 60;
  let parts = [];
  if (h) parts.push(h + ' hr');
  if (m) parts.push(m + ' min');
  if (s) parts.push(s + ' s');
  if (!parts.length && msRemainder) parts.push(msRemainder + ' ms');
  return parts.join(' ');
}

function renderStats() {
  // Calculate average time per URL (today) and total time
  const today = new Date().toISOString().slice(0, 10);
  const todayData = timingData.filter(row => row.date === today);
  const avg = todayData.length ? (todayData.reduce((sum, r) => sum + r.time, 0) / todayData.length) : 0;
  const sum = timingData.reduce((sum, r) => sum + r.time, 0);
  document.getElementById('avg-time-value').textContent = todayData.length ? formatHumanTime(avg) : '--';
  document.getElementById('sum-time-value').textContent = sum ? formatHumanTime(sum) : '--';
}

function groupByDate(data) {
  const grouped = {};
  data.forEach(row => {
    if (!grouped[row.date]) grouped[row.date] = [];
    grouped[row.date].push(row);
  });
  return grouped;
}

function renderTable() {
  const tbody = document.querySelector('#timing-table tbody');
  tbody.innerHTML = '';
  const grouped = groupByDate(filteredData);
  const dates = Object.keys(grouped).sort((a, b) => {
    const order = document.getElementById('sort-order').value;
    return order === 'latest' ? b.localeCompare(a) : a.localeCompare(b);
  });
  dates.forEach(date => {
    const rows = grouped[date];
    const totalTime = rows.reduce((sum, r) => sum + r.time, 0);
    const avgTime = rows.length ? totalTime / rows.length : 0;
    const count = rows.length;
    const totalTimeSec = (totalTime / 1000).toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2});
    const avgTimeSec = (avgTime / 1000).toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2});
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${date}</td><td>${totalTimeSec}</td><td>${avgTimeSec}</td><td>${count}</td>`;
    tbody.appendChild(tr);
  });
}

function setupControls() {
  document.getElementById('filter-btn').onclick = filterByDateRange;
  document.getElementById('clear-filter-btn').onclick = clearDateFilter;
  document.getElementById('sort-order').onchange = sortTable;
  document.getElementById('export-csv-btn').onclick = exportCSV;
}

function filterByDateRange() {
  const start = document.getElementById('start-date').value;
  const end = document.getElementById('end-date').value;
  filteredData = timingData.filter(row => {
    return (!start || row.date >= start) && (!end || row.date <= end);
  });
  renderTable();
}

function clearDateFilter() {
  document.getElementById('start-date').value = '';
  document.getElementById('end-date').value = '';
  filteredData = [...timingData];
  renderTable();
}

function sortTable() {
  const order = document.getElementById('sort-order').value;
  filteredData.sort((a, b) => {
    if (order === 'latest') return b.date.localeCompare(a.date);
    else return a.date.localeCompare(b.date);
  });
  renderTable();
}

function exportCSV() {
  let csv = 'Date,Total Time (s),Avg Time per URL (s),Count\n';
  const grouped = groupByDate(filteredData);
  const dates = Object.keys(grouped).sort();
  dates.forEach(date => {
    const rows = grouped[date];
    const totalTime = rows.reduce((sum, r) => sum + r.time, 0);
    const avgTime = rows.length ? totalTime / rows.length : 0;
    const count = rows.length;
    const totalTimeSec = (totalTime / 1000).toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2});
    const avgTimeSec = (avgTime / 1000).toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2});
    csv += `${date},${totalTimeSec},${avgTimeSec},${count}\n`;
  });
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'timing-stats.csv';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function startAutoRefresh() {
  if (autoRefreshInterval) clearInterval(autoRefreshInterval);
  autoRefreshInterval = setInterval(() => {
    fetchTimingData();
  }, 10000);
} 