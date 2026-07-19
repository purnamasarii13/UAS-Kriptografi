// ---------------------------------------------------------------------------
// Shared helpers used across all algorithm pages
// ---------------------------------------------------------------------------

function initTheme() {
  const saved = localStorage.getItem('crypto-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', saved);
  updateThemeIcon(saved);
  const btn = document.getElementById('themeToggle');
  if (btn) {
    btn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('crypto-theme', next);
      updateThemeIcon(next);
    });
  }
}

function updateThemeIcon(theme) {
  const icon = document.getElementById('themeIcon');
  if (!icon) return;
  icon.className = theme === 'dark' ? 'bi bi-moon-stars-fill' : 'bi bi-sun-fill';
}

function copyToClipboard(text, btnEl) {
  navigator.clipboard.writeText(text).then(() => {
    if (!btnEl) return;
    const original = btnEl.innerHTML;
    btnEl.innerHTML = '<i class="bi bi-check2"></i> Disalin!';
    setTimeout(() => { btnEl.innerHTML = original; }, 1400);
  });
}

// Render a small hex/binary matrix (rows x cols) as a Bootstrap table
function renderMatrixTable(matrix, variant) {
  const cls = variant ? ` table-${variant}` : '';
  let html = `<table class="table state-matrix-table${cls}"><tbody>`;
  for (const row of matrix) {
    html += '<tr>';
    for (const cell of row) {
      html += `<td>${cell}</td>`;
    }
    html += '</tr>';
  }
  html += '</tbody></table>';
  return html;
}

// Render a generic labeled Bootstrap table from a list of {label, value} rows
function renderKeyValueTable(rows, headers) {
  headers = headers || ['Keterangan', 'Nilai'];
  let html = `<table class="table-sm align-middle kv-table"><thead><tr><th>${headers[0]}</th><th>${headers[1]}</th></tr></thead><tbody>`;
  rows.forEach(r => {
    html += `<tr><td class="fw-semibold">${r.label}</td><td class="mono-cell">${r.value}</td></tr>`;
  });
  html += '</tbody></table>';
  return html;
}

// Render step-flow pill trail, e.g. ['Input','PC-1','Split C0D0']
function renderStepFlow(labels) {
  return '<div class="step-flow">' + labels.map((l, i) =>
    (i > 0 ? '<span class="step-arrow"><i class="bi bi-arrow-right"></i></span>' : '') +
    `<span class="step-pill">${l}</span>`
  ).join('') + '</div>';
}

function monoBlock(label, value) {
  return `<div class="mb-2"><div class="form-label mb-1">${label}</div><div class="mono-block">${value}</div></div>`;
}

function showError(containerId, message) {
  const el = document.getElementById(containerId);
  el.innerHTML = `<div class="alert alert-danger error-alert d-flex align-items-center gap-2" role="alert">
      <i class="bi bi-exclamation-triangle-fill"></i><div>${message}</div></div>`;
  el.classList.remove('d-none');
}

function clearError(containerId) {
  const el = document.getElementById(containerId);
  el.innerHTML = '';
  el.classList.add('d-none');
}

// Bootstrap contextual colors cycling for Round badges: Primary, Success, Warning, Danger
const ROUND_BADGE_COLORS = ['primary', 'success', 'warning', 'danger'];
function roundBadge(n, text) {
  const color = ROUND_BADGE_COLORS[(n - 1) % ROUND_BADGE_COLORS.length];
  return `<span class="badge bg-${color} ms-2">${text || ('Round ' + n)}</span>`;
}

// ---------------------------------------------------------------------------
// Accordion "Tampilkan Solusi Penyelesaian" / "Sembunyikan Solusi" toggle
// ---------------------------------------------------------------------------
function setupSolutionToggle(buttonId, wrapId) {
  const btn = document.getElementById(buttonId);
  if (!btn) return;
  btn.addEventListener('click', function () {
    const wrap = document.getElementById(wrapId);
    const hidden = wrap.classList.contains('d-none');
    wrap.classList.toggle('d-none');
    this.innerHTML = hidden
      ? '<i class="bi bi-eye-slash me-1"></i>Sembunyikan Solusi'
      : '<i class="bi bi-eye me-1"></i>Tampilkan Solusi Penyelesaian';
  });
}

function accordionItem(id, title, body, badgeHtml) {
  return `<div class="accordion-item">
    <h2 class="accordion-header">
      <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#c${id}">
        <span>${title}</span>${badgeHtml || ''}
      </button>
    </h2>
    <div id="c${id}" class="accordion-collapse collapse" data-bs-parent="#accordionContainer">
      <div class="accordion-body">${body}</div>
    </div>
  </div>`;
}

// ---------------------------------------------------------------------------
// Load Example — generic filler
// ---------------------------------------------------------------------------
function loadExampleValues(values) {
  Object.entries(values).forEach(([id, val]) => {
    const el = document.getElementById(id);
    if (!el) return;
    if (el.type === 'radio') return;
    el.value = val;
  });
}

// ---------------------------------------------------------------------------
// PDF Export of the result + full solution steps
// ---------------------------------------------------------------------------
async function downloadResultAsPDF(moduleName, resultHex, resultBin, solutionContainerId) {
  const { jsPDF } = window.jspdf;
  const doc = new jsPDF({ unit: 'pt', format: 'a4' });
  const marginX = 40;
  let y = 50;
  const pageHeight = doc.internal.pageSize.getHeight();
  const maxWidth = doc.internal.pageSize.getWidth() - marginX * 2;

  function ensureSpace(lines = 1, lineHeight = 14) {
    if (y + lines * lineHeight > pageHeight - 40) {
      doc.addPage();
      y = 50;
    }
  }

  doc.setFontSize(16);
  doc.text(`CryptoLab - Hasil Simulasi ${moduleName}`, marginX, y);
  y += 24;

  doc.setFontSize(11);
  doc.setTextColor(90);
  doc.text(new Date().toLocaleString('id-ID'), marginX, y);
  doc.setTextColor(0);
  y += 20;

  doc.setFontSize(13);
  doc.text('Hasil Akhir', marginX, y);
  y += 16;
  doc.setFontSize(10);
  doc.text(`Hex : ${resultHex}`, marginX, y); y += 14;
  const binLines = doc.splitTextToSize(`Biner: ${resultBin}`, maxWidth);
  ensureSpace(binLines.length);
  doc.text(binLines, marginX, y); y += binLines.length * 14 + 10;

  const container = document.getElementById(solutionContainerId);
  if (container) {
    doc.setFontSize(13);
    ensureSpace(2);
    doc.text('Langkah Penyelesaian Lengkap', marginX, y);
    y += 18;
    doc.setFontSize(9);

    const items = container.querySelectorAll('.accordion-item');
    items.forEach(item => {
      const titleSpan = item.querySelector('.accordion-button span');
      const title = titleSpan ? titleSpan.innerText : item.querySelector('.accordion-button').innerText;
      const body = item.querySelector('.accordion-body').innerText.trim();

      ensureSpace(2, 16);
      doc.setFont(undefined, 'bold');
      doc.setFontSize(10.5);
      const titleLines = doc.splitTextToSize(title, maxWidth);
      doc.text(titleLines, marginX, y);
      y += titleLines.length * 13 + 3;

      doc.setFont(undefined, 'normal');
      doc.setFontSize(9);
      const bodyLines = doc.splitTextToSize(body, maxWidth);
      bodyLines.forEach(line => {
        ensureSpace(1, 11);
        doc.text(line, marginX, y);
        y += 11;
      });
      y += 8;
    });
  }

  doc.save(`cryptolab-${moduleName.toLowerCase().replace(/\s+/g, '-')}.pdf`);
}

document.addEventListener('DOMContentLoaded', initTheme);
