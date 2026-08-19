// === Configuration & State ===
const { POPULAR, SCENARIOS, OSV_SUPPORTED, AI_CONFIGURED } = window.BOOT;
    const $ = (s) => document.querySelector(s);
    const $$ = (s) => Array.from(document.querySelectorAll(s));
    let LAST = [];           // last result set (normalized advisories)
    let AI = {};             // advisory_id -> verdict
    let filterReturnFocus = null;

    // === DOM Helpers ===
    function setResultsBusy(busy) {
      $('#results').setAttribute('aria-busy', String(Boolean(busy)));
    }

    function setFilterPanel(open, restoreFocus = true) {
      const isOpen = Boolean(open);
      if (isOpen) filterReturnFocus = document.activeElement;
      document.body.classList.toggle('filters-open', isOpen);
      $('#filters-toggle').setAttribute('aria-expanded', String(isOpen));
      $('#filter-scrim').tabIndex = isOpen ? 0 : -1;
      if (isOpen) {
        requestAnimationFrame(() => $('#filters-close').focus());
      } else if (restoreFocus && filterReturnFocus && document.contains(filterReturnFocus)) {
        filterReturnFocus.focus();
      }
    }


    function selectedCategories() {
      return $$('input[name=category]:checked').map(c => c.value);
    }

    // === Package Suggestions ===
    function refreshPackages() {
      const eco = $('#ecosystem').value;
      const list = POPULAR[eco] || [];
      const sel = $('#affects_pick');
      const prev = sel.value;
      sel.innerHTML = '<option value="">— any package —</option>' +
        list.map(p => `<option value="${p}">${p}</option>`).join('');
      if (list.includes(prev)) sel.value = prev;
    }

    // === Search & Filters ===
    function publishedFilter() {
      const v = $('#published').value;
      if (!v || v === 'any') return '';
      if (v === '2020') return '>=2020-01-01';
      const days = {'7d':7,'30d':30,'90d':90,'180d':180,'1y':365,'2y':730}[v];
      if (!days) return '';
      const d = new Date(Date.now() - days*86400000);
      return '>=' + d.toISOString().slice(0,10);
    }

    function selectedExtraCwes() {
      return $$('input[name=extra_cwe]:checked').map(c => c.value);
    }
    function updateExtraCount() {
      const n = selectedExtraCwes().length;
      $('#extra_cwes_count').textContent = n ? (n + ' CWE' + (n>1?'s':'')) : 'none';
    }

    function applyScenario(key) {
      const s = SCENARIOS.find(x => x.key === key);
      if (!s) return;
      $$('input[name=category]').forEach(c => { c.checked = (s.categories||[]).includes(c.value); });
      if (s.ecosystem) { $('#ecosystem').value = s.ecosystem; refreshPackages(); }
      if (s.published) $('#published').value = s.published;
      if ('include_extended' in s) $('#include_extended').checked = !!s.include_extended;
      $('#severity').value = s.severity || 'any';
    }

    function toast(msg, kind='') {
      const t = document.createElement('div');
      t.className = 'toast ' + kind;
      t.textContent = msg;
      t.setAttribute('role', kind === 'err' ? 'alert' : 'status');
      t.setAttribute('aria-live', kind === 'err' ? 'assertive' : 'polite');
      document.body.appendChild(t);
      setTimeout(() => t.remove(), 5000);
    }

    function esc(s) {
      return String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    function safeAttr(s) {
      return (s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }

    function safeUrl(value) {
      try {
        const url = new URL(String(value || ''), window.location.origin);
        return ['http:', 'https:'].includes(url.protocol) ? esc(url.href) : '#';
      } catch (_) {
        return '#';
      }
    }

    function severityRank(s) {
      return {critical:4, high:3, medium:2, low:1, unknown:0}[s] || 0;
    }

    // === Rendering ===
    function renderCard(a) {
      const v = AI[a.advisory_id] || a.ai;
      let aiHtml = '';
      if (v) {
        if (v.error) {
          aiHtml = `<div class="ai-verdict error">
            <div class="verdict-head"><span class="verdict-state">AI error</span></div>
            <div class="desc">${esc(v.error)}</div>
          </div>`;
        } else {
          const incomplete = v.has_errors && v.is_match !== true;
          const cls = v.is_match ? 'match' : (incomplete ? '' : 'nomatch');
          const state = v.is_match ? 'Confirmed match' : (incomplete ? 'Incomplete score' : 'Not a match');
          const pct = Math.round((v.confidence||0)*100);
          aiHtml = `<div class="ai-verdict ${cls}">
            <div class="verdict-head">
              <span class="verdict-state">${state}</span>
              ${v.vuln_type ? '<span class="verdict-type">/ '+esc(v.vuln_type)+'</span>' : ''}
              <span class="verdict-score">${pct}%${v.cached?' · CACHED':''}${v.has_errors?' · PARTIAL':''}</span>
            </div>
            <progress class="conf-bar" max="100" value="${pct}" aria-label="AI confidence ${pct}%">${pct}%</progress>
            <div class="desc">${esc(v.reason||'')}</div>
          </div>`;
        }
      }
      const cwes = (a.cwe_labels||[]).map(c =>
        `<span class="badge cwe" title="${esc(c.label)}">${esc(c.id)}</span>`).join('');
      const pkgs = (a.packages||[]).slice(0,4).map(p =>
        `<span class="badge pkg">${esc(p.ecosystem)}:${esc(p.name)}${p.first_patched_version?' → '+esc(p.first_patched_version):''}</span>`).join('');
      const morePkgs = (a.packages||[]).length > 4 ? `<span class="badge">+${a.packages.length-4} more</span>` : '';
      const cve = a.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(a.cve_id)}" target="_blank" rel="noopener noreferrer">${esc(a.cve_id)}</a>` : '<span class="muted">no CVE</span>';
      const dimClass = ($('#only_match').checked && v && v.is_match === false) ? 'dim' : '';
      const safeSeverity = ['critical','high','medium','low','unknown'].includes(a.severity) ? a.severity : 'unknown';
      const sevbar = 'sevbar-' + safeSeverity;
      const srcs = a.sources || [a.source].filter(Boolean);
      const sourceClass = srcs.map(s => String(s).toLowerCase().replace(/[^a-z0-9-]/g, '')).filter(Boolean).join('-');
      const srcBadge = srcs.length
        ? `<span class="badge src src-${sourceClass}" title="Data source(s)">${srcs.map(s=>esc(String(s).toUpperCase())).join('+')}</span>` : '';
      const nativeBadge = (a.native && !(a.cwes||[]).length)
        ? `<span class="badge badge--native" title="Native OSV record with no CWE — relies on AI">NO CWE · AI</span>` : '';
      const withdrawnBadge = a.withdrawn_at
        ? `<span class="badge badge--withdrawn" title="Withdrawn at ${esc(a.withdrawn_at)}">WITHDRAWN</span>` : '';
      const kevBadge = a.kev
        ? `<span class="badge badge--kev" title="CISA Known Exploited Vulnerability">KEV / EXPLOITED</span>` : '';
      const epssPct = Number(a.epss_percentage);
      const epssBar = Number.isFinite(epssPct)
        ? `<span class="badge badge--epss" title="EPSS exploit probability">EPSS ${(epssPct * 100).toFixed(2)}%</span>`
        : '';
      const epssMeta = Number.isFinite(epssPct)
        ? `<span class="epss-meter" title="EPSS exploit probability${Number.isFinite(Number(a.epss_percentile)) ? ' · percentile ' + Math.round(Number(a.epss_percentile) * 100) : ''}">
            <span class="meta-label">EPSS</span>
            <progress max="100" value="${Math.min(100, Math.max(0, epssPct * 100))}" aria-label="EPSS ${(epssPct * 100).toFixed(2)}%"></progress>
            ${(epssPct * 100).toFixed(2)}%${Number.isFinite(Number(a.epss_percentile)) ? ' · p' + Math.round(Number(a.epss_percentile) * 100) : ''}
          </span>`
        : '';
      return `<article class="card ${sevbar} ${dimClass}" data-id="${esc(a.advisory_id)}">
        <div class="card-top">
          <h3 class="title">${esc(a.summary)}</h3>
          <span class="badge sev ${safeSeverity}">${esc(a.severity)}</span>
        </div>
        <div class="badges">
          ${srcBadge}${nativeBadge}${kevBadge}${withdrawnBadge}${epssBar}
          <span class="badge eco">${esc((a.ecosystems||[]).join(', ')||'—')}</span>
          ${cwes}
        </div>
        <div class="badges">${pkgs}${morePkgs}</div>
        <div class="meta">
          <span><span class="meta-label">Advisory</span><a href="${safeUrl(a.html_url)}" target="_blank" rel="noopener noreferrer">${esc(a.ghsa_id || a.advisory_id)}</a></span>
          <span><span class="meta-label">CVE</span>${cve}</span>
          <span><span class="meta-label">Published</span><time datetime="${esc((a.published_at||'').slice(0,10))}">${esc((a.published_at||'').slice(0,10))}</time></span>
          ${a.cvss_score ? '<span><span class="meta-label">CVSS</span>'+esc(a.cvss_score)+'</span>' : ''}
          ${epssMeta}
        </div>
        ${aiHtml}
      </article>`;
    }

    // The set currently on screen: filtered by "only matches", then sorted.
    function currentItems() {
      let items = LAST.slice();
      if ($('#only_match').checked) {
        items = items.filter(a => {
          const v = AI[a.advisory_id] || a.ai;
          return v && v.is_match === true;
        });
      }
      // AI-confirmed matches stay at the top; otherwise honour the selected sort.
      const sort = $('#sort').value;
      const dir = $('#direction').value === 'asc' ? 1 : -1;
      items.sort((x, y) => {
        const vx = AI[x.advisory_id]||x.ai, vy = AI[y.advisory_id]||y.ai;
        const mx = vx && vx.is_match ? (vx.confidence||0)+1 : 0;
        const my = vy && vy.is_match ? (vy.confidence||0)+1 : 0;
        if (my !== mx) return my - mx;
        let cmp = 0;
        if (sort === 'cve_id') {
          cmp = (x.cve_id || '').localeCompare(y.cve_id || '');
        } else if (sort === 'updated') {
          cmp = (x.updated_at || '').localeCompare(y.updated_at || '');
        } else if (sort === 'epss_percentage') {
          cmp = (Number(x.epss_percentage) || 0) - (Number(y.epss_percentage) || 0);
        } else if (sort === 'epss_percentile') {
          cmp = (Number(x.epss_percentile) || 0) - (Number(y.epss_percentile) || 0);
        } else {
          cmp = (x.published_at || '').localeCompare(y.published_at || '');
        }
        if (cmp) return cmp * dir;
        return severityRank(y.severity) - severityRank(x.severity);
      });
      return items;
    }

    function failedIds() {
      return LAST.map(a => a.advisory_id).filter(id => AI[id] && (AI[id].error || AI[id].has_errors));
    }

    function updateActionButtons() {
      const has = LAST.length > 0;
      $('#ai-btn').disabled = !has;
      $('#only_match').disabled = !has;
      $('#export-btn').setAttribute('aria-disabled', String(!has));
      $('#export-btn').tabIndex = has ? 0 : -1;
      if (!has) $('.export-menu').removeAttribute('open');
      const nfail = failedIds().length;
      const rb = $('#retry-btn');
      rb.disabled = nfail === 0;
      rb.textContent = nfail ? `Retry failed (${nfail})` : 'Retry failed';
    }

    function render() {
      const items = currentItems();
      const el = $('#results');
      if (!items.length) {
        el.innerHTML = `<div class="empty">No advisories match the current filter.</div>`;
        updateActionButtons();
        return;
      }
      el.innerHTML = items.map(renderCard).join('');
      updateActionButtons();
    }

    async function search() {
      const cats = selectedCategories();
      if (!cats.length) { toast('Select at least one bug class', 'err'); return; }
      if (document.body.classList.contains('filters-open')) setFilterPanel(false, false);
      $('#search-btn').disabled = true;
      setResultsBusy(true);
      $('#results').innerHTML = `<div class="loading"><span class="spinner"></span>Searching advisories…</div>`;
      $('#summary').textContent = 'Searching…';
      const sources = $$('input[name=source]:checked').map(c => c.value);
      if (!sources.length) {
        toast('Select at least one data source', 'err');
        $('#search-btn').disabled = false;
        setResultsBusy(false);
        return;
      }
      // A failed query must never leave the previous result set available to
      // the Auto pipeline or export controls as if it were fresh data.
      LAST = [];
      AI = {};
      updateActionButtons();
      const payload = {
        categories: cats,
        include_extended: $('#include_extended').checked,
        ecosystem: $('#ecosystem').value,
        severity: $('#severity').value,
        affects: $('#affects_pick').value,
        published: publishedFilter(),
        max_results: parseInt($('#max_results').value) || 100,
        extra_cwes: selectedExtraCwes(),
        sort: $('#sort').value,
        direction: $('#direction').value,
        type: $('#type').value,
        sources: sources,
        refresh_osv: $('#refresh_osv').checked,
      };
      if (sources.includes('nvd')) {
        $('#results').innerHTML = `<div class="loading"><span class="spinner"></span>Fetching… (NVD is rate-limited — may take a moment per CWE)</div>`;
      } else if (sources.includes('osv')) {
        $('#results').innerHTML = `<div class="loading"><span class="spinner"></span>Fetching… (OSV may download a ~10MB list on first use)</div>`;
      }
      try {
        const r = await fetch('/api/search', {method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(payload)});
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || 'search failed');
        LAST = data.results;
        AI = {};
        LAST.forEach(a => { if (a.ai) AI[a.advisory_id] = a.ai; });
        const cached = LAST.filter(a => a.ai).length;
        const ps = data.query.per_source || {};
        const psText = Object.keys(ps).length ? ' · ' + Object.entries(ps).map(([k,v]) => `${k.toUpperCase()}:${v}`).join(' + ') : '';
        $('#summary').innerHTML = `<b>${data.count}</b> advisories${psText} · CWEs: <code>${data.query.cwes.join(', ')}</code>`
          + (cached ? ` · <span class="summary-cached">${cached} already AI-scored</span>` : '');
        (data.warnings || []).forEach(w => toast('⚠️ ' + w, 'err'));
        $('#ai-btn').disabled = LAST.length === 0;
        $('#only_match').disabled = LAST.length === 0;
        $('#only_match').checked = false;
        render();
      } catch (e) {
        $('#results').innerHTML = `<div class="empty">❌ ${esc(e.message)}</div>`;
        $('#summary').textContent = 'Error.';
        toast(e.message, 'err');
      } finally {
        $('#search-btn').disabled = false;
        setResultsBusy(false);
      }
    }

    // === AI Classification ===
    // One classify request for a set of ids. Merges verdicts into AI and
    // returns the number of results that came back as errors.
    async function classifyIds(ids) {
      if (!ids.length) return 0;
      const cats = selectedCategories();
      for (let offset = 0; offset < ids.length; offset += 100) {
        const batch = ids.slice(offset, offset + 100);
        const r = await fetch('/api/ai/classify', {method:'POST', headers:{'content-type':'application/json'},
          body: JSON.stringify({categories: cats.length ? cats : ['bac'], advisory_ids: batch})});
        const data = await r.json();
        if (!r.ok) throw new Error(data.error || 'AI failed');
        Object.assign(AI, data.verdicts);
      }
      return ids.filter(id => AI[id] && (AI[id].error || AI[id].has_errors)).length;
    }

    async function refineAI() {
      if (!LAST.length) return;
      const ids = LAST.map(a => a.advisory_id);
      $('#ai-btn').disabled = true;
      $('#retry-btn').disabled = true;
      setResultsBusy(true);
      const orig = $('#ai-btn').innerHTML;
      $('#ai-btn').innerHTML = '<span class="spinner"></span>Refining…';
      try {
        await classifyIds(ids);
        render();
        // Auto-retry the ones that errored (rate limits / transient failures),
        // up to 3 extra rounds. Backend also retries internally with backoff.
        let round = 0;
        while (failedIds().length && round < 3) {
          round++;
          const fails = failedIds();
          $('#ai-btn').innerHTML = `<span class="spinner"></span>Retrying ${fails.length}… (${round}/3)`;
          toast(`Retrying ${fails.length} failed advisory(ies)… round ${round}`, 'ok');
          await classifyIds(fails);
          render();
        }
        const matches = LAST.filter(a => (AI[a.advisory_id]||{}).is_match).length;
        const errs = failedIds().length;
        toast(`AI done: ${matches} matches` + (errs ? `, ${errs} still failing — use ↻ Retry failed` : ''),
              errs ? 'err' : 'ok');
      } catch (e) {
        toast(e.message, 'err');
      } finally {
        $('#ai-btn').innerHTML = orig;
        setResultsBusy(false);
        render();
      }
    }

    async function retryFailed() {
      const fails = failedIds();
      if (!fails.length) return;
      $('#retry-btn').disabled = true;
      setResultsBusy(true);
      const orig = $('#retry-btn').innerHTML;
      $('#retry-btn').innerHTML = '<span class="spinner"></span>Retrying…';
      try {
        await classifyIds(fails);
        render();
        const left = failedIds().length;
        toast(left ? `${left} still failing` : 'All retried successfully', left ? 'err' : 'ok');
      } catch (e) {
        toast(e.message, 'err');
      } finally {
        $('#retry-btn').innerHTML = orig;
        setResultsBusy(false);
        render();
      }
    }

    async function testAI() {
      const pill = $('#ai-test-pill');
      pill.textContent = '⚡ testing…';
      try {
        const r = await fetch('/api/ai/test', {
          method: 'POST',
          headers: {'content-type': 'application/json'},
          body: '{}',
        });
        const d = await r.json();
        if (d.ok) { pill.textContent = '⚡ AI OK'; toast('AI reachable ('+d.model+'): '+d.reply, 'ok'); }
        else { pill.textContent = '⚡ AI fail'; toast('AI test failed: '+d.error, 'err'); }
      } catch (e) { pill.textContent = '⚡ AI fail'; toast(e.message, 'err'); }
    }

    // Any advisory in the current set that the AI has NOT scored yet.
    function unscoredCount() {
      const cats = selectedCategories();
      return LAST.filter(a => {
        const verdict = AI[a.advisory_id] || a.ai;
        if (!verdict) return true;
        const scored = verdict.scored_categories || [];
        return cats.some(category => !scored.includes(category));
      }).length;
    }

    // === Export ===
    function flatRow(a) {
      const v = AI[a.advisory_id] || a.ai || {};
      return {
        advisory_id: a.advisory_id,
        ghsa_id: a.ghsa_id || '',
        cve_id: a.cve_id || '',
        sources: (a.sources || [a.source]).filter(Boolean).join('|'),
        severity: a.severity || '',
        cvss: a.cvss_score || '',
        ecosystems: (a.ecosystems || []).join('|'),
        packages: (a.packages || []).map(p => `${p.ecosystem}:${p.name}${p.first_patched_version?'@'+p.first_patched_version:''}`).join('|'),
        cwes: (a.cwes || []).join('|'),
        kev: a.kev === true ? 'yes' : 'no',
        nvd_status: a.nvd_status || '',
        severity_by_source: JSON.stringify(a.severity_by_source || {}),
        cvss_by_source: JSON.stringify(a.cvss_by_source || {}),
        ai_match: v.error ? 'ERROR' : (v.is_match === true ? 'yes' : (v.is_match === false ? 'no' : '')),
        ai_confidence: v.confidence != null ? v.confidence : '',
        ai_vuln_type: v.vuln_type || '',
        ai_reason: v.error ? v.error : (v.reason || ''),
        published: (a.published_at || '').slice(0, 10),
        updated: (a.updated_at || '').slice(0, 10),
        withdrawn_at: a.withdrawn_at || '',
        url: a.html_url || '',
        summary: a.summary || '',
        epss: a.epss_percentage != null ? a.epss_percentage : '',
        epss_percentile: a.epss_percentile != null ? a.epss_percentile : '',
      };
    }
    function download(name, text, mime) {
      const blob = new Blob([text], {type: mime});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = name;
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    function stamp() { return new Date().toISOString().slice(0,19).replace(/[:T]/g,'-'); }
    function csvCell(v) {
      const text = String(v == null ? '' : v);
      // Spreadsheet applications may execute attacker-controlled advisory text
      // as a formula. A leading apostrophe forces the cell to remain plain text.
      const safe = /^[\t\r\n]/.test(text) || /^[ ]*[=+\-@]/.test(text)
        ? "'" + text
        : text;
      return /[",\r\n]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe;
    }
    function doExport(fmt) {
      let items = currentItems();
      if (fmt === 'csv-matches') items = items.filter(a => (AI[a.advisory_id]||a.ai||{}).is_match === true);
      if (!items.length) { toast('Nothing to export', 'err'); return; }
      const rows = items.map(flatRow);
      if (fmt === 'json') {
        const full = items.map(a => ({...a, ai: AI[a.advisory_id] || a.ai || null}));
        download(`vulnerability-advisories-${stamp()}.json`, JSON.stringify(full, null, 2), 'application/json');
      } else {
        const cols = Object.keys(rows[0]);
        const csv = [cols.join(',')].concat(rows.map(r => cols.map(c => csvCell(r[c])).join(','))).join('\n');
        download(`vulnerability-advisories-${stamp()}.csv`, '﻿' + csv, 'text/csv;charset=utf-8');
      }
      $('.export-menu').removeAttribute('open');
      toast(`Exported ${items.length} advisory(ies) as ${fmt.startsWith('csv')?'CSV':'JSON'}`, 'ok');
    }

    // === Auto Pipeline ===
    function setSources(list) {
      $$('input[name=source]').forEach(c => { c.checked = list.includes(c.value); });
    }

    // One-click pipeline: optimal sources -> search -> AI (+retry) -> only matches.
    async function autoRun() {
      if ($('#auto-btn').disabled) return;
      const cats = selectedCategories();
      if (!cats.length) { toast('Select at least one bug class', 'err'); return; }
      const eco = $('#ecosystem').value;
      const osvOk = OSV_SUPPORTED.includes(eco);
      // GHSA covers CWE-tagged advisories; OSV-native adds the no-CWE records the
      // AI can still catch. For "any" ecosystem OSV can't be used, so GHSA only.
      setSources(osvOk ? ['ghsa', 'osv-native'] : ['ghsa']);

      const btn = $('#auto-btn');
      btn.disabled = true;
      const orig = btn.innerHTML;
      try {
        btn.innerHTML = '<span class="spinner"></span>1/3 Searching…';
        await search();
        if (!LAST.length) { toast('No advisories match these filters', 'err'); return; }
        if (AI_CONFIGURED) {
          btn.innerHTML = '<span class="spinner"></span>2/3 AI classifying…';
          await refineAI();               // includes auto-retry of failures
          $('#only_match').checked = true; // 3/3 keep only real matches
          const n = currentItems().length;
          toast(`Auto done: ${n} confirmed match(es) shown`, 'ok');
        } else {
          toast('AI not configured (set AI_* in .env) — showing raw results', 'err');
        }
        render();
      } finally {
        btn.disabled = false;
        btn.innerHTML = orig;
      }
    }

    // === Event Listeners ===
    $('#auto-btn').addEventListener('click', autoRun);
    $('#search-btn').addEventListener('click', search);
    $('#ai-btn').addEventListener('click', refineAI);
    // "Only AI matches" is a display filter — but if nothing is scored yet it
    // would show an empty list, so auto-run the AI pass first, then filter.
    $('#only_match').addEventListener('change', async (e) => {
      if (e.target.checked && LAST.length && unscoredCount() > 0) {
        toast('Running AI first so there is something to filter…', 'ok');
        await refineAI();
      }
      render();
    });
    $('#retry-btn').addEventListener('click', retryFailed);
    $('#ai-test-pill').addEventListener('click', testAI);
    $('#filters-toggle').addEventListener('click', () => setFilterPanel(true));
    $('#filters-close').addEventListener('click', () => setFilterPanel(false));
    $('#filter-scrim').addEventListener('click', () => setFilterPanel(false));
    $('#ecosystem').addEventListener('change', refreshPackages);
    $('#sort').addEventListener('change', () => { if (LAST.length) render(); });
    $('#direction').addEventListener('change', () => { if (LAST.length) render(); });
    $('#scenario').addEventListener('change', e => applyScenario(e.target.value));
    $$('input[name=extra_cwe]').forEach(c => c.addEventListener('change', updateExtraCount));
    $$('.export-pop button').forEach(b => b.addEventListener('click', () => doExport(b.dataset.fmt)));
    // Close the export menu when clicking outside it.
    document.addEventListener('click', e => {
      const m = $('.export-menu');
      if (m && m.open && !m.contains(e.target)) m.removeAttribute('open');
    });
    $('#export-btn').addEventListener('click', e => {
      if (e.currentTarget.getAttribute('aria-disabled') === 'true') e.preventDefault();
    });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && document.body.classList.contains('filters-open')) {
        setFilterPanel(false);
      } else if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        autoRun();
      }
    });
    window.addEventListener('resize', () => {
      if (window.innerWidth > 900 && document.body.classList.contains('filters-open')) {
        setFilterPanel(false, false);
      }
    });

    // Initial population.
    refreshPackages();
    updateExtraCount();
    updateActionButtons();
