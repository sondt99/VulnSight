const { POPULAR, SCENARIOS, OSV_SUPPORTED, AI_CONFIGURED } = window.BOOT;
    const $ = (s) => document.querySelector(s);
    const $$ = (s) => Array.from(document.querySelectorAll(s));
    let LAST = [];           // last result set (normalized advisories)
    let AI = {};             // ghsa_id -> verdict


    function selectedCategories() {
      return $$('input[name=category]:checked').map(c => c.value);
    }

    // --- Package suggestions driven by the chosen ecosystem -----------------
    function refreshPackages() {
      const eco = $('#ecosystem').value;
      const list = POPULAR[eco] || [];
      const sel = $('#affects_pick');
      const prev = sel.value;
      sel.innerHTML = '<option value="">— any package —</option>' +
        list.map(p => `<option value="${p}">${p}</option>`).join('');
      if (list.includes(prev)) sel.value = prev;
    }

    // --- Published preset -> GitHub advisory date filter --------------------
    function publishedFilter() {
      const v = $('#published').value;
      if (!v || v === 'any') return '';
      if (v === '2020') return '>=2020-01-01';
      const days = {'7d':7,'30d':30,'90d':90,'180d':180,'1y':365,'2y':730}[v];
      if (!days) return '';
      const d = new Date(Date.now() - days*86400000);
      return '>=' + d.toISOString().slice(0,10);
    }

    // --- Extra CWE tick-list ------------------------------------------------
    function selectedExtraCwes() {
      return $$('input[name=extra_cwe]:checked').map(c => c.value);
    }
    function updateExtraCount() {
      const n = selectedExtraCwes().length;
      $('#extra_cwes_count').textContent = n ? (n + ' CWE' + (n>1?'s':'')) : 'none';
    }

    // --- Apply a ready-made scenario ---------------------------------------
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
      document.body.appendChild(t);
      setTimeout(() => t.remove(), 5000);
    }

    function esc(s) {
      return (s || '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
    }

    function severityRank(s) {
      return {critical:4, high:3, medium:2, low:1, unknown:0}[s] || 0;
    }

    function renderCard(a) {
      const v = AI[a.ghsa_id] || a.ai;
      let aiHtml = '';
      if (v) {
        if (v.error) {
          aiHtml = `<div class="ai-verdict"><div class="head">⚠️ AI error</div><div class="desc">${esc(v.error)}</div></div>`;
        } else {
          const cls = v.is_match ? 'match' : 'nomatch';
          const icon = v.is_match ? '✅ Match' : '❌ Not a match';
          const pct = Math.round((v.confidence||0)*100);
          aiHtml = `<div class="ai-verdict ${cls}">
            <div class="head">${icon} ${v.vuln_type ? '· <span style="color:var(--accent2)">'+esc(v.vuln_type)+'</span>' : ''}
              <span style="margin-left:auto;color:var(--muted);font-weight:600">${pct}%${v.cached?' · cached':''}</span></div>
            <div class="conf-bar"><div class="conf-fill" data-pct="${pct}"></div></div>
            <div class="desc">${esc(v.reason||'')}</div>
          </div>`;
        }
      }
      const cwes = (a.cwe_labels||[]).map(c =>
        `<span class="badge cwe" title="${esc(c.label)}">${esc(c.id)}</span>`).join('');
      const pkgs = (a.packages||[]).slice(0,4).map(p =>
        `<span class="badge pkg">${esc(p.ecosystem)}:${esc(p.name)}${p.first_patched_version?' → '+esc(p.first_patched_version):''}</span>`).join('');
      const morePkgs = (a.packages||[]).length > 4 ? `<span class="badge">+${a.packages.length-4} more</span>` : '';
      const cve = a.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${esc(a.cve_id)}" target="_blank">${esc(a.cve_id)}</a>` : '<span class="muted">no CVE</span>';
      const dimClass = ($('#only_match').checked && v && v.is_match === false) ? 'dim' : '';
      const sevbar = 'sevbar-' + (a.severity || 'unknown');
      const srcs = a.sources || [a.source].filter(Boolean);
      const srcBadge = srcs.length
        ? `<span class="badge src src-${srcs.join('-')}" title="Data source(s)">${srcs.map(s=>s.toUpperCase()).join('+')}</span>` : '';
      const nativeBadge = (a.native && !(a.cwes||[]).length)
        ? `<span class="badge" style="border-color:var(--warn);color:var(--warn)" title="Native OSV record with no CWE — relies on AI">no CWE · AI</span>` : '';
      return `<div class="card ${sevbar} ${dimClass}" data-id="${esc(a.ghsa_id)}">
        <div class="card-top">
          <div class="title">${esc(a.summary)}</div>
          <span class="badge sev ${a.severity}">${esc(a.severity)}</span>
        </div>
        <div class="badges">
          ${srcBadge}${nativeBadge}
          <span class="badge eco">${(a.ecosystems||[]).join(', ')||'—'}</span>
          ${cwes}
        </div>
        <div class="badges">${pkgs}${morePkgs}</div>
        <div class="meta">
          <span><a href="${esc(a.html_url)}" target="_blank">${esc(a.ghsa_id)}</a></span>
          <span>${cve}</span>
          <span>📅 ${esc((a.published_at||'').slice(0,10))}</span>
          ${a.cvss_score ? '<span>CVSS '+a.cvss_score+'</span>' : ''}
        </div>
        ${aiHtml}
      </div>`;
    }

    // The set currently on screen: filtered by "only matches", then sorted.
    function currentItems() {
      let items = LAST.slice();
      if ($('#only_match').checked) {
        items = items.filter(a => {
          const v = AI[a.ghsa_id] || a.ai;
          return v && v.is_match === true;
        });
      }
      // Sort: AI match first (by confidence), then severity, then date.
      items.sort((x, y) => {
        const vx = AI[x.ghsa_id]||x.ai, vy = AI[y.ghsa_id]||y.ai;
        const mx = vx && vx.is_match ? (vx.confidence||0)+1 : 0;
        const my = vy && vy.is_match ? (vy.confidence||0)+1 : 0;
        if (my !== mx) return my - mx;
        const sr = severityRank(y.severity) - severityRank(x.severity);
        if (sr) return sr;
        return (y.published_at||'').localeCompare(x.published_at||'');
      });
      return items;
    }

    function failedIds() {
      return LAST.map(a => a.ghsa_id).filter(id => AI[id] && AI[id].error);
    }

    function updateActionButtons() {
      const has = LAST.length > 0;
      $('#ai-btn').disabled = !has;
      $('#only_match').disabled = !has;
      $('#export-btn').style.opacity = has ? '1' : '.4';
      $('#export-btn').style.pointerEvents = has ? 'auto' : 'none';
      const nfail = failedIds().length;
      const rb = $('#retry-btn');
      rb.disabled = nfail === 0;
      rb.textContent = nfail ? `↻ Retry failed (${nfail})` : '↻ Retry failed';
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
      // Animate confidence bars from 0 -> target after paint.
      requestAnimationFrame(() => {
        $$('.conf-fill').forEach(f => { f.style.width = (f.dataset.pct || 0) + '%'; });
      });
      updateActionButtons();
    }

    async function search() {
      const cats = selectedCategories();
      if (!cats.length) { toast('Select at least one bug class', 'err'); return; }
      $('#search-btn').disabled = true;
      $('#results').innerHTML = `<div class="loading"><span class="spinner"></span>Fetching advisories from GitHub…</div>`;
      $('#summary').textContent = 'Searching…';
      const sources = $$('input[name=source]:checked').map(c => c.value);
      if (!sources.length) { toast('Select at least one data source', 'err'); $('#search-btn').disabled = false; return; }
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
        LAST.forEach(a => { if (a.ai) AI[a.ghsa_id] = a.ai; });
        const cached = LAST.filter(a => a.ai).length;
        const ps = data.query.per_source || {};
        const psText = Object.keys(ps).length ? ' · ' + Object.entries(ps).map(([k,v]) => `${k.toUpperCase()}:${v}`).join(' + ') : '';
        $('#summary').innerHTML = `<b>${data.count}</b> advisories${psText} · CWEs: <code>${data.query.cwes.join(', ')}</code>`
          + (cached ? ` · <span style="color:var(--accent2)">${cached} already AI-scored</span>` : '');
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
      }
    }

    // One classify request for a set of ids. Merges verdicts into AI and
    // returns the number of results that came back as errors.
    async function classifyIds(ids) {
      if (!ids.length) return 0;
      const cats = selectedCategories();
      const r = await fetch('/api/ai/classify', {method:'POST', headers:{'content-type':'application/json'},
        body: JSON.stringify({category: cats[0] || 'bac', ghsa_ids: ids})});
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || 'AI failed');
      Object.assign(AI, data.verdicts);
      return Object.values(data.verdicts).filter(v => v.error).length;
    }

    async function refineAI() {
      if (!LAST.length) return;
      const ids = LAST.map(a => a.ghsa_id);
      $('#ai-btn').disabled = true;
      $('#retry-btn').disabled = true;
      const orig = $('#ai-btn').textContent;
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
        const matches = LAST.filter(a => (AI[a.ghsa_id]||{}).is_match).length;
        const errs = failedIds().length;
        toast(`AI done: ${matches} matches` + (errs ? `, ${errs} still failing — use ↻ Retry failed` : ''),
              errs ? 'err' : 'ok');
      } catch (e) {
        toast(e.message, 'err');
      } finally {
        $('#ai-btn').textContent = orig;
        render();
      }
    }

    async function retryFailed() {
      const fails = failedIds();
      if (!fails.length) return;
      $('#retry-btn').disabled = true;
      const orig = $('#retry-btn').textContent;
      $('#retry-btn').innerHTML = '<span class="spinner"></span>Retrying…';
      try {
        await classifyIds(fails);
        render();
        const left = failedIds().length;
        toast(left ? `${left} still failing` : 'All retried successfully', left ? 'err' : 'ok');
      } catch (e) {
        toast(e.message, 'err');
      } finally {
        $('#retry-btn').textContent = orig;
        render();
      }
    }

    async function testAI() {
      const pill = $('#ai-test-pill');
      pill.textContent = '⚡ testing…';
      try {
        const r = await fetch('/api/ai/test');
        const d = await r.json();
        if (d.ok) { pill.textContent = '⚡ AI OK'; toast('AI reachable ('+d.model+'): '+d.reply, 'ok'); }
        else { pill.textContent = '⚡ AI fail'; toast('AI test failed: '+d.error, 'err'); }
      } catch (e) { pill.textContent = '⚡ AI fail'; toast(e.message, 'err'); }
    }

    // Any advisory in the current set that the AI has NOT scored yet.
    function unscoredCount() {
      return LAST.filter(a => !(AI[a.ghsa_id] || a.ai)).length;
    }

    // --- Export -------------------------------------------------------------
    function flatRow(a) {
      const v = AI[a.ghsa_id] || a.ai || {};
      return {
        ghsa_id: a.ghsa_id,
        cve_id: a.cve_id || '',
        sources: (a.sources || [a.source]).filter(Boolean).join('|'),
        severity: a.severity || '',
        cvss: a.cvss_score || '',
        ecosystems: (a.ecosystems || []).join('|'),
        packages: (a.packages || []).map(p => `${p.ecosystem}:${p.name}${p.first_patched_version?'@'+p.first_patched_version:''}`).join('|'),
        cwes: (a.cwes || []).join('|'),
        ai_match: v.error ? 'ERROR' : (v.is_match === true ? 'yes' : (v.is_match === false ? 'no' : '')),
        ai_confidence: v.confidence != null ? v.confidence : '',
        ai_vuln_type: v.vuln_type || '',
        ai_reason: v.error ? v.error : (v.reason || ''),
        published: (a.published_at || '').slice(0, 10),
        url: a.html_url || '',
        summary: a.summary || '',
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
      const s = String(v == null ? '' : v);
      return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    }
    function doExport(fmt) {
      let items = currentItems();
      if (fmt === 'csv-matches') items = items.filter(a => (AI[a.ghsa_id]||a.ai||{}).is_match === true);
      if (!items.length) { toast('Nothing to export', 'err'); return; }
      const rows = items.map(flatRow);
      if (fmt === 'json') {
        download(`ghsa-advisories-${stamp()}.json`, JSON.stringify(rows, null, 2), 'application/json');
      } else {
        const cols = Object.keys(rows[0]);
        const csv = [cols.join(',')].concat(rows.map(r => cols.map(c => csvCell(r[c])).join(','))).join('\n');
        download(`ghsa-advisories-${stamp()}.csv`, '﻿' + csv, 'text/csv;charset=utf-8');
      }
      $('.export-menu').removeAttribute('open');
      toast(`Exported ${items.length} advisory(ies) as ${fmt.startsWith('csv')?'CSV':'JSON'}`, 'ok');
    }

    function setSources(list) {
      $$('input[name=source]').forEach(c => { c.checked = list.includes(c.value); });
    }

    // One-click pipeline: optimal sources -> search -> AI (+retry) -> only matches.
    async function autoRun() {
      const cats = selectedCategories();
      if (!cats.length) { toast('Select at least one bug class', 'err'); return; }
      const eco = $('#ecosystem').value;
      const osvOk = OSV_SUPPORTED.includes(eco);
      // GHSA covers CWE-tagged advisories; OSV-native adds the no-CWE records the
      // AI can still catch. For "any" ecosystem OSV can't be used, so GHSA only.
      setSources(osvOk ? ['ghsa', 'osv-native'] : ['ghsa']);

      const btn = $('#auto-btn');
      btn.disabled = true;
      const orig = btn.textContent;
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
        btn.textContent = orig;
      }
    }

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
    $('#ecosystem').addEventListener('change', refreshPackages);
    $('#scenario').addEventListener('change', e => applyScenario(e.target.value));
    $$('input[name=extra_cwe]').forEach(c => c.addEventListener('change', updateExtraCount));
    $$('.export-pop button').forEach(b => b.addEventListener('click', () => doExport(b.dataset.fmt)));
    // Close the export menu when clicking outside it.
    document.addEventListener('click', e => {
      const m = $('.export-menu');
      if (m && m.open && !m.contains(e.target)) m.removeAttribute('open');
    });
    document.addEventListener('keydown', e => { if (e.key === 'Enter' && e.target.tagName === 'SELECT') autoRun(); });

    // Initial population.
    refreshPackages();
    updateExtraCount();
    updateActionButtons();
