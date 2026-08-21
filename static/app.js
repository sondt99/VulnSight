// === Configuration & State ===
const { POPULAR, CLASSES, OSV_SUPPORTED, AI_CONFIGURED, AI_CALL_BUDGET, AUTH_REQUIRED } = window.BOOT;
    const $ = (s) => document.querySelector(s);
    const $$ = (s) => Array.from(document.querySelectorAll(s));
    let LAST = [];           // last result set (normalized advisories)
    let AI = {};             // advisory_id -> verdict
    // The sorted category list `AI` was scored against. A verdict for "bac" says
    // nothing about "sqli", so the queue must not be filtered or exported as if
    // it did once the selection moves on.
    let AI_CATS = null;
    // Facts about the last successful search, so the summary can be re-rendered
    // whenever the visible set changes instead of going stale after one write.
    let SEARCH_META = null;
    let filterReturnFocus = null;

    // === DOM Helpers ===
    function setResultsBusy(busy) {
      $('#results').setAttribute('aria-busy', String(Boolean(busy)));
    }

    // Below this width the rail is a modal slide-over, not a static sidebar.
    const MODAL_PANEL_WIDTH = 900;

    function setFilterPanel(open, restoreFocus = true) {
      const isOpen = Boolean(open);
      const modal = window.innerWidth <= MODAL_PANEL_WIDTH;
      const rail = $('#control-panel');
      if (isOpen) filterReturnFocus = document.activeElement;
      document.body.classList.toggle('filters-open', isOpen);
      $('#filters-toggle').setAttribute('aria-expanded', String(isOpen));
      // The scrim sits *behind* the panel; focusing it stranded keyboard users
      // outside the dialog. Escape and the × button are the accessible exits.
      $('#filter-scrim').tabIndex = -1;

      // The panel is visually modal (scrim + locked body scroll), so make it
      // modal for assistive tech too and stop Tab from wandering behind it.
      if (isOpen && modal) {
        rail.setAttribute('role', 'dialog');
        rail.setAttribute('aria-modal', 'true');
      } else {
        rail.removeAttribute('role');
        rail.removeAttribute('aria-modal');
      }
      [$('.topbar'), $('#workspace')].forEach(el => {
        if (el) el.inert = isOpen && modal;
      });

      if (isOpen) {
        focusWhenVisible(rail, $('#filters-close'));
      } else if (restoreFocus && filterReturnFocus && document.contains(filterReturnFocus)) {
        filterReturnFocus.focus();
      }
    }

    const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),'
      + 'select:not([disabled]),summary,[tabindex]:not([tabindex="-1"])';

    // `inert` keeps focus out of the background but nothing brings it back from
    // the end of the document, so wrap Tab inside the open panel.
    function trapPanelTab(e) {
      if (e.key !== 'Tab') return;
      if (!document.body.classList.contains('filters-open')) return;
      if (window.innerWidth > MODAL_PANEL_WIDTH) return;
      const items = Array.from($('#control-panel').querySelectorAll(FOCUSABLE))
        .filter(el => el.offsetParent !== null);
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }

    // `visibility` is part of the panel's transition, so on the next frame the
    // target is still visibility:hidden and .focus() silently does nothing.
    function focusWhenVisible(transitioningEl, target) {
      let done = false;
      const attempt = () => {
        if (done || !target) return;
        done = true;
        transitioningEl.removeEventListener('transitionend', attempt);
        target.focus();
      };
      transitioningEl.addEventListener('transitionend', attempt);
      setTimeout(attempt, 400);   // fallback if the transition never fires
    }


    // Query targets are curated classes plus any single CWEs picked from the
    // catalog ("cwe:639"); the backend treats both the same way.
    function selectedCategories() {
      return $$('input[name=category]:checked').map(c => c.value).concat(selectedCweKeys());
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
    function publishedWindow(value) {
      if (!value || value === 'any') return '';
      if (value === '2020') return '>=2020-01-01';
      const days = {'7d':7,'30d':30,'90d':90,'180d':180,'1y':365,'2y':730}[value];
      if (!days) return '';
      const d = new Date(Date.now() - days*86400000);
      return '>=' + d.toISOString().slice(0,10);
    }

    // The full form as plain data. One shape feeds the API payload and the
    // recent-search history, so a replayed search is byte-for-byte the same.
    function formState() {
      return {
        categories: selectedCategories(),
        include_extended: $('#include_extended').checked,
        ecosystem: $('#ecosystem').value,
        severity: $('#severity').value,
        affects: $('#affects_pick').value,
        published: $('#published').value,
        max_results: parseInt($('#max_results').value) || 100,
        sort: $('#sort').value,
        direction: $('#direction').value,
        type: $('#type').value,
        sources: $$('input[name=source]:checked').map(c => c.value),
      };
    }

    function setSelectValue(selector, value) {
      const el = $(selector);
      if (!el || value == null) return;
      if (Array.from(el.options).some(o => o.value === value)) el.value = value;
    }

    function applyState(state) {
      if (!state) return;
      let categories = sanitizeCategories(state.categories);
      // Syntax alone is not enough: a stored "cwe:9999999" would restore as a
      // chip and only fail later, server-side. Drop what MITRE does not define
      // (checked only once the catalog has actually loaded).
      if (ENTRIES.some(entry => entry.kind === 'cwe')) {
        const known = new Set(ENTRIES.filter(e => e.kind === 'cwe').map(e => e.key));
        const dropped = categories.filter(k => k.indexOf('cwe:') === 0 && !known.has(k));
        if (dropped.length) {
          categories = categories.filter(k => dropped.indexOf(k) === -1);
          toast('Skipped unknown ' + dropped.join(', ') + ' from that saved search', 'err');
        }
      }
      PICKED.clear();
      categories.forEach(key => {
        if (key.indexOf('cwe:') === 0) PICKED.add(key.slice(4));
      });
      $$('input[name=category]').forEach(c => { c.checked = categories.includes(c.value); });
      $('#include_extended').checked = state.include_extended !== false;
      setSelectValue('#ecosystem', state.ecosystem);
      refreshPackages();                       // options depend on the ecosystem
      setSelectValue('#affects_pick', state.affects);
      setSelectValue('#severity', state.severity);
      setSelectValue('#published', state.published);
      setSelectValue('#max_results', String(state.max_results || 100));
      setSelectValue('#sort', state.sort);
      setSelectValue('#direction', state.direction);
      setSelectValue('#type', state.type);
      const sources = (state.sources || []).filter(
        s => $$('input[name=source]').some(box => box.value === s));
      setSources(sources.length ? sources : ['ghsa']);
      // Never replay a forced 10 MB OSV re-download from a history click — but
      // say so, rather than silently unticking a box the user just ticked.
      if ($('#refresh_osv').checked) {
        $('#refresh_osv').checked = false;
        toast('“Force-refresh OSV cache” left off for this replay', 'ok');
      }
      renderSelection();
    }

    // localStorage is user-writable, so a restored query is re-validated here
    // rather than trusted straight into the API.
    function sanitizeCategories(values) {
      if (!Array.isArray(values)) return [];
      const known = new Set(CLASSES.map(c => c.key));
      return values.filter(v => typeof v === 'string'
        && (known.has(v) || /^cwe:[1-9][0-9]{0,6}$/.test(v)));
    }

    // === Bug-class filter ===
    // With 29 classes the browsable list needs narrowing. A selected class is
    // never hidden: it is part of the query, so it must stay visible and
    // un-tickable-by-accident even when it does not match the filter.
    function filterClasses() {
      const query = $('#class-search').value.trim().toLowerCase();
      const tokens = query.split(/\s+/).filter(Boolean);
      const items = $$('#taxonomy-list .taxonomy-item');
      let shown = 0;
      items.forEach(item => {
        const checked = item.querySelector('input').checked;
        const hay = CLASS_HAY[item.dataset.key] || '';
        const match = !tokens.length || tokens.every(t => hay.includes(t));
        const visible = match || checked;
        item.hidden = !visible;
        item.classList.toggle('filtered-keep', visible && !match);
        if (visible) shown++;
      });
      // Hide a group heading once everything under it is filtered out.
      $$('#taxonomy-list .taxonomy-group').forEach(heading => {
        const group = heading.dataset.group;
        heading.hidden = !items.some(
          item => !item.hidden && item.dataset.group === group);
      });
      $('#taxonomy-empty').hidden = shown > 0;
      const total = items.length;
      $('#class-count').textContent = query
        ? `${shown} of ${total} shown`
        : `${total} available`;
    }

    // === Recent searches ===
    const HISTORY_KEY = 'vulnsight_history';
    const HISTORY_MAX = 12;
    let CURRENT_SIG = null;   // signature of the search currently on screen

    function loadHistory() {
      try {
        const raw = JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
        if (!Array.isArray(raw)) return [];
        return raw.filter(e => e && typeof e.sig === 'string' && e.query
          && sanitizeCategories(e.query.categories).length);
      } catch (_) {
        return [];
      }
    }

    function saveHistory(list) {
      try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, HISTORY_MAX)));
      } catch (_) {
        // Quota or private mode: history is a convenience, never required state.
      }
    }

    function stateSignature(state) {
      return JSON.stringify([
        state.categories.slice().sort(), state.include_extended, state.ecosystem,
        state.severity, state.affects, state.published, state.max_results,
        state.sort, state.direction, state.type, state.sources.slice().sort(),
      ]);
    }

    function shortClassLabel(label) {
      return label.split(' (')[0];
    }

    function historyLabel(state) {
      const names = state.categories.map(key => {
        if (key.indexOf('cwe:') === 0) return 'CWE-' + key.slice(4);
        const cls = CLASSES.find(c => c.key === key);
        return cls ? shortClassLabel(cls.label) : key;
      });
      const shown = names.slice(0, 2).join(' + ')
        + (names.length > 2 ? ' +' + (names.length - 2) : '');
      const parts = [shown || 'no target', state.ecosystem];
      if (state.severity && state.severity !== 'any') parts.push(state.severity);
      if (state.affects) parts.push(state.affects.split(':').pop());
      if (state.published && state.published !== 'any') {
        // Look the option up by value rather than interpolating into a selector.
        const option = Array.from($('#published').options)
          .find(o => o.value === state.published);
        parts.push(option ? option.textContent.trim() : state.published);
      }
      return parts.join(' · ');
    }

    // The signature dedupes on sources / max results / sort as well, so two rows
    // could look identical and restore different queries. Surface those here.
    function historyDetail(state) {
      const parts = [(state.sources || []).map(s => s.toUpperCase()).join('+') || 'no source'];
      parts.push('max ' + (state.max_results || 100));
      if (state.sort && state.sort !== 'published') parts.push(state.sort.replace(/_/g, ' '));
      if (state.direction === 'asc') parts.push('oldest first');
      if (state.type && state.type !== 'reviewed') parts.push(state.type);
      if (state.include_extended === false) parts.push('core CWEs only');
      return parts.join(' · ');
    }

    function recordHistory(state, count) {
      const sig = stateSignature(state);
      const list = loadHistory().filter(e => e.sig !== sig);
      list.unshift({
        sig: sig,
        at: Date.now(),
        count: count,
        label: historyLabel(state),
        query: state,
      });
      saveHistory(list);
      CURRENT_SIG = sig;
      renderHistory();
    }

    // A row that says "100 hits" when the user remembers "7 confirmed" is not
    // the search they are looking for, so record the AI outcome too.
    function recordHistoryMatches(matches) {
      if (!CURRENT_SIG) return;
      const list = loadHistory();
      const entry = list.find(e => e.sig === CURRENT_SIG);
      if (!entry) return;
      entry.matches = matches;
      saveHistory(list);
      renderHistory();
    }

    function relativeTime(ms) {
      // A missing or corrupted timestamp must not render as "20685d ago";
      // note that Number(null) is 0, so a plain isFinite check is not enough.
      const at = Number(ms);
      if (!at || !Number.isFinite(at)) return 'just now';
      const mins = Math.round((Date.now() - at) / 60000);
      if (mins < 1) return 'just now';
      if (mins < 60) return mins + 'm ago';
      const hours = Math.round(mins / 60);
      if (hours < 24) return hours + 'h ago';
      const days = Math.round(hours / 24);
      return days === 1 ? 'yesterday' : days + 'd ago';
    }

    function renderHistory() {
      const list = loadHistory();
      const section = $('#history-section');
      section.hidden = list.length === 0;
      $('#history-list').innerHTML = list.map(entry => {
        const count = Number(entry.count) || 0;
        // Recomputed from the stored query, so entries written by an older
        // build gain the detail line too.
        const label = entry.query ? historyLabel(entry.query) : (entry.label || '');
        const detail = entry.query ? historyDetail(entry.query) : '';
        const matches = Number.isFinite(Number(entry.matches))
          ? ` · <span class="history-matches">${Number(entry.matches)} confirmed</span>` : '';
        // Keyed by signature, not array index: two tabs share this storage and a
        // stale index would restore — or delete — the wrong row.
        return `<li class="history-item">
          <button type="button" class="history-run" data-sig="${safeAttr(entry.sig)}"
              title="${safeAttr(label + (detail ? ' — ' + detail : ''))} — click to restore and search again">
            <span class="history-label">${esc(label)}</span>
            <span class="history-meta">
              <span class="history-count">${count} hit${count === 1 ? '' : 's'}</span>${matches}
              <span class="history-detail">${esc(detail)}</span>
              <span class="history-when">${esc(relativeTime(entry.at))}</span>
            </span>
          </button>
          <button type="button" class="history-drop" data-sig="${safeAttr(entry.sig)}"
              aria-label="Forget ${safeAttr(label || 'this search')}">×</button>
        </li>`;
      }).join('');
    }


    // === CWE / bug-name finder ===
    // The whole MITRE catalog is fetched once and searched in memory, so typing
    // never costs a round trip. A picked CWE becomes the pseudo-class "cwe:<id>",
    // which the backend treats exactly like a curated bug class.
    const COMBO_LIMIT = 40;
    const PICKED = new Set();      // bare CWE ids, e.g. "639"
    let ENTRIES = [];              // searchable rows: curated classes + every CWE
    let comboMatches = [];
    let comboActive = -1;
    let catalogError = '';

    CLASSES.forEach(c => { c.cwes = (c.core || []).concat(c.extended || []); });

    // Everything a class can be matched on, computed once. Single source of
    // truth for both the finder and the class-list filter — it used to be
    // duplicated into a data-haystack attribute on every row.
    function classHaystack(c) {
      return (c.key + ' ' + c.code + ' ' + c.label + ' ' + (c.description || '')
        + ' ' + c.group + ' ' + (c.terms || []).join(' ')).toLowerCase();
    }
    const CLASS_HAY = {};
    CLASSES.forEach(c => { CLASS_HAY[c.key] = classHaystack(c); });

    // CWE id -> the curated classes that already cover it.
    const CLASS_BY_CWE = {};
    CLASSES.forEach(c => c.cwes.forEach(id => {
      (CLASS_BY_CWE[id] = CLASS_BY_CWE[id] || []).push(c);
    }));

    function classEntries() {
      return CLASSES.map(c => ({
        kind: 'class',
        key: c.key,
        // Curated short code, not the raw key: "DESERIALIZATION" would overflow
        // the fixed-width code column and squeeze every CWE name beside it.
        code: c.code || c.key.toUpperCase(),
        label: c.label,
        note: (c.cwes || []).length + ' CWEs',
        // The community terms are what people type ("__proto__", "toctou"),
        // so they must be searchable and worth showing.
        aliases: (c.terms || []).slice(0, 4),
        hay: CLASS_HAY[c.key],
      }));
    }

    function buildEntries(payload) {
      const rows = (payload && payload.rows) || [];
      ENTRIES = classEntries().concat(rows.map(row => {
        const [id, label, aliasText, level] = row;
        const aliases = aliasText ? aliasText.split('|') : [];
        return {
          kind: 'cwe',
          key: 'cwe:' + id,
          id: id,
          code: 'CWE-' + id,
          label: label,
          note: level,
          aliases: aliases,
          hay: (id + ' ' + label + ' ' + aliasText).toLowerCase(),
        };
      }));
    }

    async function loadCweCatalog() {
      // Curated classes are searchable before the catalog request resolves, and
      // remain searchable if it never does.
      ENTRIES = classEntries();
      try {
        const r = await fetch('/api/cwes', {headers: {'accept': 'application/json'}});
        if (!r.ok) throw new Error('catalog request failed (' + r.status + ')');
        buildEntries(await r.json());
      } catch (e) {
        catalogError = e.message;
        toast('CWE catalog failed to load: ' + e.message, 'err');
      }
    }

    function escapeRe(s) {
      return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    // Higher score = better match. Ordering is what makes a 944-row catalog
    // usable: exact ID, then ID prefix, then exact/prefix name or alias, then
    // "contains every word".
    function scoreEntry(entry, q, idQuery, tokens, boundary) {
      let score = 0;
      if (entry.kind === 'cwe' && idQuery) {
        if (entry.id === idQuery) return 2000;
        if (entry.id.startsWith(idQuery)) score = 1200 - entry.id.length;
      }
      const label = entry.label.toLowerCase();
      const aliases = entry.aliases.map(a => a.toLowerCase());
      let text = 0;
      if (label === q || aliases.includes(q)) text = 900;
      else if (label.startsWith(q) || aliases.some(a => a.startsWith(q))) text = 800;
      else if (boundary.test(entry.hay)) text = 700;
      else if (tokens.length > 1 && tokens.every(t => entry.hay.includes(t))) text = 600;
      else if (entry.hay.includes(q)) text = 500;
      score = Math.max(score, text);
      if (!score) return 0;
      // A curated class beats a lone CWE, and a CWE a class already covers
      // beats an unrelated one — both are the likelier intent.
      if (entry.kind === 'class') score += 60;
      else if (CLASS_BY_CWE[entry.id]) score += 30;
      return score;
    }

    function searchEntries(raw) {
      const q = raw.trim().toLowerCase();
      if (!q) return [];
      const idQuery = /^(cwe[-\s]?)?\d+$/.test(q) ? q.replace(/^cwe[-\s]?/, '') : '';
      const tokens = q.split(/\s+/).filter(Boolean);
      const boundary = new RegExp('\\b' + escapeRe(q));
      const scored = [];
      for (const entry of ENTRIES) {
        const score = scoreEntry(entry, q, idQuery, tokens, boundary);
        if (score > 0) scored.push([score, entry]);
      }
      scored.sort((a, b) => b[0] - a[0]
        || (a[1].kind === 'cwe' && b[1].kind === 'cwe' ? Number(a[1].id) - Number(b[1].id) : 0)
        || a[1].label.localeCompare(b[1].label));
      return scored.slice(0, COMBO_LIMIT).map(pair => pair[1]);
    }

    function isPicked(entry) {
      return entry.kind === 'class'
        ? $$('input[name=category]').some(c => c.value === entry.key && c.checked)
        : PICKED.has(entry.id);
    }

    // Two rows: code + full name + level, then the aliases and the curated class
    // that already covers this CWE. The name gets the space it needs; the
    // secondary line is what truncates.
    function comboOptionHtml(entry, index) {
      // The sidebar is ~300px wide, so the covering class is shown as its short
      // key ("BAC") with the full name on hover — the CWE name gets the room.
      const cls = entry.kind === 'cwe' && (CLASS_BY_CWE[entry.id] || [])[0];
      const covered = cls
        ? `<span class="combo-in" title="Already covered by ${safeAttr(cls.label)}">${esc(cls.code || cls.key.toUpperCase())}</span>`
        : '';
      const aliasText = entry.aliases.join(' · ');
      const aliases = entry.aliases.length
        ? `<span class="combo-alias" title="${safeAttr(aliasText)}">${esc(entry.aliases.slice(0, 3).join(' · '))}</span>` : '';
      const sub = aliases || covered
        ? `<span class="combo-sub">${aliases}${covered}</span>` : '';
      // "Already added" was conveyed only by opacity and a CSS checkmark, and
      // aria-selected="false" told assistive tech the opposite.
      const picked = isPicked(entry);
      return `<li class="combo-option ${entry.kind}${picked ? ' picked' : ''}"
          role="option" id="cwe-option-${index}" data-key="${safeAttr(entry.key)}"
          aria-selected="${index === comboActive}"${picked ? ' aria-disabled="true"' : ''}>
        <span class="combo-head">
          <span class="combo-code">${esc(entry.code)}</span>
          <span class="combo-label" title="${safeAttr(entry.label)}">${esc(entry.label)}</span>
          <span class="combo-note">${esc(entry.note)}</span>
        </span>
        ${sub}${picked ? '<span class="sr-only">already added</span>' : ''}
      </li>`;
    }

    function renderCombo() {
      const list = $('#cwe-options');
      const input = $('#cwe-search');
      const query = input.value.trim();
      $('#cwe-clear').hidden = !query;
      if (!query) {
        list.hidden = true;
        list.innerHTML = '';
        input.setAttribute('aria-expanded', 'false');
        input.removeAttribute('aria-activedescendant');
        return;
      }
      comboMatches = searchEntries(query);
      if (!comboMatches.length) {
        const why = catalogError ? 'CWE catalog unavailable' : 'No bug class or CWE matches';
        list.innerHTML = `<li class="combo-empty">${esc(why)} “${esc(query)}”</li>`;
      } else {
        if (comboActive >= comboMatches.length) comboActive = comboMatches.length - 1;
        list.innerHTML = comboMatches.map(comboOptionHtml).join('');
      }
      list.hidden = false;
      input.setAttribute('aria-expanded', 'true');
      const active = comboActive >= 0 && comboMatches.length ? `cwe-option-${comboActive}` : '';
      if (active) input.setAttribute('aria-activedescendant', active);
      else input.removeAttribute('aria-activedescendant');
    }

    function closeCombo() {
      comboActive = -1;
      comboMatches = [];
      const list = $('#cwe-options');
      list.hidden = true;
      list.innerHTML = '';
      $('#cwe-search').setAttribute('aria-expanded', 'false');
      $('#cwe-search').removeAttribute('aria-activedescendant');
    }

    function moveComboActive(delta) {
      if (!comboMatches.length) return;
      const last = comboMatches.length - 1;
      comboActive = comboActive < 0
        ? (delta > 0 ? 0 : last)
        : Math.min(last, Math.max(0, comboActive + delta));
      renderCombo();
      const el = $(`#cwe-option-${comboActive}`);
      if (el) el.scrollIntoView({block: 'nearest'});
    }

    function announceSelection(message) {
      $('#selection-live').textContent = message;
    }

    function pickEntry(entry) {
      if (!entry) return;
      if (entry.kind === 'class') {
        const box = $$('input[name=category]').find(c => c.value === entry.key);
        if (box) {
          box.checked = true;
          box.closest('.cat').classList.add('just-added');
          setTimeout(() => box.closest('.cat').classList.remove('just-added'), 900);
        }
        announceSelection(entry.label + ' class added');
      } else {
        PICKED.add(entry.id);
        announceSelection(entry.code + ' added');
      }
      $('#cwe-search').value = '';
      closeCombo();
      renderSelection();
      $('#cwe-search').focus();
    }

    function selectedCweKeys() {
      return Array.from(PICKED).sort((a, b) => Number(a) - Number(b)).map(id => 'cwe:' + id);
    }

    function cweEntry(id) {
      return ENTRIES.find(e => e.kind === 'cwe' && e.id === id);
    }

    function renderSelection() {
      const classBoxes = $$('input[name=category]:checked');
      const ids = Array.from(PICKED).sort((a, b) => Number(a) - Number(b));
      const chips = classBoxes.map(box => {
        const cls = CLASSES.find(c => c.key === box.value);
        const label = cls ? cls.label : box.value;
        return `<span class="chip chip-class" role="listitem">
          <span class="chip-text" title="${safeAttr(label)}">${esc(label)}</span>
          <button type="button" class="chip-x" data-drop-class="${safeAttr(box.value)}"
            aria-label="Remove ${safeAttr(label)}">×</button>
        </span>`;
      }).concat(ids.map(id => {
        const entry = cweEntry(id);
        const label = entry ? entry.label : 'CWE-' + id;
        return `<span class="chip chip-cwe" role="listitem">
          <span class="chip-code">CWE-${esc(id)}</span>
          <span class="chip-text" title="${safeAttr(label)}">${esc(label)}</span>
          <button type="button" class="chip-x" data-drop-cwe="${safeAttr(id)}"
            aria-label="Remove CWE-${safeAttr(id)}">×</button>
        </span>`;
      }));
      $('#selected-chips').innerHTML = chips.length
        ? chips.join('')
        : '<span class="chips-empty">Nothing selected — search above or tick a class.</span>';
      const total = classBoxes.length + ids.length;
      $('#selection-count').textContent = total
        ? `${total} selected · ${total} AI pass${total > 1 ? 'es' : ''} per advisory`
        : '';
      updateNvdHint();
      // Changing the selection can invalidate verdicts already on screen.
      updateActionButtons();
    }

    // NVD costs one rate-limited request per CWE, so make that cost visible
    // before the user starts a search that would take minutes.
    function updateNvdHint() {
      const hint = $('.nvd-hint');
      if (!hint) return;
      const cwes = estimatedCweCount();
      const seconds = Math.round(cwes * 7);
      hint.textContent = $('input[name=source][value=nvd]').checked && cwes > 1
        ? `NVD: ~${cwes} CWEs × ~7s ≈ ${seconds}s without NVD_API_KEY. Free key at nvd.nist.gov`
        : 'Without NVD_API_KEY, queries take ~7s per CWE. Free key at nvd.nist.gov';
    }

    // Exactly what resolve_cwes() will produce server-side for this selection.
    function estimatedCweCount() {
      const extended = $('#include_extended').checked;
      const set = new Set(PICKED);
      $$('input[name=category]:checked').forEach(box => {
        const cls = CLASSES.find(c => c.key === box.value);
        if (!cls) return;
        (cls.core || []).forEach(id => set.add(id));
        if (extended) (cls.extended || []).forEach(id => set.add(id));
      });
      return set.size;
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

    function showAuthGate(msg) {
      const gate = $('#auth-gate');
      if (!gate) return;
      gate.hidden = false;
      const hint = $('#auth-gate-hint');
      if (hint && msg) hint.textContent = msg;
      const input = $('#auth-token');
      if (input) {
        input.value = '';
        requestAnimationFrame(() => input.focus());
      }
    }

    function hideAuthGate() {
      const gate = $('#auth-gate');
      if (gate) gate.hidden = true;
    }

    function saveAuthToken() {
      const input = $('#auth-token');
      const value = (input && input.value || '').trim();
      if (!value) { toast('Enter the API token', 'err'); return; }
      sessionStorage.setItem('vulnsight_token', value);
      hideAuthGate();
      toast('Token saved for this tab', 'ok');
    }

    async function apiPost(url, payload) {
      const headers = {'content-type': 'application/json'};
      const token = sessionStorage.getItem('vulnsight_token') || '';
      if (token) headers['X-VulnSight-Token'] = token;
      const r = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload === undefined ? {} : payload),
      });
      let data = {};
      try { data = await r.json(); } catch (_) { data = {}; }
      if (r.status === 401) {
        sessionStorage.removeItem('vulnsight_token');
        if (AUTH_REQUIRED) {
          showAuthGate('That token was rejected. Check VULNSIGHT_API_TOKEN.');
        }
        throw new Error(data.error || 'Authentication required.');
      }
      if (!r.ok) throw new Error(data.error || ('request failed (' + r.status + ')'));
      return data;
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
          // Quota/rate-limit answers are the common case and the raw upstream
          // string does not tell the user what to do about it.
          const quota = /429|quota|rate.?limit|too many/i.test(v.error);
          const advice = quota
            ? 'The AI provider is rate-limiting or out of quota — wait a moment, then retry.'
            : esc(v.error);
          aiHtml = `<div class="ai-verdict error" role="alert">
            <div class="verdict-head">
              <span class="verdict-state">AI error</span>
              <button type="button" class="verdict-retry" data-retry="${safeAttr(a.advisory_id)}">Retry</button>
            </div>
            <div class="desc">${advice}</div>
          </div>`;
        } else {
          const incomplete = v.has_errors && v.is_match !== true;
          // 'partial' used to be an empty class, leaving the one state that
          // means "scoring failed halfway" as the only one with no colour.
          const cls = v.is_match ? 'match' : (incomplete ? 'partial' : 'nomatch');
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
      // The CWE *is* the taxonomy this tool searches by, so show the id and the
      // name inline; the name used to live only in a title, unreachable by
      // touch and by keyboard.
      const cwes = (a.cwe_labels||[]).map(c =>
        `<span class="badge cwe" title="CWE-${esc(c.id)}: ${esc(c.label)}">CWE-${esc(c.id)}<small>${esc(c.label)}</small></span>`).join('');
      const ecoNames = (a.ecosystems||[]).filter(Boolean);
      // Package badges repeat the ecosystem the eco badge already states.
      const pkgs = (a.packages||[]).slice(0,4).map(p => {
        const name = ecoNames.length === 1 && p.ecosystem === ecoNames[0]
          ? esc(p.name) : `${esc(p.ecosystem)}:${esc(p.name)}`;
        return `<span class="badge pkg" title="${safeAttr(p.ecosystem + ':' + p.name)}">${name}${p.first_patched_version?' → '+esc(p.first_patched_version):''}</span>`;
      }).join('');
      const morePkgs = (a.packages||[]).length > 4 ? `<span class="badge">+${a.packages.length-4} more</span>` : '';
      const cve = a.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(a.cve_id)}" target="_blank" rel="noopener noreferrer">${esc(a.cve_id)}</a>` : '<span class="muted">no CVE</span>';
      // A withdrawn advisory is not actionable — de-emphasise it the way
      // non-matches already are.
      const dimClass = a.withdrawn_at ? 'dim' : '';
      const safeSeverity = ['critical','high','medium','low','unknown'].includes(a.severity) ? a.severity : 'unknown';
      const sevbar = 'sevbar-' + safeSeverity;
      const srcs = a.sources || [a.source].filter(Boolean);
      const sourceClass = srcs.map(s => String(s).toLowerCase().replace(/[^a-z0-9-]/g, '')).filter(Boolean).join('-');
      const srcBadge = srcs.length
        ? `<span class="badge src src-${sourceClass}" title="Data source(s)">${srcs.map(s=>esc(String(s).toUpperCase())).join('+')}</span>` : '';
      const nativeBadge = (a.native && !(a.cwes||[]).length)
        ? `<span class="badge badge--native" title="Native OSV record with no CWE — relies on AI">NO CWE · AI</span>` : '';
      const withdrawnBadge = a.withdrawn_at
        ? `<span class="badge badge--withdrawn">WITHDRAWN ${esc(String(a.withdrawn_at).slice(0,10))}</span>` : '';
      const kevBadge = a.kev
        ? `<span class="badge badge--kev" title="CISA Known Exploited Vulnerability">KEV / EXPLOITED</span>` : '';
      // Number(null) is 0 and finite, which used to render "no EPSS data" as a
      // measured 0.00% exploit probability — a fabricated fact in a triage tool.
      const hasEpss = a.epss_percentage != null && Number.isFinite(Number(a.epss_percentage));
      const epssPct = hasEpss ? Number(a.epss_percentage) : NaN;
      const hasPercentile = a.epss_percentile != null && Number.isFinite(Number(a.epss_percentile));
      const epssMeta = hasEpss
        ? `<span class="epss-meter" title="EPSS exploit probability${hasPercentile ? ' · percentile ' + Math.round(Number(a.epss_percentile) * 100) : ''}">
            <span class="meta-label">EPSS</span>
            <progress max="100" value="${Math.min(100, Math.max(0, epssPct * 100))}" aria-label="EPSS ${(epssPct * 100).toFixed(2)}%"></progress>
            ${(epssPct * 100).toFixed(2)}%${hasPercentile ? ' · p' + Math.round(Number(a.epss_percentile) * 100) : ''}
          </span>`
        : '';
      return `<article class="card ${sevbar} ${dimClass}" data-id="${esc(a.advisory_id)}">
        <div class="card-top">
          <h3 class="title">${esc(a.summary)}</h3>
          <span class="badge sev ${safeSeverity}">${esc(a.severity)}</span>
        </div>
        <div class="badges">
          ${srcBadge}${nativeBadge}${kevBadge}${withdrawnBadge}
          ${ecoNames.length ? `<span class="badge eco">${esc(ecoNames.join(', '))}</span>` : ''}
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

    // Only rows that still need work. A partial verdict that already resolved to
    // a match is done — counting it made "Retry failed" re-bill finished rows.
    function failedIds() {
      return LAST.map(a => a.advisory_id).filter(id => {
        const v = AI[id];
        return v && (v.error || (v.has_errors && v.is_match !== true));
      });
    }

    // True when verdicts on screen were scored for a different selection than
    // the one now active — they describe another question's answer.
    function verdictsAreStale() {
      if (!AI_CATS || !Object.keys(AI).length) return false;
      const now = selectedCategories().slice().sort();
      return now.length !== AI_CATS.length
        || now.some((c, i) => c !== AI_CATS[i]);
    }

    function classLabelFor(key) {
      if (key.indexOf('cwe:') === 0) return 'CWE-' + key.slice(4);
      const cls = CLASSES.find(c => c.key === key);
      return cls ? shortClassLabel(cls.label) : key;
    }

    function renderStaleBanner() {
      const banner = $('#stale-banner');
      const stale = verdictsAreStale();
      banner.hidden = !stale;
      if (stale) {
        banner.textContent = 'AI verdicts below were scored for '
          + AI_CATS.map(classLabelFor).join(' + ')
          + ', not the current selection. Re-run “Refine with AI” before trusting or exporting them.';
      }
      return stale;
    }

    function updateActionButtons() {
      const has = LAST.length > 0;
      const stale = renderStaleBanner();
      $('#ai-btn').disabled = !has;
      // Filtering on verdicts that answer a different question would silently
      // hide the wrong advisories, so the filter is blocked until re-scored.
      $('#only_match').disabled = !has || stale;
      if (stale && $('#only_match').checked) $('#only_match').checked = false;
      $('#only_match_label').title = stale
        ? 'Verdicts are stale — re-run “Refine with AI” first'
        : 'Runs AI first if needed, then hides non-matches';
      // Stay focusable while disabled: tabIndex -1 removed the control from the
      // tab order entirely, so its aria-disabled was never announced.
      $('#export-btn').setAttribute('aria-disabled', String(!has));
      $('#export-btn').tabIndex = 0;
      if (!has) $('.export-menu').removeAttribute('open');
      // Say *why* a control is unavailable, not just what it would have done.
      [$('#ai-btn'), $('#retry-btn'), $('#export-btn'), $('#only_match')].forEach(el => {
        if (!el) return;
        if (has) el.removeAttribute('aria-describedby');
        else el.setAttribute('aria-describedby', 'needs-search-hint');
      });
      const nfail = failedIds().length;
      const rb = $('#retry-btn');
      rb.disabled = nfail === 0;
      rb.textContent = nfail ? `Retry failed (${nfail})` : 'Retry failed';
    }

    // The summary used to be written once per search and then contradict the
    // screen as soon as a filter hid anything.
    function renderSummary(shown) {
      const m = SEARCH_META;
      if (!m) return;
      const ps = Object.entries(m.perSource);
      const psText = ps.length
        ? ' · ' + ps.map(([k, v]) => `${k.toUpperCase()}:${v}`).join(' + ') : '';
      const head = shown === m.count
        ? `<b>${m.count}</b> advisories`
        : `<b>${shown}</b> of ${m.count} shown`;
      // "Hidden" and "never scored" look identical once the filter is on, which
      // reads as "the AI cleared these" when the AI never saw them.
      const unscored = $('#only_match').checked ? unscoredCount() : 0;
      const unscoredNote = unscored
        ? ` · <span class="summary-unscored" title="These were never scored, so they are hidden rather than cleared">${unscored} not scored</span>`
        : '';
      // A full page is very likely a truncated one; saying so prevents reading
      // "0 hits for CWE-639" as "this CWE has no advisories".
      const capped = m.count >= m.maxResults
        ? ` · <span class="summary-capped" title="Raise “Max results” to widen the query">capped at ${m.maxResults}</span>`
        : '';
      const shownCwes = m.cwes.slice(0, 6).join(', ');
      const more = m.cwes.length > 6 ? `<span title="${safeAttr(m.cwes.join(', '))}"> +${m.cwes.length - 6} more</span>` : '';
      $('#summary').innerHTML = head + unscoredNote + psText + capped
        + ` · CWEs: <code>${esc(shownCwes)}</code>${more}`
        + (m.cached ? ` · <span class="summary-cached">${m.cached} already AI-scored</span>` : '');
    }

    function render() {
      const items = currentItems();
      const el = $('#results');
      renderSummary(items.length);
      if (!items.length) {
        // Distinguish "the query found nothing" from "your filter hid it all".
        const filtered = LAST.length > 0;
        el.innerHTML = `<div class="empty">${filtered
          ? 'All ' + LAST.length + ' advisories are hidden by the “Confirmed only” filter.'
          : 'No advisories matched this query.'}</div>`;
        updateActionButtons();
        return;
      }
      el.innerHTML = items.map(renderCard).join('');
      updateActionButtons();
    }

    // `overrides` lets the Auto pipeline run with its own source set without
    // rewriting the checkboxes the user deliberately ticked.
    async function search(overrides) {
      const state = Object.assign(formState(), overrides || {});
      // Validate everything *before* touching the results pane: bailing out
      // afterwards used to leave a spinner up forever while Export and the AI
      // pass kept operating on the previous, now-invisible result set.
      if (!state.categories.length) { toast('Select a bug class or a CWE', 'err'); return false; }
      if (!state.sources.length) { toast('Select at least one data source', 'err'); return false; }
      const sources = state.sources;
      if (document.body.classList.contains('filters-open')) setFilterPanel(false, false);
      $('#search-btn').disabled = true;
      setResultsBusy(true);
      $('#results').innerHTML = `<div class="loading"><span class="spinner"></span>Searching advisories…</div>`;
      $('#summary').textContent = 'Searching…';
      // A failed query must never leave the previous result set available to
      // the Auto pipeline or export controls as if it were fresh data.
      LAST = [];
      AI = {};
      AI_CATS = null;
      updateActionButtons();
      const payload = Object.assign({}, state, {
        published: publishedWindow(state.published),
        refresh_osv: $('#refresh_osv').checked,
      });
      if (sources.includes('nvd')) {
        $('#results').innerHTML = `<div class="loading"><span class="spinner"></span>Fetching… (NVD is rate-limited — may take a moment per CWE)</div>`;
      } else if (sources.includes('osv')) {
        $('#results').innerHTML = `<div class="loading"><span class="spinner"></span>Fetching… (OSV may download a ~10MB list on first use)</div>`;
      }
      try {
        const data = await apiPost('/api/search', payload);
        LAST = data.results;
        AI = {};
        LAST.forEach(a => { if (a.ai) AI[a.advisory_id] = a.ai; });
        const cached = LAST.filter(a => a.ai).length;
        // The server only attaches cached verdicts when every requested
        // category has one, so they belong to exactly this selection.
        AI_CATS = cached ? state.categories.slice().sort() : null;
        SEARCH_META = {
          count: data.count,
          perSource: data.query.per_source || {},
          cwes: data.query.cwes || [],
          maxResults: state.max_results,
          cached: cached,
        };
        (data.warnings || []).forEach(w => toast('⚠️ ' + w, 'err'));
        $('#ai-btn').disabled = LAST.length === 0;
        $('#only_match').disabled = LAST.length === 0;
        $('#only_match').checked = false;
        recordHistory(state, data.count);
        render();
        return true;
      } catch (e) {
        SEARCH_META = null;
        $('#results').innerHTML = `<div class="empty">❌ ${esc(e.message)}</div>`;
        $('#summary').textContent = 'Error.';
        toast(e.message, 'err');
        return false;
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
      const sent = cats.length ? cats : ['bac'];
      // Each request costs categories × advisories model calls, and the server
      // rejects anything over AI_CALL_BUDGET. Size the batch to stay under it.
      const budget = Number(AI_CALL_BUDGET) || 500;
      const batchSize = Math.max(1, Math.min(100, Math.floor(budget / sent.length)));
      for (let offset = 0; offset < ids.length; offset += batchSize) {
        const batch = ids.slice(offset, offset + batchSize);
        const data = await apiPost('/api/ai/classify', {
          categories: sent,
          advisory_ids: batch,
        });
        Object.assign(AI, data.verdicts);
        AI_CATS = sent.slice().sort();
      }
      return ids.filter(id => AI[id] && (AI[id].error || AI[id].has_errors)).length;
    }

    // Estimated model calls for scoring `count` advisories with the current
    // selection — what the user is about to spend.
    function aiCallEstimate(count) {
      return count * Math.max(1, selectedCategories().length);
    }

    // Returns true when the pass completed; callers use it to avoid presenting
    // a failed run as a clean "0 matches" result.
    async function refineAI() {
      if (!LAST.length) return false;
      let ok = true;
      const ids = LAST.map(a => a.advisory_id);
      $('#ai-btn').disabled = true;
      $('#retry-btn').disabled = true;
      setResultsBusy(true);
      const orig = 'Refine with AI';
      $('#ai-btn').innerHTML = '<span class="spinner"></span>Refining…';
      try {
        await classifyIds(ids);
        render();
        // One extra round for leftovers; the backend already retried per item.
        let round = 0;
        while (failedIds().length && round < 1) {
          round++;
          const fails = failedIds();
          $('#ai-btn').innerHTML = `<span class="spinner"></span>Retrying ${fails.length}…`;
          toast(`Retrying ${fails.length} failed advisory(ies)… round ${round}`, 'ok');
          await classifyIds(fails);
          render();
        }
        const matches = LAST.filter(a => (AI[a.advisory_id]||{}).is_match).length;
        const errs = failedIds().length;
        recordHistoryMatches(matches);
        toast(`AI done: ${matches} matches` + (errs ? `, ${errs} still failing — use ↻ Retry failed` : ''),
              errs ? 'err' : 'ok');
      } catch (e) {
        ok = false;
        toast(e.message, 'err');
      } finally {
        // A literal label, not the captured innerHTML: a re-entrant call used to
        // capture the spinner markup and restore that instead.
        $('#ai-btn').innerHTML = orig;
        setResultsBusy(false);
        render();
      }
      return ok;
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
        const d = await apiPost('/api/ai/test', {});
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
        // Without these a CSV cannot be told apart from one scored against a
        // different bug class, or from one where some categories failed.
        ai_scored_categories: (v.scored_categories || []).join('|'),
        ai_matched_category: v.matched_category || '',
        ai_has_errors: v.has_errors === true ? 'yes' : (v.error ? 'yes' : ''),
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
      if (!cats.length) { toast('Select a bug class or a CWE', 'err'); return; }
      const eco = $('#ecosystem').value;
      const osvOk = OSV_SUPPORTED.includes(eco);
      // GHSA covers CWE-tagged advisories; OSV-native adds the no-CWE records the
      // AI can still catch. For "any" ecosystem OSV can't be used, so GHSA only.
      // Applied to this run only — silently rewriting the user's source choice
      // meant the next plain search also used the overridden set.
      const autoSources = osvOk ? ['ghsa', 'osv-native'] : ['ghsa'];
      const chosen = $$('input[name=source]:checked').map(c => c.value);
      const overridden = chosen.slice().sort().join() !== autoSources.slice().sort().join();

      const btn = $('#auto-btn');
      btn.disabled = true;
      const orig = btn.innerHTML;
      try {
        btn.innerHTML = '<span class="spinner"></span>1/3 Searching…';
        if (overridden) {
          toast('Auto scan uses ' + autoSources.map(s => s.toUpperCase()).join(' + ')
                + ' for this run; your source selection is unchanged', 'ok');
        }
        const ok = await search({sources: autoSources});
        // A failed search must not be reported as "nothing matched".
        if (!ok) return;
        if (!LAST.length) { toast('No advisories match these filters', 'err'); return; }
        if (AI_CONFIGURED) {
          btn.innerHTML = '<span class="spinner"></span>2/3 AI classifying…';
          const scored = await refineAI();  // includes auto-retry of failures
          if (!scored) {
            // Reporting a failed pass as "0 confirmed matches" reads as
            // "nothing is vulnerable", which is the opposite of the truth.
            toast('AI pass failed — showing raw results, nothing was scored', 'err');
            return;
          }
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
    // "Confirmed only" reads as a local filter but has to score the queue first,
    // which costs real money. Never spend it without asking, and never leave the
    // box checked (hiding everything) when the pass fails.
    $('#only_match').addEventListener('change', async (e) => {
      if (e.target.checked && LAST.length && unscoredCount() > 0) {
        const pending = unscoredCount();
        const calls = aiCallEstimate(pending);
        const classes = Math.max(1, selectedCategories().length);
        const proceed = window.confirm(
          'Filtering to confirmed matches needs an AI pass first.\n\n'
          + `${pending} advisory(ies) × ${classes} class(es) = about ${calls} AI call(s).\n\n`
          + 'Run it now?');
        if (!proceed) { e.target.checked = false; return; }
        if (!await refineAI()) {
          // The queue would otherwise look empty with no hint that unticking
          // this box brings the raw results back.
          e.target.checked = false;
          toast('AI pass failed — showing the raw results again', 'err');
        }
      }
      render();
    });
    $('#retry-btn').addEventListener('click', retryFailed);
    // Per-card retry: the toolbar button can be scrolled far out of view by the
    // time the user reads the error on a card.
    $('#results').addEventListener('click', async (e) => {
      const button = e.target.closest('.verdict-retry');
      if (!button) return;
      const id = button.dataset.retry;
      button.disabled = true;
      button.textContent = 'Retrying…';
      try {
        await classifyIds([id]);
      } catch (err) {
        toast(err.message, 'err');
      }
      render();
    });
    $('#ai-test-pill').addEventListener('click', testAI);
    $('#filters-toggle').addEventListener('click', () => setFilterPanel(true));
    $('#filters-close').addEventListener('click', () => setFilterPanel(false));
    $('#filter-scrim').addEventListener('click', () => setFilterPanel(false));
    $('#ecosystem').addEventListener('change', refreshPackages);
    $('#sort').addEventListener('change', () => { if (LAST.length) render(); });
    $('#direction').addEventListener('change', () => { if (LAST.length) render(); });

    // --- CWE finder ---
    $('#cwe-search').addEventListener('input', () => { comboActive = -1; renderCombo(); });
    $('#cwe-search').addEventListener('keydown', e => {
      if (e.key === 'ArrowDown') { e.preventDefault(); moveComboActive(1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); moveComboActive(-1); }
      // Tab means "done with this widget" — dismiss the popup, keep the move.
      else if (e.key === 'Tab') { closeCombo(); }
      else if (e.key === 'Enter') {
        if ($('#cwe-options').hidden) return;   // let the search shortcut through
        e.preventDefault();
        // Without this, ⌘/Ctrl+Enter here would add the CWE *and* bubble to the
        // global shortcut, launching a whole search on a single keystroke.
        e.stopPropagation();
        pickEntry(comboMatches[comboActive >= 0 ? comboActive : 0]);
      } else if (e.key === 'Escape' && !$('#cwe-options').hidden) {
        e.stopPropagation();          // keep Escape from closing the whole panel
        closeCombo();
      }
    });
    $('#cwe-search').addEventListener('focus', renderCombo);
    $('#cwe-clear').addEventListener('click', () => {
      $('#cwe-search').value = '';
      closeCombo();
      $('#cwe-clear').hidden = true;
      $('#cwe-search').focus();
    });
    $('#cwe-options').addEventListener('mousedown', e => {
      // mousedown, not click: the input's blur handler would close the list first.
      const option = e.target.closest('.combo-option');
      if (!option) return;
      e.preventDefault();
      pickEntry(comboMatches.find(entry => entry.key === option.dataset.key));
    });
    $('#selected-chips').addEventListener('click', e => {
      const button = e.target.closest('.chip-x');
      if (!button) return;
      const cwe = button.dataset.dropCwe;
      const cls = button.dataset.dropClass;
      if (cwe) {
        PICKED.delete(cwe);
        announceSelection('CWE-' + cwe + ' removed');
      } else if (cls) {
        const box = $$('input[name=category]').find(c => c.value === cls);
        if (box) box.checked = false;
        announceSelection('class removed');
      }
      renderSelection();
    });
    $$('input[name=category]').forEach(box => box.addEventListener('change', () => {
      renderSelection();
      filterClasses();   // a newly ticked class must not vanish behind the filter
    }));
    $('#class-search').addEventListener('input', filterClasses);
    $('#class-search').addEventListener('keydown', e => {
      if (e.key === 'Escape' && $('#class-search').value) {
        e.stopPropagation();
        $('#class-search').value = '';
        filterClasses();
      }
    });

    // --- Recent searches ---
    $('#history-list').addEventListener('click', e => {
      const run = e.target.closest('.history-run');
      const drop = e.target.closest('.history-drop');
      const list = loadHistory();
      if (drop) {
        saveHistory(list.filter(entry => entry.sig !== drop.dataset.sig));
        renderHistory();
        return;
      }
      if (!run) return;
      const entry = list.find(item => item.sig === run.dataset.sig);
      if (!entry) { renderHistory(); return; }   // another tab removed it
      applyState(entry.query);
      search();
    });
    $('#history-clear').addEventListener('click', () => {
      saveHistory([]);
      renderHistory();
      toast('Recent searches cleared', 'ok');
    });
    $('#include_extended').addEventListener('change', updateNvdHint);
    $$('input[name=source]').forEach(box => box.addEventListener('change', updateNvdHint));
    document.addEventListener('mousedown', e => {
      const finder = $('.cwe-finder');
      if (finder && !finder.contains(e.target)) closeCombo();
    });
    // Tab used to leave the popup open and floating over the form.
    $('.cwe-finder').addEventListener('focusout', e => {
      const finder = $('.cwe-finder');
      if (!e.relatedTarget || !finder.contains(e.relatedTarget)) closeCombo();
    });
    $$('.export-pop button').forEach(b => b.addEventListener('click', () => doExport(b.dataset.fmt)));
    // Close the export menu when clicking outside it.
    document.addEventListener('click', e => {
      const m = $('.export-menu');
      if (m && m.open && !m.contains(e.target)) m.removeAttribute('open');
    });
    $('#export-btn').addEventListener('click', e => {
      if (e.currentTarget.getAttribute('aria-disabled') === 'true') e.preventDefault();
    });
    document.addEventListener('keydown', trapPanelTab, true);
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && document.body.classList.contains('filters-open')) {
        setFilterPanel(false);
      } else if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        // The ⌘↵ hint is printed on "Search raw advisories", so it must run the
        // free search — not the paid full pipeline.
        search();
      }
    });
    window.addEventListener('resize', () => {
      if (window.innerWidth > 900 && document.body.classList.contains('filters-open')) {
        setFilterPanel(false, false);
      }
    });

    // Initial population. The catalog load is fire-and-forget: classes are
    // searchable immediately and CWE rows appear as soon as it lands.
    refreshPackages();
    renderSelection();
    filterClasses();
    renderHistory();
    updateActionButtons();
    loadCweCatalog().then(renderSelection);
    if (AUTH_REQUIRED) {
      $('#auth-save').addEventListener('click', saveAuthToken);
      $('#auth-token').addEventListener('keydown', e => {
        if (e.key === 'Enter') { e.preventDefault(); saveAuthToken(); }
      });
      if (!sessionStorage.getItem('vulnsight_token')) showAuthGate();
    }
