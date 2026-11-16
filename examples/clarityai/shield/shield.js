// ClarityAI PII shield: show a document three ways.
//
//   you     the text as written, with personal data highlighted
//   ai      what a model is allowed to see: each item replaced by its stable token
//   share   what is safe to paste elsewhere: each item blocked out
//
// `entities` are the detections the NER job reported: {kind, start, end, token}. Offsets
// count characters the way Python does (one per code point), so the text is indexed by
// code point, not by UTF-16 unit.

/** Split `text` into plain and personal-data segments. Overlaps and bad spans are skipped. */
export function segments(text, entities) {
  const chars = Array.from(text);
  const spans = (entities || [])
    .filter((e) => Number.isInteger(e.start) && Number.isInteger(e.end) && e.start >= 0 && e.start < e.end && e.end <= chars.length)
    .sort((a, b) => a.start - b.start || b.end - a.end);
  const out = [];
  let at = 0;
  for (const e of spans) {
    if (e.start < at) continue;
    if (e.start > at) out.push({ text: chars.slice(at, e.start).join('') });
    out.push({ text: chars.slice(e.start, e.end).join(''), kind: e.kind, token: e.token || e.kind });
    at = e.end;
  }
  if (at < chars.length) out.push({ text: chars.slice(at).join('') });
  return out;
}

/** The text for a mode: 'you' (as written), 'ai' (tokens) or 'share' (blocked out). */
export function render(text, entities, mode) {
  return segments(text, entities)
    .map((s) => {
      if (!s.kind || mode === 'you') return s.text;
      if (mode === 'ai') return s.token;
      return '█'.repeat(Math.min(Array.from(s.text).length, 12));
    })
    .join('');
}

/** How many items of each kind were found. */
export function summary(entities) {
  const counts = {};
  for (const e of entities || []) counts[e.kind] = (counts[e.kind] || 0) + 1;
  return counts;
}

/** True when `text` still contains any original value: the check before anything is sent on. */
export function leaks(text, originals) {
  return originals.some((o) => o && text.includes(o));
}

// ---- the page (only runs in a browser)

if (typeof document !== 'undefined') {
  const $ = (id) => document.getElementById(id);
  const SAMPLE = {
    text: 'Please call Dr. Jane Smith on +44 20 7946 0958 or write to jane@example.com about the contract.',
    entities: [
      { kind: 'PERSON', start: 12, end: 26, token: 'PERSON_3f9a1c07d2b4e688' },
      { kind: 'PHONE', start: 30, end: 46, token: 'PHONE_91be0a44c6d1f2a3' },
      { kind: 'EMAIL', start: 59, end: 75, token: 'EMAIL_0c4d77a9b1e35f20' },
    ],
  };
  let state = { text: '', entities: [] };

  const show = () => {
    const view = $('you');
    view.replaceChildren();
    for (const s of segments(state.text, state.entities)) {
      if (s.kind) {
        const m = document.createElement('mark');
        m.className = 'pii';
        m.title = s.kind;
        m.textContent = s.text;
        view.append(m);
      } else {
        view.append(document.createTextNode(s.text));
      }
    }
    $('ai').textContent = render(state.text, state.entities, 'ai');
    $('share').textContent = render(state.text, state.entities, 'share');
    const counts = summary(state.entities);
    const total = state.entities.length;
    $('count').textContent = total
      ? `${total} personal item${total === 1 ? '' : 's'} found (${Object.entries(counts).map(([k, n]) => `${n} ${k.toLowerCase()}`).join(', ')}). A model sees tokens only.`
      : 'No personal data found.';
  };

  const load = async () => {
    const base = $('base').value.replace(/\/$/, '');
    const id = $('doc').value.trim();
    const headers = { authorization: `Bearer ${$('token').value.trim()}` };
    try {
      const doc = await (await fetch(`${base}/v1/documents/${encodeURIComponent(id)}`, { headers })).json();
      const found = await (await fetch(`${base}/v1/detections?filter[document_id]=${encodeURIComponent(id)}&page[size]=100`, { headers })).json();
      state = {
        text: doc.body || '',
        entities: (found.data || []).map((d) => ({ kind: d.kind, start: d.start, end: d.stop, token: d.token })),
      };
      show();
    } catch (e) {
      $('count').textContent = `Could not load the document: ${e.message}`;
    }
  };

  $('demo').addEventListener('click', () => {
    state = SAMPLE;
    show();
  });
  $('load').addEventListener('click', load);
  show();
}
