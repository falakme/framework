import assert from 'node:assert/strict';
import { test } from 'node:test';

import { leaks, render, segments, summary } from './shield.js';

const text = 'Mail Jane <jane@example.com> now. Ünal too.';
const entities = [
  { kind: 'EMAIL', start: 11, end: 27, token: 'EMAIL_aa' },
  { kind: 'PERSON', start: 34, end: 38, token: 'PERSON_bb' },
];

test('each view shows what it should', () => {
  assert.equal(render(text, entities, 'you'), text);
  assert.equal(render(text, entities, 'ai'), 'Mail Jane <EMAIL_aa> now. PERSON_bb too.');
  assert.equal(render(text, entities, 'share'), 'Mail Jane <████████████> now. ████ too.');
});

test('the ai view carries no original', () => {
  const ai = render(text, entities, 'ai');
  assert.equal(leaks(ai, ['jane@example.com', 'Ünal']), false);
  assert.equal(leaks(text, ['jane@example.com']), true);
});

test('bad and overlapping spans are skipped; offsets count code points', () => {
  const odd = [
    { kind: 'X', start: 5, end: 3, token: 't' },
    { kind: 'X', start: 0, end: 999, token: 't' },
    { kind: 'EMAIL', start: 11, end: 27, token: 'EMAIL_aa' },
    { kind: 'OVERLAP', start: 20, end: 30, token: 'o' },
  ];
  assert.equal(segments(text, odd).filter((s) => s.kind).length, 1);
  assert.equal(render('😀 Ann', [{ kind: 'PERSON', start: 2, end: 5, token: 'P' }], 'ai'), '😀 P');
});

test('the summary counts by kind', () => {
  assert.deepEqual(summary(entities), { EMAIL: 1, PERSON: 1 });
});
