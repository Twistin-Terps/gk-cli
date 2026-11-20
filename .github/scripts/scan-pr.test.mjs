// Synthetic repos only. No real credentials, remotes, user projects or cleanup.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { scanPr, assessReport } from './scan-pr.mjs';

const root = mkdtempSync(join(process.env.GK_FIXTURE_ROOT ?? tmpdir(), 'gk-synthetic-'));
const binary = process.env.GK_GITLEAKS;
if (!binary) throw new Error('GK_GITLEAKS must name the existing approved binary');
function fixture() {
  const repo = mkdtempSync(join(root, 'repo-'));
  const childEnv = {};
  for (const key of ['PATH', 'Path', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP']) {
    if (process.env[key]) childEnv[key] = process.env[key];
  }
  Object.assign(childEnv, { GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    GIT_TERMINAL_PROMPT: '0' });
  const git = (...args) => {
    const r = spawnSync('git', ['-c', 'core.hooksPath=' + join(root, 'no-hooks'),
      '-c', 'core.fsmonitor=false', '-c', 'core.longpaths=true', '-c', 'user.name=Synthetic Fixture',
      '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
      '-c', 'core.autocrlf=false', '-C', repo, ...args],
      { encoding: 'utf8', env: childEnv, windowsHide: true, timeout: 10000, maxBuffer: 1024 * 1024 });
    assert.equal(r.status, 0, 'fixture git command failed');
    return r.stdout.trim();
  };
  git('init', '-b', 'main');
  for (const name of ['README.md', 'CONTRIBUTING.md', 'LICENSE']) writeFileSync(join(repo, name), 'Synthetic document\n');
  git('add', '--', 'README.md', 'CONTRIBUTING.md', 'LICENSE'); git('commit', '-qm', 'base');
  const base = git('rev-parse', 'HEAD');
  const commit = (name, text) => { writeFileSync(join(repo, name), text); git('add', '--', name); git('commit', '-qm', 'fixture'); return git('rev-parse', 'HEAD'); };
  return { repo, git, base, commit, scan: head => scanPr({ repo, base, head, gitleaks: binary, scratchRoot: root }) };
}
const fake = () => 'ghp_' + randomBytes(24).toString('base64url').replaceAll('-', 'A').replaceAll('_', 'Z').padEnd(36, '7').slice(0, 36);

test('real scanner proves both boundaries of each clean commit, including empty commits', () => {
  const f = fixture(); f.commit('clean.txt', 'No credentials here.\n');
  f.git('commit', '--allow-empty', '-qm', 'empty');
  const r = f.scan(f.git('rev-parse', 'HEAD'));
  assert.equal(r.commits, 2); assert.equal(r.observedBoundaryRules, 4);
});
test('real scanner rejects a synthetic credential removed before PR head', () => {
  const f = fixture(); f.commit('synthetic.txt', fake() + '\n');
  const head = f.commit('synthetic.txt', 'Removed synthetic fixture.\n');
  assert.throws(() => f.scan(head), /SECRET_OR_UNEXPECTED_FINDING/);
});
test('PR-controlled allowlist and inline allow comment cannot suppress finding', () => {
  const f = fixture(); f.commit('.gitleaks.toml', '[allowlist]\nregexes = [".*"]\n');
  f.commit('.gitleaksignore', '*\n');
  const head = f.commit('synthetic.txt', fake() + ' // gitleaks:allow\n');
  assert.throws(() => f.scan(head), /SECRET_OR_UNEXPECTED_FINDING/);
});
test('merge-introduced synthetic credential is scanned', () => {
  const f = fixture(); f.git('checkout', '-b', 'side'); f.commit('side.txt', 'Side.\n');
  f.git('checkout', 'main'); f.commit('main.txt', 'Main.\n');
  f.git('merge', '--no-commit', '--no-ff', 'side');
  writeFileSync(join(f.repo, 'synthetic.txt'), fake() + '\n'); f.git('add', '--', 'synthetic.txt'); f.git('commit', '-qm', 'merge with synthetic fixture');
  assert.throws(() => f.scan(f.git('rev-parse', 'HEAD')), /SECRET_OR_UNEXPECTED_FINDING/);
});
test('empty PR range is refused before scanner', () => { const f = fixture(); assert.throws(() => f.scan(f.base), /EMPTY_OR_OVERSIZED_RANGE/); });
test('binary content is refused instead of counting omitted bytes as covered', () => {
  const f = fixture(); const head = f.commit('binary.dat', Buffer.concat([Buffer.from([0]), Buffer.from(fake())]));
  assert.throws(() => f.scan(head), /BINARY_REVIEW_REQUIRED/);
});
test('attribute changes require separate review', () => {
  const f = fixture(); const head = f.commit('.gitattributes', '*.txt -diff\n');
  assert.throws(() => f.scan(head), /ATTRIBUTES_REVIEW_REQUIRED/);
});
test('new gitlink content requires separate review', () => {
  const f = fixture(); f.git('update-index', '--add', '--cacheinfo', '160000,' + f.base + ',external');
  f.git('commit', '-qm', 'synthetic gitlink');
  assert.throws(() => f.scan(f.git('rev-parse', 'HEAD')), /GITLINK_REVIEW_REQUIRED/);
});
test('missing revision is refused', () => { const f = fixture(); assert.throws(() => f.scan('f'.repeat(40)), /GIT_INPUT_FAILED/); });
test('scanner executable failure cannot pass', () => {
  const f = fixture(); const head = f.commit('clean.txt', 'Clean.\n');
  assert.throws(() => scanPr({ repo: f.repo, base: f.base, head,
    gitleaks: join(root, 'not-a-binary'), scratchRoot: root }), /CHILD_DID_NOT_COMPLETE/);
});
test('missing one boundary refuses a zero-exit empty scan', () => {
  const sha = 'a'.repeat(40);
  assert.throws(() => assessReport([{ RuleID: 'sn-begin-' + sha }], [sha], 0, ''), /INCOMPLETE_SCANNER_COVERAGE/);
});
test('logged scanner error refuses a nominal zero exit', () => {
  assert.throws(() => assessReport([], ['a'.repeat(40)], 0, 'ERR failed to scan'), /SCANNER_FAILED/);
});
test('nonzero scanner exit refuses complete boundaries', () => {
  const sha = 'a'.repeat(40);
  assert.throws(() => assessReport([{ RuleID: 'sn-begin-' + sha }, { RuleID: 'sn-end-' + sha }], [sha], 2, ''), /SCANNER_FAILED/);
});
