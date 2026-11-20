// Model-free PR diff scanner. Never execute PR code or print scanner payloads.
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const SHA = /^[a-f0-9]{40}$/;
const LIMIT = 25 * 1024 * 1024;
function refuse(code) { throw new Error(code); }
function childEnv() {
  const env = {};
  for (const key of ['PATH', 'Path', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP']) {
    if (process.env[key]) env[key] = process.env[key];
  }
  return { ...env, GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: process.platform === 'win32' ? 'NUL' : '/dev/null',
    GIT_TERMINAL_PROMPT: '0', NO_COLOR: '1' };
}
function run(exe, args, options = {}) {
  const r = spawnSync(exe, args, { encoding: 'utf8', env: childEnv(),
    timeout: 60000, maxBuffer: LIMIT, windowsHide: true, ...options });
  if (r.error || r.signal || r.status === null) refuse('CHILD_DID_NOT_COMPLETE');
  return r;
}

export function assessReport(report, commits, status, stderr) {
  if (status !== 0 || /\b(?:ERR|FTL|FATAL)\b|level[=:]"?error/i.test(stderr)) refuse('SCANNER_FAILED');
  if (!Array.isArray(report)) refuse('INVALID_REPORT');
  const expected = new Set(commits.flatMap(sha => [`sn-begin-${sha}`, `sn-end-${sha}`]));
  const seen = new Set();
  for (const finding of report) {
    if (!finding || typeof finding.RuleID !== 'string') refuse('INVALID_FINDING');
    if (!expected.has(finding.RuleID)) refuse('SECRET_OR_UNEXPECTED_FINDING');
    seen.add(finding.RuleID);
  }
  if (seen.size !== expected.size || !expected.size) refuse('INCOMPLETE_SCANNER_COVERAGE');
  return { commits: commits.length, observedBoundaryRules: seen.size, findings: 0 };
}

export function scanPr({ repo, base, head, gitleaks = 'gitleaks', scratchRoot = tmpdir() }) {
  if (!SHA.test(base ?? '') || !SHA.test(head ?? '')) refuse('INVALID_REVISION');
  repo = realpathSync(repo);
  const scratch = mkdtempSync(join(scratchRoot, 'gk-pr-scan-'));
  const git = (...args) => {
    const r = run('git', ['-c', 'core.hooksPath=' + join(scratch, 'no-hooks'),
      '-c', 'core.fsmonitor=false', '-c', 'core.longpaths=true', '-c', 'core.attributesFile=' + (process.platform === 'win32' ? 'NUL' : '/dev/null'),
      '-C', repo, ...args], { cwd: scratch });
    if (r.status !== 0) refuse('GIT_INPUT_FAILED');
    return r.stdout;
  };
  git('cat-file', '-e', base + '^{commit}');
  git('cat-file', '-e', head + '^{commit}');
  const commits = git('rev-list', '--reverse', base + '..' + head, '--').trim().split(/\r?\n/).filter(Boolean);
  if (!commits.length || commits.length > 100 || new Set(commits).size !== commits.length || commits.some(s => !SHA.test(s))) refuse('EMPTY_OR_OVERSIZED_RANGE');
  if (git('rev-list', '--min-parents=3', base + '..' + head, '--').trim()) refuse('OCTOPUS_REVIEW_REQUIRED');
  for (const name of ['README.md', 'CONTRIBUTING.md', 'LICENSE']) {
    if (!(Number(git('cat-file', '-s', head + ':' + name).trim()) > 0)) refuse('REQUIRED_DOCUMENT_MISSING');
  }
  git('diff', '--check', base, head, '--');
  const pieces = [];
  const rules = ['[extend]', 'useDefault = true', ''];
  let inputBytes = 0;
  for (const sha of commits) {
    const raw = git('diff-tree', '--root', '--no-commit-id', '-r', '--raw',
      '--no-renames', '-z', '-m', sha, '--');
    const fields = raw.split('\0');
    if (fields.some(s => /^:(?:160000 [0-7]{6}|[0-7]{6} 160000) /.test(s))) refuse('GITLINK_REVIEW_REQUIRED');
    if (fields.some(s => /(?:^|\/)\.gitattributes$/i.test(s))) refuse('ATTRIBUTES_REVIEW_REQUIRED');
    const stats = git('--no-pager', 'show', '--format=', '--numstat', '-z',
      '--no-renames', '--no-ext-diff', '--no-textconv', '--root', '--diff-merges=separate', sha, '--');
    if (stats.split('\0').some(s => /^-\t-\t/.test(s))) refuse('BINARY_REVIEW_REQUIRED');
    const diff = git('--no-pager', 'show', '--format=fuller', '--no-ext-diff', '--no-textconv',
      '--root', '--diff-merges=separate', '--unified=0', sha, '--');
    const piece = `SNBEGIN${sha}END\n${diff}\nSNEND${sha}END\n`;
    inputBytes += Buffer.byteLength(piece);
    if (inputBytes > LIMIT) refuse('INPUT_LIMIT_EXCEEDED');
    pieces.push(piece);
    for (const [kind, prefix] of [['begin', 'SNBEGIN'], ['end', 'SNEND']]) {
      rules.push('[[rules]]', `id = "sn-${kind}-${sha}"`,
        `description = "Synthetic scanner boundary"`, `regex = '''${prefix}${sha}END'''`, '');
    }
  }
  const config = join(scratch, 'trusted.toml');
  const ignore = join(scratch, 'empty-ignore');
  const reportPath = join(scratch, 'redacted-report.json');
  writeFileSync(config, rules.join('\n'));
  writeFileSync(ignore, '');
  const r = run(gitleaks, ['stdin', '--no-banner', '--no-color', '--redact=100',
    '--ignore-gitleaks-allow', '--config', config, '--gitleaks-ignore-path', ignore,
    '--report-format', 'json', '--report-path', reportPath, '--exit-code=0'],
    { cwd: scratch, input: pieces.join('') });
  let report;
  try { report = JSON.parse(readFileSync(reportPath, 'utf8')); }
  catch { refuse('MISSING_OR_INVALID_REPORT'); }
  const result = assessReport(report, commits, r.status, r.stderr);
  return { ...result, inputBytes, scratch };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const [repo, base, head, gitleaks] = process.argv.slice(2);
    const result = scanPr({ repo, base, head, gitleaks });
    console.log(JSON.stringify({ status: 'PASS', commits: result.commits,
      observedBoundaryRules: result.observedBoundaryRules, inputBytes: result.inputBytes }));
  } catch (error) {
    const code = /^[A-Z_]+$/.test(error.message) ? error.message : 'SCAN_REFUSED';
    console.error('::error::' + code);
    process.exitCode = 1;
  }
}
