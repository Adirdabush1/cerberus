// `cerberus rules validate` unit tests. Run: npx tsx scripts/validate.test.ts
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execSync } from 'node:child_process';

let pass = 0, fail = 0;
function check(name: string, cond: boolean, detail = '') {
  if (cond) { pass++; console.log(`  ✅ ${name}`); }
  else       { fail++; console.log(`  ❌ ${name} — ${detail}`); }
}

const tmp = mkdtempSync(join(tmpdir(), 'cerberus-validate-'));

function writeYaml(name: string, content: string): string {
  const p = join(tmp, name);
  writeFileSync(p, content);
  return p;
}

function run(file: string): { code: number; out: string } {
  try {
    // `npx tsx` resolves the local tsx on every platform (the bare node_modules/.bin/tsx
    // shim is not directly executable under cmd.exe on Windows).
    const out = execSync(`npx tsx src/cli/index.ts rules validate --file "${file}"`, {
      encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
    });
    return { code: 0, out };
  } catch (e: unknown) {
    const err = e as { status?: number; stdout?: string; stderr?: string };
    return { code: err.status ?? 1, out: (err.stdout ?? '') + (err.stderr ?? '') };
  }
}

// ─── valid fixture ───────────────────────────────────────────────────────────
const validFile = writeYaml('valid.yaml', `
default: HITL
rules:
  - id: block-rm-rf
    description: "Blocks rm -rf"
    action: BLOCK
    when:
      matches: ["\\\\brm\\\\s+-rf\\\\b", { var: command }]
  - id: allow-readonly
    description: "Allow read-only ops"
    action: ALLOW
    when:
      "==": [{ var: category }, "READ"]
`);

const r1 = run(validFile);
check('valid file exits 0', r1.code === 0, `got exit code ${r1.code}`);
check('valid file prints ✓', r1.out.includes('✓'), r1.out);
check('valid file prints "All rule files valid"', r1.out.includes('All rule files valid'), r1.out);

// ─── broken fixture: missing default, duplicate id, bad action ───────────────
const brokenFile = writeYaml('broken.yaml', `
rules:
  - id: rule-a
    description: "First rule"
    action: YOLO
    when:
      matches: ["foo", { var: command }]
  - id: rule-a
    description: "Duplicate id"
    action: ALLOW
    when:
      matches: ["bar", { var: command }]
`);

const r2 = run(brokenFile);
check('broken file exits 1', r2.code === 1, `got exit code ${r2.code}`);
check('broken file prints ✗', r2.out.includes('✗'), r2.out);
check('broken file reports missing default', r2.out.includes('default'), r2.out);
check('broken file reports invalid action YOLO', r2.out.includes('YOLO'), r2.out);
check('broken file reports duplicate id', r2.out.toLowerCase().includes('duplicate'), r2.out);

// ─── bad YAML syntax ─────────────────────────────────────────────────────────
const badYaml = writeYaml('syntax.yaml', `
default: HITL
rules:
  - id: [unclosed
`);

const r3 = run(badYaml);
check('YAML syntax error exits 1', r3.code === 1, `got exit code ${r3.code}`);
check('YAML syntax error prints parse error', r3.out.toLowerCase().includes('yaml'), r3.out);

// ─── bad regex ───────────────────────────────────────────────────────────────
const badRegex = writeYaml('badregex.yaml', `
default: HITL
rules:
  - id: bad-regex
    description: "Has an invalid regex"
    action: BLOCK
    when:
      matches: ["([unclosed", { var: command }]
`);

const r4 = run(badRegex);
check('bad regex exits 1', r4.code === 1, `got exit code ${r4.code}`);
check('bad regex reports invalid regex', r4.out.includes('invalid regex'), r4.out);

// ─── bundled rules pass ───────────────────────────────────────────────────────
// (only run if file exists — skipped in CI that doesn't have full project)
try {
  const bundledOut = execSync('npx tsx src/cli/index.ts rules validate', {
    encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
  });
  check('bundled rules/default_policy.yaml is valid', bundledOut.includes('All rule files valid'), bundledOut);
} catch {
  check('bundled rules validation', false, 'command failed');
}

// ─── cleanup ─────────────────────────────────────────────────────────────────
rmSync(tmp, { recursive: true });

console.log(`\n${pass} passed, ${fail} failed.`);
if (fail > 0) process.exit(1);
