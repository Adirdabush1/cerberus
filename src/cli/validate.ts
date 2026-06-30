/**
 * `cerberus rules validate` — lint YAML rule files before the engine loads them.
 *
 * Checks:
 *   - File parses as valid YAML
 *   - Top-level shape: { default, rules[] } (both required)
 *   - `default` is one of ALLOW | HITL | BLOCK
 *   - Every rule has id (unique), description, action (valid), when (present)
 *   - All regex patterns inside `matches` ops compile without error
 *
 * Exit codes: 0 = valid, 1 = validation errors found, 2 = usage / file error
 */
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import yaml from 'js-yaml';

const VALID_ACTIONS = new Set(['ALLOW', 'HITL', 'BLOCK']);

interface Problem {
  line?: number;
  message: string;
}

function collectRegexPatterns(node: unknown, patterns: string[]): void {
  if (node === null || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (const item of node) collectRegexPatterns(item, patterns);
    return;
  }
  const obj = node as Record<string, unknown>;
  if ('matches' in obj) {
    const args = obj['matches'];
    if (Array.isArray(args) && typeof args[0] === 'string') {
      patterns.push(args[0]);
    }
  }
  for (const val of Object.values(obj)) collectRegexPatterns(val, patterns);
}

function validateFile(filePath: string): Problem[] {
  const problems: Problem[] = [];

  let raw: string;
  try {
    raw = readFileSync(filePath, 'utf8');
  } catch (err) {
    return [{ message: `Cannot read file: ${err instanceof Error ? err.message : String(err)}` }];
  }

  let parsed: unknown;
  try {
    parsed = yaml.load(raw);
  } catch (err) {
    if (err instanceof yaml.YAMLException) {
      // mark.line is 0-indexed; report 1-indexed. (mark is absent for some errors.)
      return [{ line: err.mark ? err.mark.line + 1 : undefined, message: `YAML parse error: ${err.reason}` }];
    }
    return [{ message: `YAML parse error: ${String(err)}` }];
  }

  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return [{ message: 'Top-level value must be a YAML mapping (object).' }];
  }

  const doc = parsed as Record<string, unknown>;

  // Validate `default`
  if (!('default' in doc)) {
    problems.push({ message: 'Missing required key "default" (e.g. default: HITL).' });
  } else if (!VALID_ACTIONS.has(String(doc['default']))) {
    problems.push({ message: `"default" must be one of ALLOW | HITL | BLOCK, got: ${doc['default']}` });
  }

  // Validate `rules`
  if (!('rules' in doc)) {
    problems.push({ message: 'Missing required key "rules" (must be a list).' });
    return problems;
  }
  const rules = doc['rules'];
  if (!Array.isArray(rules)) {
    problems.push({ message: '"rules" must be a YAML sequence (list).' });
    return problems;
  }

  const seenIds = new Set<string>();

  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i] as Record<string, unknown>;
    const prefix = `rules[${i}]`;

    if (typeof rule !== 'object' || rule === null || Array.isArray(rule)) {
      problems.push({ message: `${prefix}: each rule must be a mapping.` });
      continue;
    }

    const id = rule['id'];
    if (!id || typeof id !== 'string') {
      problems.push({ message: `${prefix}: missing or non-string "id".` });
    } else if (seenIds.has(id)) {
      problems.push({ message: `${prefix}: duplicate rule id "${id}".` });
    } else {
      seenIds.add(id);
    }

    if (!rule['description'] || typeof rule['description'] !== 'string') {
      problems.push({ message: `${prefix} (${id ?? '?'}): missing or non-string "description".` });
    }

    if (!('action' in rule)) {
      problems.push({ message: `${prefix} (${id ?? '?'}): missing "action".` });
    } else if (!VALID_ACTIONS.has(String(rule['action']))) {
      problems.push({ message: `${prefix} (${id ?? '?'}): "action" must be ALLOW | HITL | BLOCK, got: ${rule['action']}` });
    }

    if (!('when' in rule)) {
      problems.push({ message: `${prefix} (${id ?? '?'}): missing "when" expression.` });
    } else {
      // Validate regex patterns inside `matches` ops
      const patterns: string[] = [];
      collectRegexPatterns(rule['when'], patterns);
      for (const pattern of patterns) {
        try {
          new RegExp(pattern);
        } catch {
          problems.push({ message: `${prefix} (${id ?? '?'}): invalid regex in "matches": /${pattern}/` });
        }
      }
    }
  }

  return problems;
}

export function runValidate(args: string[]): void {
  const files: string[] = [];
  let i = 0;

  while (i < args.length) {
    const arg = args[i];
    if (arg === undefined) break; // unreachable (loop guard), but narrows arg to string

    if (arg === '--file' || arg === '-f') {
      i++;
      const value = args[i];
      if (!value) {
        process.stderr.write('cerberus rules validate: --file requires a path argument\n');
        process.exit(2);
      }
      files.push(value);
    } else if (!arg.startsWith('-')) {
      files.push(arg);
    } else {
      process.stderr.write(`cerberus rules validate: unknown option ${arg}\n`);
      process.exit(2);
    }
    i++;
  }

  if (files.length === 0) {
    // Default: validate the bundled rule file. Resolve the package root the same way the CLI
    // entrypoint does (fileURLToPath, not URL.pathname — the latter yields "/C:/…" on Windows).
    const here = dirname(fileURLToPath(import.meta.url));
    const projectRoot = process.env.AG_HOME ?? resolve(here, '..', '..');
    files.push(resolve(projectRoot, 'rules', 'default_policy.yaml'));
  }

  let totalErrors = 0;

  for (const file of files) {
    const resolved = resolve(file);
    if (!existsSync(resolved)) {
      process.stderr.write(`cerberus rules validate: file not found: ${resolved}\n`);
      totalErrors++;
      continue;
    }

    const problems = validateFile(resolved);
    if (problems.length === 0) {
      process.stdout.write(`✓ ${resolved}\n`);
    } else {
      process.stdout.write(`✗ ${resolved}\n`);
      for (const p of problems) {
        const loc = p.line !== undefined ? `:${p.line}` : '';
        process.stdout.write(`  ${resolved}${loc}: ${p.message}\n`);
      }
      totalErrors += problems.length;
    }
  }

  if (totalErrors > 0) {
    process.stdout.write(`\n${totalErrors} problem(s) found.\n`);
    process.exit(1);
  } else {
    process.stdout.write('\nAll rule files valid.\n');
  }
}
