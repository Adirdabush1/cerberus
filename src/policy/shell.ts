/**
 * Shell-line segmentation for the policy engine.
 *
 * ALLOW rules match a command by its first word (`^\s*(ls|grep|…)\b`). On their own they would
 * approve whatever is chained after that word — `grep x f; sed -i … .env`, `ls && rm -r src`. The
 * engine therefore re-checks an ALLOW against every simple command the line runs.
 *
 * GOVERNING PRINCIPLE: a mis-parse may only ever make the engine STRICTER. A wrong split yields
 * extra segments (each of which must pass on its own), and anything that cannot be judged from the
 * words alone returns null so the caller falls back to human review.
 */

/** Redirect targets that discard output (bash, PowerShell, cmd). Any other target is a file write. */
const NULL_SINK = /^(\/dev\/null|\$null|nul)$/i;

/**
 * Split a bash / PowerShell / cmd line into its simple commands, on `;` `|` `&` `||` `&&` and
 * newlines outside quotes. Returns null ("not judgeable") when the line contains:
 *   - command substitution: `$(…)` or backticks (live inside "…" too)
 *   - unquoted `(…)` or `{…}` — subshells, process substitution, PowerShell script blocks and
 *     grouping expressions all run code from inside an otherwise read-only command
 *   - output redirection into a file (`> out.txt`); fd duplication (`2>&1`) and null sinks are fine
 *   - a backslash before a quote: bash reads `\"` as an escape and PowerShell does not, and either
 *     reading could hide a separator from the other
 *   - an unterminated quote
 */
export function splitCommand(line: string): string[] | null {
  const segments: string[] = [];
  let cur = '';
  let quote: "'" | '"' | null = null;
  const flush = (): void => {
    if (cur.trim()) segments.push(cur.trim());
    cur = '';
  };

  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    const next = line[i + 1];
    if (c === '\\' && (next === '"' || next === "'")) return null;

    if (quote === "'") {
      // single quotes are literal in both bash and PowerShell
      if (c === "'") quote = null;
      cur += c;
      continue;
    }
    if (c === '`' || (c === '$' && next === '(')) return null;
    if (quote === '"') {
      if (c === '"') quote = null;
      cur += c;
      continue;
    }

    if (c === "'" || c === '"') {
      quote = c;
      cur += c;
      continue;
    }
    if (c === '(' || c === ')' || c === '{' || c === '}') return null;

    // `>`, `>>`, `2>`, `*>`, `&>` … followed by an fd duplication (`>&1`) or a target word.
    if (c === '>' || (c === '&' && next === '>')) {
      let j = c === '&' ? i + 2 : i + 1;
      if (line[j] === '>') j++;
      let end: number;
      if (line[j] === '&') {
        const dup = /^&(\d+|-)/.exec(line.slice(j));
        if (!dup) return null;
        end = j + dup[0].length;
      } else {
        while (line[j] === ' ' || line[j] === '\t') j++;
        const target = /^[^\s;|&<>]*/.exec(line.slice(j))![0];
        if (!NULL_SINK.test(target)) return null;
        end = j + target.length;
      }
      cur += line.slice(i, end);
      i = end - 1;
      continue;
    }

    if (c === ';' || c === '|' || c === '&' || c === '\n' || c === '\r') {
      flush();
      continue;
    }
    cur += c;
  }

  if (quote) return null;
  flush();
  return segments;
}
