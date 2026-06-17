/**
 * `cerberus service <install|uninstall|status>` (M8, Part 1).
 *
 * Runs the engine ALWAYS-ON in the background: a macOS launchd LaunchAgent with RunAtLoad + KeepAlive,
 * so the gateway survives logout, reboot, and closed agent sessions. The whole point of always-on is
 * pairing it with out-of-band escalation, so install bakes in AG_ESCALATE=1 and the dashboard-hold
 * surface (escalation can only fire while the engine actually holds the call).
 *
 * Linux (systemd --user) is deferred — install prints guidance there rather than half-working.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const LABEL = 'com.cerberus.engine';

function plistPath(): string {
  return join(homedir(), 'Library', 'LaunchAgents', `${LABEL}.plist`);
}

/** Env vars baked into the LaunchAgent: always-on defaults, overridable by the installing shell. */
function serviceEnv(): Record<string, string> {
  const env: Record<string, string> = {
    // Always-on exists to enable OOB escalation, and escalation only fires on the dashboard-hold
    // surface — so default both on (the installing shell can still override either).
    AG_ESCALATE: process.env.AG_ESCALATE ?? '1',
    AG_APPROVAL_SURFACE: process.env.AG_APPROVAL_SURFACE ?? 'dashboard',
    // launchd starts with a bare PATH; carry the installing shell's PATH so AG_NOTIFY_CMD can find tools.
    PATH: process.env.PATH ?? '/usr/local/bin:/usr/bin:/bin',
  };
  // Pass through any explicitly-set tuning so the background engine matches the user's intent.
  for (const k of [
    'AG_ENGINE_PORT', 'AG_NOTIFY_CMD', 'AG_PUBLIC_URL', 'AG_ESCALATE_GRACE_MS',
    'AG_ESCALATE_GRANT_MS', 'AG_ESCALATE_KEY', 'AG_RULES', 'AG_RISK_WEIGHTS',
    'AG_AUDIT', 'AG_TTL_MS', 'AG_INJECTION', 'AG_AUTO_OPEN',
  ]) {
    if (process.env[k]) env[k] = process.env[k] as string;
  }
  return env;
}

function xmlEscape(s: string): string {
  return s.replace(/[<>&]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;' })[c] as string);
}

function buildPlist(root: string): string {
  const node = process.execPath;
  const cli = join(root, 'bin', 'cerberus.mjs');
  const logDir = join(root, '.cerberus');
  mkdirSync(logDir, { recursive: true });
  const env = serviceEnv();
  const envXml = Object.entries(env)
    .map(([k, v]) => `      <key>${xmlEscape(k)}</key>\n      <string>${xmlEscape(v)}</string>`)
    .join('\n');
  const args = [node, cli, 'engine'].map((a) => `      <string>${xmlEscape(a)}</string>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${args}
  </array>
  <key>EnvironmentVariables</key>
  <dict>
${envXml}
  </dict>
  <key>WorkingDirectory</key>
  <string>${xmlEscape(root)}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>${xmlEscape(join(logDir, 'engine.out.log'))}</string>
  <key>StandardErrorPath</key>
  <string>${xmlEscape(join(logDir, 'engine.err.log'))}</string>
</dict>
</plist>
`;
}

function launchctl(args: string[]): { ok: boolean; out: string } {
  try {
    const out = execFileSync('launchctl', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { ok: true, out };
  } catch (err) {
    return { ok: false, out: err instanceof Error ? err.message : String(err) };
  }
}

function install(root: string): void {
  const path = plistPath();
  mkdirSync(join(homedir(), 'Library', 'LaunchAgents'), { recursive: true });
  launchctl(['unload', '-w', path]); // best-effort: clear any previous load before rewriting
  writeFileSync(path, buildPlist(root), { mode: 0o644 });
  const r = launchctl(['load', '-w', path]);
  if (!r.ok) {
    process.stderr.write(`Cerberus: wrote ${path} but \`launchctl load\` failed:\n${r.out}\n`);
    process.exit(1);
  }
  const port = process.env.AG_ENGINE_PORT ?? '9000';
  process.stdout.write(
    `✓ Cerberus engine installed as a launchd service (${LABEL}).\n` +
      `  plist:  ${path}\n` +
      `  starts: now + at every login/reboot (KeepAlive)\n` +
      `  engine: http://127.0.0.1:${port}/  ·  logs in ${join(root, '.cerberus')}/engine.*.log\n` +
      `  escalate: ${serviceEnv().AG_ESCALATE === '1' ? 'on' : 'off'}` +
      `${process.env.AG_NOTIFY_CMD ? '' : '  (set AG_NOTIFY_CMD before install to wire email/push)'}\n` +
      `  stop:   cerberus service uninstall\n`,
  );
}

function uninstall(): void {
  const path = plistPath();
  if (!existsSync(path)) {
    process.stdout.write('Cerberus: no launchd service installed.\n');
    return;
  }
  launchctl(['unload', '-w', path]);
  rmSync(path, { force: true });
  process.stdout.write(`✓ Cerberus engine service removed (${LABEL}).\n`);
}

function status(): void {
  const path = plistPath();
  if (!existsSync(path)) {
    process.stdout.write('Cerberus service: not installed (run `cerberus service install`).\n');
    return;
  }
  const r = launchctl(['list', LABEL]);
  if (r.ok) {
    // launchctl list <label> prints a dict including "PID" when running.
    const running = /"PID"\s*=/.test(r.out);
    process.stdout.write(`Cerberus service: installed, ${running ? 'running' : 'loaded (not running — check logs)'}\n  plist: ${path}\n`);
  } else {
    process.stdout.write(`Cerberus service: plist present at ${path}, but not loaded. Run \`cerberus service install\`.\n`);
  }
}

export function runService(action: string | undefined, root: string): void {
  if (process.platform !== 'darwin') {
    process.stderr.write(
      'Cerberus: `service` currently supports macOS (launchd) only.\n' +
        'On Linux, run the engine under systemd --user or your process manager, e.g.:\n' +
        `  AG_ESCALATE=1 AG_APPROVAL_SURFACE=dashboard ${process.execPath} ${join(root, 'bin', 'cerberus.mjs')} engine\n`,
    );
    process.exit(1);
  }
  switch (action) {
    case 'install':
      return install(root);
    case 'uninstall':
      return uninstall();
    case 'status':
      return status();
    default:
      process.stderr.write('usage: cerberus service <install|uninstall|status>\n');
      process.exit(1);
  }
}
