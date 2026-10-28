/**
 * PolicyEngine — the deterministic decision core.
 *
 * V1 implementation reads declarative rules (DATA, not code) from a YAML file and
 * evaluates them with json-logic-js. Hidden behind the `PolicyEngine` interface so
 * an OPA or Cedar adapter can be dropped in for Enterprise without touching callers.
 */
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import jsonLogic from 'json-logic-js';
import { classify } from '../taxonomy/index.js';
import { splitCommand } from './shell.js';
import type { MCPToolCall, PolicyAction, PolicyDecision, ToolCategory } from '../contract/types.js';

export interface PolicyEngine {
  evaluate(call: MCPToolCall): PolicyDecision;
}

interface Rule {
  id: string;
  description: string;
  action: PolicyAction;
  when: unknown;
}

interface PolicyFile {
  default: PolicyAction;
  rules: Rule[];
}

/** The primitive fields rules match against. */
interface Fact {
  tool: string;
  category: ToolCategory;
  command: string;
  path: string;
  glob: string;
  url: string;
  cwd: string;
}

const STRICTNESS: Readonly<Record<PolicyAction, number>> = { ALLOW: 0, HITL: 1, BLOCK: 2 };

// Register a regex operation once, so rules can express `{ matches: [pattern, { var: command }] }`,
// with optional RegExp flags as a third argument: `{ matches: [pattern, { var: path }, "i"] }`.
let opsRegistered = false;
function registerOps(): void {
  if (opsRegistered) return;
  jsonLogic.add_operation('matches', (pattern: unknown, value: unknown, flags?: unknown): boolean => {
    if (typeof pattern !== 'string' || typeof value !== 'string') return false;
    try {
      return new RegExp(pattern, typeof flags === 'string' ? flags : '').test(value);
    } catch {
      return false; // a malformed rule must never throw inside the hot path
    }
  });
  opsRegistered = true;
}

export class JsonLogicPolicyEngine implements PolicyEngine {
  private readonly policy: PolicyFile;

  constructor(rulesPath: string) {
    registerOps();
    const parsed = yaml.load(readFileSync(rulesPath, 'utf8')) as Partial<PolicyFile> | undefined;
    if (!parsed || !Array.isArray(parsed.rules)) {
      throw new Error(`AgentGuard: invalid policy file at ${rulesPath} (expected { default, rules[] }).`);
    }
    this.policy = { default: parsed.default ?? 'HITL', rules: parsed.rules };
  }

  evaluate(call: MCPToolCall): PolicyDecision {
    const category = classify(call.tool);
    const fact = this.toFact(call, category);

    const rule = this.firstMatch(fact);
    if (rule) {
      const decision: PolicyDecision = { action: rule.action, ruleId: rule.id, reason: rule.description, category };
      return rule.action === 'ALLOW' && fact.command ? this.checkEachCommand(fact, decision) : decision;
    }

    // Fail-Closed: a tool we cannot even categorise is never auto-allowed.
    if (category === 'UNKNOWN') {
      return {
        action: 'HITL',
        ruleId: null,
        reason: `Unknown tool "${call.tool}" — fail-closed to human review.`,
        category,
      };
    }

    return {
      action: this.policy.default,
      ruleId: null,
      reason: `No rule matched — applying default policy (${this.policy.default}).`,
      category,
    };
  }

  private firstMatch(fact: Fact): Rule | undefined {
    return this.policy.rules.find((rule) => jsonLogic.apply(rule.when, fact) === true);
  }

  /**
   * ALLOW rules anchor on a command's first word, so `grep x f; sed -i … .env` would ride in on
   * `grep`. The line is allowed only if every simple command on it is allowed on its own; otherwise
   * the strictest per-command decision wins. A line that can't be split safely goes to review.
   */
  private checkEachCommand(fact: Fact, allowed: PolicyDecision): PolicyDecision {
    const segments = splitCommand(fact.command);
    if (segments === null) {
      return {
        action: 'HITL',
        ruleId: null,
        reason: 'Command uses substitution, grouping or file redirection — too dynamic to auto-approve; human review.',
        category: fact.category,
      };
    }
    let strictest = allowed;
    for (const command of segments) {
      const rule = this.firstMatch({ ...fact, command });
      const action = rule?.action ?? this.policy.default;
      if (STRICTNESS[action] > STRICTNESS[strictest.action]) {
        const why = rule?.description ?? `no rule matched — default policy (${this.policy.default})`;
        strictest = { action, ruleId: rule?.id ?? null, reason: `\`${command}\`: ${why}`, category: fact.category };
      }
    }
    return strictest;
  }

  /** Flatten the tool call into the primitive fields rules match against. */
  private toFact(call: MCPToolCall, category: ToolCategory): Fact {
    const input = call.input ?? {};
    const str = (v: unknown): string => (typeof v === 'string' ? v : '');
    return {
      tool: call.tool,
      category,
      command: str(input['command']),
      path: str(input['file_path'] ?? input['path']),
      glob: str(input['glob']), // Grep's file filter — `glob: ".env"` reads the file like a path does
      url: str(input['url']),
      cwd: call.cwd ?? '',
    };
  }
}
