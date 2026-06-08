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

// Register a regex operation once, so rules can express `{ matches: [pattern, { var: command }] }`.
let opsRegistered = false;
function registerOps(): void {
  if (opsRegistered) return;
  jsonLogic.add_operation('matches', (pattern: unknown, value: unknown): boolean => {
    if (typeof pattern !== 'string' || typeof value !== 'string') return false;
    try {
      return new RegExp(pattern).test(value);
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

    for (const rule of this.policy.rules) {
      if (jsonLogic.apply(rule.when, fact) === true) {
        return { action: rule.action, ruleId: rule.id, reason: rule.description, category };
      }
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

  /** Flatten the tool call into the primitive fields rules match against. */
  private toFact(call: MCPToolCall, category: ToolCategory) {
    const input = call.input ?? {};
    const str = (v: unknown): string => (typeof v === 'string' ? v : '');
    return {
      tool: call.tool,
      category,
      command: str(input['command']),
      path: str(input['file_path'] ?? input['path']),
      url: str(input['url']),
      cwd: call.cwd ?? '',
    };
  }
}
