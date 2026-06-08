declare module 'json-logic-js' {
  type RulesLogic = unknown;
  interface JsonLogic {
    apply(logic: RulesLogic, data?: unknown): unknown;
    add_operation(name: string, fn: (...args: any[]) => unknown): void;
    rm_operation(name: string): void;
    uses_data(logic: RulesLogic): string[];
  }
  const jsonLogic: JsonLogic;
  export default jsonLogic;
}
