export interface ToolInputSchema {
  type: "object";
  properties: Record<string, any>;
  required?: string[];
  additionalProperties?: boolean;
}

export interface MCPTool {
  name: string;
  description: string;
  inputSchema: ToolInputSchema;
  handler: (args: Record<string, any>) => Promise<string>;
}

export interface DiagnosticCheck {
  name: string;
  status: "pass" | "fail" | "skip";
  detail: string;
}

export interface DiagnosticsReport {
  checks: DiagnosticCheck[];
  summary: string;
}

export interface PCConfig {
  port: number;
  secret: string;
}

export type PCRegistry = Record<string, PCConfig>;

export interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method: string;
  params?: Record<string, any>;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: any;
  error?: {
    code: number;
    message: string;
    data?: any;
  };
}
