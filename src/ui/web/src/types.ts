// The likzik config file (config/model.zig + gateway/config.zig), as JSON.
// Fields are optional where the proxy has defaults.

export type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
export const METHODS: Method[] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

export interface Certificate { certificate_chain: string; private_key: string; server_names?: string[] }
export interface Listener {
  name: string; address: string; protocol?: "http" | "tcp";
  route_config?: string; cluster?: string; trust_forwarded_headers?: boolean;
  idle_timeout_ms?: number; tls?: { certificates: Certificate[] };
}
export interface CoreRoute {
  match: { prefix?: string; path?: string; methods?: string[] };
  route: { cluster: string; prefix_rewrite?: string; timeout_ms?: number };
}
export interface VirtualHost { name: string; domains: string[]; routes: CoreRoute[] }
export interface RouteConfig { name: string; virtual_hosts: VirtualHost[] }
export interface Endpoint { address: string; weight?: number }
export type LbPolicy = "least_request" | "round_robin" | "random";
export interface Cluster {
  name: string; lb_policy?: LbPolicy; connect_timeout_ms?: number; idle_timeout_ms?: number;
  max_idle_per_endpoint?: number; max_connect_attempts?: number; eject_after_failures?: number; eject_ms?: number;
  tls?: { sni?: string; verify?: boolean; ca_file?: string }; endpoints: Endpoint[];
}

export interface NameValue { name: string; value: string }
export interface HeaderOps { set?: NameValue[]; add?: NameValue[]; remove?: string[] }
export interface HeaderMatch { name: string; value?: string; prefix?: string; present?: boolean }
export interface QueryMatch { name: string; value?: string; present?: boolean }
export interface GwRoute {
  name: string; hosts?: string[]; path: string; methods?: string[];
  headers?: HeaderMatch[]; query?: QueryMatch[];
  auth?: string[]; auth_optional?: boolean; rate_limits?: string[];
  cluster?: string; redirect?: { status?: number; location: string };
  respond?: { status?: number; body?: string; content_type?: string };
  rewrite?: string; timeout_ms?: number;
  request_headers?: HeaderOps; response_headers?: HeaderOps;
}
export interface ApiKeySet {
  name: string; header?: string; query?: string; strip?: boolean;
  keys: { consumer: string; sha256?: string; key?: string }[];
}
export interface JwtProvider {
  name: string; algorithms: string[]; issuer?: string; audiences?: string[];
  jwks_file?: string; jwks?: unknown; hs_secret?: string; leeway_s?: number;
  header?: string; query?: string; consumer_claim?: string;
  claims_to_headers?: { claim: string; header: string }[]; forward_token?: boolean; require_exp?: boolean;
}
export interface RateLimit { name: string; requests: number; per?: "second" | "minute" | "hour"; burst?: number; key?: string }
export interface Gateway {
  listeners?: string[]; fallthrough?: boolean; consumer_header?: string;
  api_keys?: ApiKeySet[]; jwt?: JwtProvider[]; rate_limits?: RateLimit[]; routes: GwRoute[];
}
export interface Config {
  version?: string; workers?: number; admin?: { address: string };
  limits?: Record<string, number>; tls?: { require_ktls?: boolean };
  xds?: { address: string; node_id: string; node_cluster?: string; authority?: string; connect_timeout_ms?: number };
  listeners: Listener[]; route_configs?: RouteConfig[]; clusters?: Cluster[];
  extensions?: { gateway?: Gateway };
}

// Admin endpoint (/server_info) as proxied by likzik-ui.
export interface ServerInfo {
  name: string; build: string; state: "live" | "draining"; uptime_ms: number; workers: number;
  config: { version: string; generation: number; reloads_ok: number; reloads_failed: number; last_error: string };
  worker_generations: number[];
}
export type Stats = Record<string, number>;
export interface HistoryEntry { id: number; time_ms: number; note: string; replaced_generation: number | null; size: number }
