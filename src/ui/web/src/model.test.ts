import { describe, expect, it } from "vitest";
import { changes, conflicts, matchKind, routesFor, autoName, flatten, showVal, clientChecks } from "./model";
import type { Config } from "./types";

const cfg: Config = {
  listeners: [
    { name: "api", address: "0.0.0.0:443", route_config: "core" },
    { name: "internal", address: "127.0.0.1:8081", route_config: "core" },
    { name: "db", address: "0.0.0.0:5432", protocol: "tcp", cluster: "pg" },
  ],
  route_configs: [{ name: "core", virtual_hosts: [{ name: "all", domains: ["*"], routes: [{ match: { prefix: "/" }, route: { cluster: "web" } }] }] }],
  clusters: [{ name: "web", endpoints: [{ address: "10.0.0.1:80" }] }, { name: "pg", endpoints: [{ address: "10.0.0.2:5432" }] }],
  extensions: { gateway: { listeners: ["api"], fallthrough: true, routes: [
    { name: "me", path: "/users/me", cluster: "web" },
    { name: "user", path: "/users/:id", methods: ["GET"], cluster: "web" },
    { name: "rest", path: "/users/*rest", cluster: "web" },
  ] } },
};

describe("routesFor", () => {
  it("lists gateway routes then fallthrough core routes on gateway listeners", () => {
    const r = routesFor(cfg, "api");
    expect(r.map((x) => x.kind)).toEqual(["gw", "gw", "gw", "core"]);
    expect(r[3].fallthrough).toBe(true);
  });
  it("lists only core routes elsewhere, nothing for TCP", () => {
    expect(routesFor(cfg, "internal").map((x) => x.kind)).toEqual(["core"]);
    expect(routesFor(cfg, "db")).toEqual([]);
  });
});

describe("conflicts follow the gateway's priority", () => {
  const routes = cfg.extensions!.gateway!.routes;
  it("same shape is a clash, whatever the param names", () => {
    expect(conflicts({ path: "/users/:uid", methods: ["GET"] }, routes).find((c) => c.t === "dup")?.other.name).toBe("user");
  });
  it("more specific new route wins, less specific loses", () => {
    const c = conflicts({ path: "/users/:id/orders" }, routes);
    expect(c.find((x) => x.other.name === "rest")?.t).toBe("wins");
    expect(conflicts({ path: "/*all" }, routes).every((x) => x.t === "loses")).toBe(true);
  });
  it("disjoint methods or paths do not conflict", () => {
    expect(conflicts({ path: "/users/:id", methods: ["POST"] }, [routes[1]])).toEqual([]);
    expect(conflicts({ path: "/orders/:id" }, routes)).toEqual([]);
  });
});

describe("draft changes", () => {
  it("finds new, edited and removed entities", () => {
    const d: Config = JSON.parse(JSON.stringify(cfg));
    d.clusters!.push({ name: "new", endpoints: [{ address: "1.1.1.1:1" }] });
    d.extensions!.gateway!.routes[1].methods = ["GET", "PUT"];
    d.extensions!.gateway!.routes.splice(2, 1);
    const ch = changes(cfg, d).map((c) => `${c.op} ${c.key}`).sort();
    expect(ch).toEqual(["Edited route:user", "New cluster:new", "Removed route:rest"]);
  });
  it("masks secrets in before/after values", () => {
    const f = flatten({ jwt: [{ hs_secret: "x" }], api_keys: [{ keys: [{ key: "k" }] }] });
    for (const [k, v] of Object.entries(f)) expect(showVal(k, v)).toBe("••• (secret)");
  });
});

describe("helpers", () => {
  it("matchKind and autoName", () => {
    expect(matchKind("/a/b")).toBe("Exact");
    expect(matchKind("/a/:id")).toBe("Parameter");
    expect(matchKind("/a/*rest")).toBe("Wildcard");
    expect(autoName(cfg, ["GET"], "/users/:id")).toBe("get-users-id");
  });
  it("checks flag missing clusters", () => {
    const d: Config = JSON.parse(JSON.stringify(cfg));
    d.extensions!.gateway!.routes[0].cluster = "ghost";
    expect(clientChecks(d)[0][0]).toBe("Failed");
    expect(clientChecks(cfg)[0][0]).toBe("Passed");
  });
});
