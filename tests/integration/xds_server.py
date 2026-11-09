"""Minimal ADS (state of the world) server for likzik's xDS tests, built on
Envoy's real protos (pip: grpcio, xds-protos).

    python3 xds_server.py GRPC_PORT HTTP_PORT

HTTP side door:
    PUT /state     set what is served (JSON, see build_*), pushes to clients
    GET /requests  every DiscoveryRequest received, as JSON lines
"""
import json, queue, sys, threading
from concurrent import futures
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import grpc
from envoy.config.cluster.v3 import cluster_pb2
from envoy.config.endpoint.v3 import endpoint_pb2
from envoy.config.listener.v3 import listener_pb2
from envoy.config.route.v3 import route_pb2
from envoy.extensions.filters.network.http_connection_manager.v3 import http_connection_manager_pb2 as hcm_pb2
from envoy.extensions.filters.network.tcp_proxy.v3 import tcp_proxy_pb2
from envoy.service.discovery.v3 import ads_pb2_grpc, discovery_pb2

T = "type.googleapis.com/envoy."
CDS, EDS = T + "config.cluster.v3.Cluster", T + "config.endpoint.v3.ClusterLoadAssignment"
LDS, RDS = T + "config.listener.v3.Listener", T + "config.route.v3.RouteConfiguration"

state = {"version": "0"}
state_cv = threading.Condition()
requests_log = []


def cla(name, addrs):
    m = endpoint_pb2.ClusterLoadAssignment(cluster_name=name)
    loc = m.endpoints.add()
    for a in addrs:
        host, port = a.rsplit(":", 1)
        sa = loc.lb_endpoints.add().endpoint.address.socket_address
        sa.address, sa.port_value = host, int(port)
    return m


def build(st):
    out = {CDS: {}, EDS: {}, LDS: {}, RDS: {}}
    for c in st.get("clusters", []):
        m = cluster_pb2.Cluster(name=c["name"])
        m.lb_policy = cluster_pb2.Cluster.LbPolicy.Value(c.get("lb", "ROUND_ROBIN"))
        m.connect_timeout.FromMilliseconds(c.get("connect_timeout_ms", 1000))
        if c.get("eds"):
            m.type = cluster_pb2.Cluster.EDS
            m.eds_cluster_config.eds_config.ads.SetInParent()
        else:
            m.type = cluster_pb2.Cluster.STATIC
            m.load_assignment.CopyFrom(cla(c["name"], c["endpoints"]))
        out[CDS][m.name] = m
    for name, addrs in st.get("endpoints", {}).items():
        out[EDS][name] = cla(name, addrs)
    for l in st.get("listeners", []):
        m = listener_pb2.Listener(name=l["name"])
        m.address.socket_address.address = "127.0.0.1"
        m.address.socket_address.port_value = l["port"]
        f = m.filter_chains.add().filters.add()
        if "tcp_cluster" in l:
            f.name = "envoy.filters.network.tcp_proxy"
            f.typed_config.Pack(tcp_proxy_pb2.TcpProxy(stat_prefix=l["name"], cluster=l["tcp_cluster"]))
        else:
            h = hcm_pb2.HttpConnectionManager(stat_prefix=l["name"])
            h.rds.route_config_name = l["rds"]
            h.rds.config_source.ads.SetInParent()
            f.name = "envoy.filters.network.http_connection_manager"
            f.typed_config.Pack(h)
        out[LDS][m.name] = m
    for r in st.get("routes", []):
        m = route_pb2.RouteConfiguration(name=r["name"])
        for vh in r["vhosts"]:
            v = m.virtual_hosts.add(name=vh["name"], domains=vh["domains"])
            for rt in vh["routes"]:
                x = v.routes.add()
                if "path" in rt:
                    x.match.path = rt["path"]
                else:
                    x.match.prefix = rt.get("prefix", "/")
                if "regex" in rt:
                    x.match.ClearField("prefix")
                    x.match.safe_regex.regex = rt["regex"]
                x.route.cluster = rt["cluster"]
                if "rewrite" in rt:
                    x.route.prefix_rewrite = rt["rewrite"]
        out[RDS][m.name] = m
    return out


class Ads(ads_pb2_grpc.AggregatedDiscoveryServiceServicer):
    def StreamAggregatedResources(self, request_iterator, context):
        inbox = queue.Queue()
        subs = {}  # type_url -> resource names ([] = wildcard)
        sent = {}  # type_url -> version sent

        def reader():
            try:
                for req in request_iterator:
                    inbox.put(req)
            finally:
                inbox.put(None)
        threading.Thread(target=reader, daemon=True).start()

        def responses(force_types):
            with state_cv:
                version, resources = state["version"], state["resources"]
            for t in force_types:
                if t not in subs:
                    continue
                if sent.get(t) == version and t not in forced:
                    continue
                names = subs[t]
                items = [m for n, m in resources[t].items() if not names or n in names]
                resp = discovery_pb2.DiscoveryResponse(version_info=version, type_url=t, nonce=f"{t[-8:]}-{version}")
                for m in items:
                    resp.resources.add().Pack(m)
                sent[t] = version
                yield resp

        seen_version = None
        while True:
            try:
                req = inbox.get(timeout=0.1)
            except queue.Empty:
                req = False
            if req is None:
                return
            forced = set()
            if req:
                requests_log.append({
                    "type": req.type_url.rsplit(".", 1)[-1], "version": req.version_info,
                    "nonce": req.response_nonce, "names": list(req.resource_names),
                    "error": req.error_detail.message if req.HasField("error_detail") else None,
                    "node": req.node.id,
                })
                names = list(req.resource_names)
                if subs.get(req.type_url) != names or not req.response_nonce:
                    forced.add(req.type_url)  # new or changed subscription
                subs[req.type_url] = names
                yield from responses([req.type_url])
            with state_cv:
                v = state["version"]
            if v != seen_version:
                seen_version = v
                yield from responses([CDS, EDS, LDS, RDS])


class Door(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_PUT(self):
        st = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with state_cv:
            state["version"] = st["version"]
            state["resources"] = build(st)
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        body = "\n".join(json.dumps(r) for r in requests_log).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    state["resources"] = build({})
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    ads_pb2_grpc.add_AggregatedDiscoveryServiceServicer_to_server(Ads(), server)
    server.add_insecure_port(f"127.0.0.1:{sys.argv[1]}")
    server.start()
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[2])), Door).serve_forever()
