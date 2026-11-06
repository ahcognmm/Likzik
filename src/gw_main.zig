//! likzik-gw: the likzik core proxy with the API gateway extension.
//! Same supervisor, workers and config as `likzik`; the gateway is
//! configured in the config's `extensions.gateway` section.

const std = @import("std");
const likzik = @import("likzik");
const gateway = @import("gateway");
const core_main = @import("likzik_main");

pub const std_options: std.Options = .{ .log_level = .info };

pub fn main(init: std.process.Init) !u8 {
    likzik.proxy.filter.registered = &gateway.extension;
    return core_main.run(init);
}
