const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    if (target.result.os.tag != .linux) {
        std.debug.print("likzik supports Linux only\n", .{});
    }

    const options = b.addOptions();
    options.addOption([]const u8, "version", "0.1.0");
    const options_mod = options.createModule();

    const lib = b.addModule("likzik", .{
        .root_source_file = b.path("src/likzik.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.addImport("build_options", options_mod);
    // TLS: OpenSSL 3.x from the system (built with kTLS support).
    lib.link_libc = true;
    lib.linkSystemLibrary("ssl", .{});
    lib.linkSystemLibrary("crypto", .{});
    // xDS: gRPC over HTTP/2 (nghttp2) with protobuf-c messages generated from
    // proto/xds.proto (the generated C is committed; `make proto` refreshes it).
    lib.linkSystemLibrary("nghttp2", .{});
    lib.linkSystemLibrary("protobuf-c", .{});
    lib.addIncludePath(b.path("proto"));
    lib.addCSourceFile(.{ .file = b.path("proto/xds.pb-c.c"), .flags = &.{"-std=c99"} });
    const xds_c = b.addTranslateC(.{ .root_source_file = b.path("proto/xds_c.h"), .target = target, .optimize = optimize });
    xds_c.addIncludePath(b.path("proto"));
    lib.addImport("xds_c", xds_c.createModule());

    const exe = b.addExecutable(.{
        .name = "likzik",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "likzik", .module = lib }},
        }),
    });
    exe.root_module.addImport("build_options", options_mod);
    b.installArtifact(exe);

    // likzik-gw: core + API gateway extension (src/gateway).
    const gateway_mod = b.createModule(.{
        .root_source_file = b.path("src/gateway/gateway.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "likzik", .module = lib }},
    });
    const core_main_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "likzik", .module = lib },
            .{ .name = "build_options", .module = options_mod },
        },
    });
    const gw_exe = b.addExecutable(.{
        .name = "likzik-gw",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/gw_main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "likzik", .module = lib },
                .{ .name = "gateway", .module = gateway_mod },
                .{ .name = "likzik_main", .module = core_main_mod },
            },
        }),
    });
    b.installArtifact(gw_exe);

    // likzik-ui: web dashboard (status from the admin endpoint, config
    // edits through the config file). Runs beside the proxy.
    const ui_exe = b.addExecutable(.{
        .name = "likzik-ui",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/ui/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "likzik", .module = lib }},
        }),
    });
    b.installArtifact(ui_exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run likzik").dependOn(&run_cmd.step);

    // Unit tests.
    const unit = b.addTest(.{ .root_module = lib });
    const run_unit = b.addRunArtifact(unit);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit.step);
    const gw_tests = b.addTest(.{ .root_module = gateway_mod });
    test_step.dependOn(&b.addRunArtifact(gw_tests).step);

    // Parser fuzz tests. `zig build fuzz -Dfuzz-iters=N` runs the mutation
    // fuzzer longer; `--fuzz` uses Zig's coverage-guided fuzzer.
    const fuzz_opts = b.addOptions();
    fuzz_opts.addOption(usize, "iterations", b.option(usize, "fuzz-iters", "mutation fuzzer iterations (default 100000)") orelse 100_000);
    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("tests/fuzz/http1_fuzz.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "likzik", .module = lib },
            .{ .name = "fuzz_options", .module = fuzz_opts.createModule() },
        },
    });
    const fuzz = b.addTest(.{ .root_module = fuzz_mod });
    const run_fuzz = b.addRunArtifact(fuzz);
    b.step("fuzz", "Run the HTTP/1.1 parser fuzz tests").dependOn(&run_fuzz.step);
    test_step.dependOn(&run_fuzz.step);

    // Parser micro-benchmark.
    const bench = b.addExecutable(.{
        .name = "parse-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/parse_bench.zig"),
            .target = target,
            .optimize = .fast,
            .imports = &.{.{ .name = "likzik", .module = lib }},
        }),
    });
    const run_bench = b.addRunArtifact(bench);
    b.step("bench-parse", "Benchmark the HTTP/1.1 parser").dependOn(&run_bench.step);
    b.installArtifact(bench);

}
