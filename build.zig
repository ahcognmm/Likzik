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

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    b.step("run", "Run likzik").dependOn(&run_cmd.step);

    // Unit tests.
    const unit = b.addTest(.{ .root_module = lib });
    const run_unit = b.addRunArtifact(unit);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit.step);

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
            .optimize = .ReleaseFast,
            .imports = &.{.{ .name = "likzik", .module = lib }},
        }),
    });
    const run_bench = b.addRunArtifact(bench);
    b.step("bench-parse", "Benchmark the HTTP/1.1 parser").dependOn(&run_bench.step);
    b.installArtifact(bench);

}
