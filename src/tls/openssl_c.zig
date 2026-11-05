//! Minimal hand-written bindings to OpenSSL 3.x (libssl/libcrypto).
//! Only what likzik uses; macros are expanded to their *_ctrl calls.
//! Constants are checked against OpenSSL 3.0 headers.

pub const SSL_CTX = opaque {};
pub const SSL = opaque {};
pub const SSL_METHOD = opaque {};
pub const BIO = opaque {};
pub const SSL_CIPHER = opaque {};

pub const SSL_FILETYPE_PEM: c_int = 1;
pub const SSL_VERIFY_NONE: c_int = 0;
pub const SSL_VERIFY_PEER: c_int = 1;

pub const SSL_ERROR_NONE: c_int = 0;
pub const SSL_ERROR_SSL: c_int = 1;
pub const SSL_ERROR_WANT_READ: c_int = 2;
pub const SSL_ERROR_WANT_WRITE: c_int = 3;
pub const SSL_ERROR_SYSCALL: c_int = 5;
pub const SSL_ERROR_ZERO_RETURN: c_int = 6;

pub const SSL_OP_ENABLE_KTLS: u64 = 1 << 3;
pub const SSL_OP_IGNORE_UNEXPECTED_EOF: u64 = 1 << 7;
pub const SSL_OP_NO_COMPRESSION: u64 = 1 << 17;
pub const SSL_OP_CIPHER_SERVER_PREFERENCE: u64 = 1 << 22;
pub const SSL_OP_NO_RENEGOTIATION: u64 = 1 << 30;

pub const SSL_MODE_ENABLE_PARTIAL_WRITE: c_long = 0x1;
pub const SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER: c_long = 0x2;
pub const SSL_MODE_RELEASE_BUFFERS: c_long = 0x10;

pub const SSL_CTRL_MODE: c_int = 33;
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_CB: c_int = 53;
pub const SSL_CTRL_SET_TLSEXT_SERVERNAME_ARG: c_int = 54;
pub const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
pub const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
pub const TLSEXT_NAMETYPE_host_name: c_int = 0;
pub const TLS1_2_VERSION: c_long = 0x0303;
pub const TLS1_3_VERSION: c_long = 0x0304;

pub const SSL_TLSEXT_ERR_OK: c_int = 0;
pub const SSL_TLSEXT_ERR_NOACK: c_int = 3;
pub const OPENSSL_NPN_NEGOTIATED: c_int = 1;

pub const BIO_CTRL_GET_KTLS_SEND: c_int = 73;
pub const BIO_CTRL_GET_KTLS_RECV: c_int = 76;

pub const ServernameCb = *const fn (ssl: *SSL, al: *c_int, arg: ?*anyopaque) callconv(.c) c_int;
pub const AlpnSelectCb = *const fn (ssl: *SSL, out: *[*c]const u8, outlen: *u8, in: [*c]const u8, inlen: c_uint, arg: ?*anyopaque) callconv(.c) c_int;

pub extern fn TLS_server_method() ?*const SSL_METHOD;
pub extern fn TLS_client_method() ?*const SSL_METHOD;
pub extern fn SSL_CTX_new(method: ?*const SSL_METHOD) ?*SSL_CTX;
pub extern fn SSL_CTX_free(ctx: ?*SSL_CTX) void;
pub extern fn SSL_CTX_up_ref(ctx: *SSL_CTX) c_int;
pub extern fn SSL_CTX_set_options(ctx: *SSL_CTX, op: u64) u64;
pub extern fn SSL_CTX_ctrl(ctx: *SSL_CTX, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;
pub extern fn SSL_CTX_callback_ctrl(ctx: *SSL_CTX, cmd: c_int, cb: ?*const fn () callconv(.c) void) c_long;
pub extern fn SSL_CTX_use_certificate_chain_file(ctx: *SSL_CTX, file: [*:0]const u8) c_int;
pub extern fn SSL_CTX_use_PrivateKey_file(ctx: *SSL_CTX, file: [*:0]const u8, typ: c_int) c_int;
pub extern fn SSL_CTX_check_private_key(ctx: *const SSL_CTX) c_int;
pub extern fn SSL_CTX_set_ciphersuites(ctx: *SSL_CTX, str: [*:0]const u8) c_int;
pub extern fn SSL_CTX_set_cipher_list(ctx: *SSL_CTX, str: [*:0]const u8) c_int;
pub extern fn SSL_CTX_set_alpn_select_cb(ctx: *SSL_CTX, cb: AlpnSelectCb, arg: ?*anyopaque) void;
pub extern fn SSL_CTX_set_alpn_protos(ctx: *SSL_CTX, protos: [*]const u8, len: c_uint) c_int;
pub extern fn SSL_CTX_set_num_tickets(ctx: *SSL_CTX, n: usize) c_int;
pub extern fn SSL_CTX_set_verify(ctx: *SSL_CTX, mode: c_int, cb: ?*const anyopaque) void;
pub extern fn SSL_CTX_set_default_verify_paths(ctx: *SSL_CTX) c_int;
pub extern fn SSL_CTX_load_verify_locations(ctx: *SSL_CTX, file: ?[*:0]const u8, path: ?[*:0]const u8) c_int;

pub extern fn SSL_new(ctx: *SSL_CTX) ?*SSL;
pub extern fn SSL_free(ssl: ?*SSL) void;
pub extern fn SSL_set_fd(ssl: *SSL, fd: c_int) c_int;
pub extern fn SSL_set_accept_state(ssl: *SSL) void;
pub extern fn SSL_set_connect_state(ssl: *SSL) void;
pub extern fn SSL_do_handshake(ssl: *SSL) c_int;
pub extern fn SSL_read(ssl: *SSL, buf: [*]u8, num: c_int) c_int;
pub extern fn SSL_write(ssl: *SSL, buf: [*]const u8, num: c_int) c_int;
pub extern fn SSL_get_error(ssl: *const SSL, ret: c_int) c_int;
pub extern fn SSL_shutdown(ssl: *SSL) c_int;
pub extern fn SSL_pending(ssl: *const SSL) c_int;
pub extern fn SSL_ctrl(ssl: *SSL, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;
pub extern fn SSL_get_servername(ssl: *const SSL, typ: c_int) ?[*:0]const u8;
pub extern fn SSL_set_SSL_CTX(ssl: *SSL, ctx: *SSL_CTX) ?*SSL_CTX;
pub extern fn SSL_get_rbio(ssl: *const SSL) ?*BIO;
pub extern fn SSL_get_wbio(ssl: *const SSL) ?*BIO;
pub extern fn SSL_set1_host(ssl: *SSL, hostname: [*:0]const u8) c_int;
pub extern fn SSL_get_version(ssl: *const SSL) [*:0]const u8;
pub extern fn SSL_get_current_cipher(ssl: *const SSL) ?*const SSL_CIPHER;
pub extern fn SSL_CIPHER_get_name(c: ?*const SSL_CIPHER) [*:0]const u8;
pub extern fn SSL_select_next_proto(out: *[*c]u8, outlen: *u8, server: [*]const u8, server_len: c_uint, client: [*c]const u8, client_len: c_uint) c_int;
pub extern fn BIO_ctrl(b: ?*BIO, cmd: c_int, larg: c_long, parg: ?*anyopaque) c_long;

pub extern fn ERR_get_error() c_ulong;
pub extern fn ERR_peek_error() c_ulong;
pub extern fn ERR_error_string_n(e: c_ulong, buf: [*]u8, len: usize) void;
pub extern fn ERR_clear_error() void;
