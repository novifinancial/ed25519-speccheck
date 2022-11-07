const std = @import("std");
const fmt = std.fmt;
const io = std.io;
const Ed25519 = std.crypto.sign.Ed25519;

pub fn main() !void {
    var reader = io.getStdIn().reader();
    var bw = io.bufferedWriter(io.getStdOut().writer());
    var out = bw.writer();

    var count_buf: [4]u8 = undefined;
    const count = try fmt.parseInt(usize, try reader.readUntilDelimiter(&count_buf, '\n'), 10);

    var msg: [32]u8 = undefined;
    var pbk: [32]u8 = undefined;
    var sig: [64]u8 = undefined;
    var msg_hex_buf: [4 + msg.len * 2 + 1]u8 = undefined;
    var pbk_hex_buf: [4 + pbk.len * 2 + 1]u8 = undefined;
    var sig_hex_buf: [4 + sig.len * 2 + 1]u8 = undefined;

    try out.writeAll("\n|Zig            |");
    var i: usize = 0;
    while (i < count) : (i += 1) {
        _ = try fmt.hexToBytes(&msg, (try reader.readUntilDelimiter(&msg_hex_buf, '\n'))[4..]);
        _ = try fmt.hexToBytes(&pbk, (try reader.readUntilDelimiter(&pbk_hex_buf, '\n'))[4..]);
        _ = try fmt.hexToBytes(&sig, (try reader.readUntilDelimiterOrEof(&sig_hex_buf, '\n')).?[4..]);
        try out.writeAll(if (verify(msg, pbk, sig)) " V |" else |_| " X |");
    }
    try out.writeByte('\n');
    try bw.flush();
}

fn verify(msg: [32]u8, pbk_bytes: [32]u8, sig_bytes: [64]u8) !void {
    const pbk = try Ed25519.PublicKey.fromBytes(pbk_bytes);
    const sig = Ed25519.Signature.fromBytes(sig_bytes);
    try sig.verify(&msg, pbk);
}
