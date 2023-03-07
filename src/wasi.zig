const std = @import("std");
const builtin = @import("builtin");
const core = @import("core.zig");

const Val = core.Val;
const ValType = core.ValType;
const ModuleInstance = core.ModuleInstance;
const ModuleImports = core.ModuleImports;

const WasiInitError = std.mem.Allocator.Error || std.os.OpenError;

const WasiContext = struct {
    argv: [][]const u8 = &[_][]u8{},
    env: [][]const u8 = &[_][]u8{},
    dirs: [][]const u8 = &[_][]u8{},
    fd_table: std.AutoHashMap(u32, std.os.fd_t), // TODO switch to array
    next_fd_id: u32 = 3,
    allocator: std.mem.Allocator,

    fn init(opts: *const WasiOpts, allocator: std.mem.Allocator) WasiInitError!WasiContext {
        var context = WasiContext{
            .fd_table = std.AutoHashMap(u32, std.os.fd_t).init(allocator),
            .allocator = allocator,
        };

        if (opts.argv) |argv| {
            context.argv = try context.allocator.dupe([]const u8, argv);
            for (argv) |arg, i| {
                context.argv[i] = try context.allocator.dupe(u8, arg);
            }
        }

        if (opts.env) |env| {
            context.env = try context.allocator.dupe([]const u8, env);
            for (env) |e, i| {
                context.env[i] = try context.allocator.dupe(u8, e);
            }
        }

        if (opts.dirs) |dirs| {
            context.dirs = try context.allocator.dupe([]const u8, dirs);
            for (dirs) |e, i| {
                context.dirs[i] = try context.allocator.dupe(u8, e);
            }
        }

        try context.fd_table.put(0, std.io.getStdIn().handle);
        try context.fd_table.put(1, std.io.getStdOut().handle);
        try context.fd_table.put(2, std.io.getStdErr().handle);

        var cwd = std.fs.cwd();
        for (context.dirs) |dir_path| {
            const dir: std.fs.Dir = try cwd.openDir(dir_path, .{});
            _ = try context.fdAdd(dir.fd);
        }

        return context;
    }

    fn deinit(self: *WasiContext) void {
        if (self.argv.len > 0) {
            for (self.argv) |arg| {
                self.allocator.free(arg);
            }
            self.allocator.free(self.argv);
        }

        if (self.env.len > 0) {
            for (self.env) |e| {
                self.allocator.free(e);
            }
            self.allocator.free(self.env);
        }

        if (self.dirs.len > 0) {
            for (self.dirs) |e| {
                self.allocator.free(e);
            }
            self.allocator.free(self.dirs);
        }

        self.fd_table.deinit();
    }

    fn fdLookup(self: *const WasiContext, fd_wasi: u32) ?std.os.fd_t {
        if (fd_wasi != FD_WASI_INVALID) {
            if (self.fd_table.get(fd_wasi)) |fd_os| {
                return fd_os;
            }
        }

        return null;
    }

    fn fdDirPath(self: *WasiContext, fd_wasi: u32) ?[]const u8 {
        if (fd_wasi != FD_WASI_INVALID) {
            const dirs_index = fd_wasi - 3;
            if (dirs_index < self.dirs.len) {
                return self.dirs[dirs_index];
            }
        }

        return null;
    }

    fn fdAdd(self: *WasiContext, fd_os: std.os.fd_t) std.mem.Allocator.Error!u32 {
        var fd_wasi: u32 = self.next_fd_id;
        self.fd_table.put(fd_wasi, fd_os) catch {
            fd_wasi = FD_WASI_INVALID;
        };
        self.next_fd_id += 1;

        return fd_wasi;
    }

    fn fdRemove(self: *WasiContext, wasi_fd: u32) ?std.os.fd_t {
        if (self.fd_table.fetchRemove(wasi_fd)) |result| {
            return result.value;
        } else {
            return null;
        }
    }

    fn hasPathAccess(self: *WasiContext, fd_dir: std.os.fd_t, relative_path: []const u8) bool {
        if (self.dirs.len > 0) {
            const dir = std.fs.Dir{ .fd = fd_dir };
            var path_buffer_relative: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const absolute_path: []const u8 = dir.realpath(relative_path, &path_buffer_relative) catch unreachable;

            const cwd: std.fs.Dir = std.fs.cwd();
            for (self.dirs) |allowdir| {
                var path_buffer_allowed: [std.fs.MAX_PATH_BYTES]u8 = undefined;
                const path_allowed: []const u8 = cwd.realpath(allowdir, &path_buffer_allowed) catch unreachable;
                if (std.mem.startsWith(u8, absolute_path, path_allowed)) {
                    return true;
                }
            }
        }

        return false;
    }

    fn fromUserdata(userdata: ?*anyopaque) *WasiContext {
        std.debug.assert(userdata != null);
        return @ptrCast(*WasiContext, @alignCast(8, userdata.?));
    }
};

// Values taken from https://github.com/AssemblyScript/wasi-shim/blob/main/assembly/bindings/
const Errno = enum(u8) {
    SUCCESS = 0, // No error occurred. System call completed successfully.
    TOOBIG = 1, // Argument list too long.
    ACCES = 2, // Permission denied.
    ADDRINUSE = 3, // Address in use.
    ADDRNOTAVAIL = 4, // Address not available.
    AFNOSUPPORT = 5, // Address family not supported.
    AGAIN = 6, // Resource unavailable, or operation would block.
    ALREADY = 7, // Connection already in progress.
    BADF = 8, // Bad file descriptor.
    BADMSG = 9, // Bad message.
    BUSY = 10, // Device or resource busy.
    CANCELED = 11, // Operation canceled.
    CHILD = 12, // No child processes.
    CONNABORTED = 13, // Connection aborted.
    CONNREFUSED = 14, // Connection refused.
    CONNRESET = 15, // Connection reset.
    DEADLK = 16, // Resource deadlock would occur.
    DESTADDRREQ = 17, // Destination address required.
    DOM = 18, // Mathematics argument out of domain of function.
    DQUOT = 19, // Reserved.
    EXIST = 20, // File exists.
    FAULT = 21, // Bad address.
    FBIG = 22, // File too large.
    HOSTUNREACH = 23, // Host is unreachable.
    IDRM = 24, // Identifier removed.
    ILSEQ = 25, // Illegal byte sequence.
    INPROGRESS = 26, // Operation in progress.
    INTR = 27, // Interrupted function.
    INVAL = 28, // Invalid argument.
    IO = 29, // I/O error.
    ISCONN = 30, // Socket is connected.
    ISDIR = 31, // Is a directory.
    LOOP = 32, // Too many levels of symbolic links.
    MFILE = 33, // File descriptor value too large.
    MLINK = 34, // Too many links.
    MSGSIZE = 35, // Message too large.
    MULTIHOP = 36, // Reserved.
    NAMETOOLONG = 37, // Filename too long.
    NETDOWN = 38, // Network is down.
    NETRESET = 39, // Connection aborted by network.
    NETUNREACH = 40, // Network unreachable.
    NFILE = 41, // Too many files open in system.
    NOBUFS = 42, // No buffer space available.
    NODEV = 43, // No such device.
    NOENT = 44, // No such file or directory.
    NOEXEC = 45, // Executable file format error.
    NOLCK = 46, // No locks available.
    NOLINK = 47, // Reserved.
    NOMEM = 48, // Not enough space.
    NOMSG = 49, // No message of the desired type.
    NOPROTOOPT = 50, // Protocol not available.
    NOSPC = 51, // No space left on device.
    NOSYS = 52, // Function not supported.
    NOTCONN = 53, // The socket is not connected.
    NOTDIR = 54, // Not a directory or a symbolic link to a directory.
    NOTEMPTY = 55, // Directory not empty.
    NOTRECOVERABLE = 56, // State not recoverable.
    NOTSOCK = 57, // Not a socket.
    NOTSUP = 58, // Not supported, or operation not supported on socket.
    NOTTY = 59, // Inappropriate I/O control operation.
    NXIO = 60, // No such device or address.
    OVERFLOW = 61, // Value too large to be stored in data type.
    OWNERDEAD = 62, // Previous owner died.
    PERM = 63, // Operation not permitted.
    PIPE = 64, // Broken pipe.
    PROTO = 65, // Protocol error.
    PROTONOSUPPORT = 66, // Protocol not supported.
    PROTOTYPE = 67, // Protocol wrong type for socket.
    RANGE = 68, // Result too large.
    ROFS = 69, // Read-only file system.
    SPIPE = 70, // Invalid seek.
    SRCH = 71, // No such process.
    STALE = 72, // Reserved.
    TIMEDOUT = 73, // Connection timed out.
    TXTBSY = 74, // Text file busy.
    XDEV = 75, // Cross-device link.
    NOTCAPABLE = 76, // Extension: Capabilities insufficient.

    fn translateError(err: anyerror) Errno {
        return switch (err) {
            error.OutOfMemory => .NOMEM,
            error.AccessDenied => .ACCES,
            error.FileTooBig => .FBIG,
            error.IsDir => .ISDIR,
            error.SymLinkLoop => .LOOP,
            error.ProcessFdQuotaExceeded => .MFILE,
            error.NameTooLong => .NAMETOOLONG,
            error.SystemFdQuotaExceeded => .NFILE,
            error.NoDevice => .NODEV,
            error.FileNotFound => .NOENT,
            error.SystemResources => .NOMEM,
            error.NoSpaceLeft => .NOSPC,
            error.NotDir => .NOTDIR,
            error.PathAlreadyExists => .EXIST,
            error.DeviceBusy => .BUSY,
            error.FileLocksNotSupported => .NOTSUP,
            error.WouldBlock => .AGAIN,
            error.FileBusy => .TXTBSY,
            error.Unseekable => .SPIPE,
            error.DirNotEmpty => .NOTEMPTY,
            error.InputOutput => .IO,
            error.DiskQuota => .DQUOT,
            else => .INVAL,
        };
    }
};

const WasiLookupFlags = packed struct {
    symlink_follow: bool,
};

const WasiOpenFlags = packed struct {
    creat: bool,
    directory: bool,
    excl: bool,
    trunc: bool,
};

const WasiRights = packed struct {
    fd_datasync: bool,
    fd_read: bool,
    fd_seek: bool,
    fd_fdstat_set_flags: bool,
    fd_sync: bool,
    fd_tell: bool,
    fd_write: bool,
    fd_advise: bool,
    fd_allocate: bool,
    path_create_directory: bool,
    path_create_file: bool,
    path_link_source: bool,
    path_link_target: bool,
    path_open: bool,
    fd_readdir: bool,
    path_readlink: bool,
    path_rename_source: bool,
    path_rename_target: bool,
    path_filestat_get: bool,
    path_filestat_set_size: bool,
    path_filestat_set_times: bool,
    fd_filestat_get: bool,
    fd_filestat_set_size: bool,
    fd_filestat_set_times: bool,
    path_symlink: bool,
    path_remove_directory: bool,
    path_unlink_file: bool,
    poll_fd_readwrite: bool,
    sock_shutdown: bool,
    sock_accept: bool,
};

const WasiFdFlags = packed struct {
    append: bool,
    dsync: bool,
    nonblock: bool,
    rsync: bool,
    sync: bool,
};

const Whence = enum(u8) {
    Set,
    Cur,
    End,

    fn fromInt(int: i32) ?Whence {
        return switch (int) {
            0 => .Set,
            1 => .Cur,
            2 => .End,
            else => null,
        };
    }
};

const WindowsApi = struct {
    const windows = std.os.windows;

    const BOOL = windows.BOOL;
    const DWORD = windows.DWORD;
    const WINAPI = windows.WINAPI;
    const HANDLE = windows.HANDLE;
    const FILETIME = windows.FILETIME;

    const CLOCK = struct {
        const REALTIME = 0;
        const MONOTONIC = 1;
        const PROCESS_CPUTIME_ID = 2;
        const THREAD_CPUTIME_ID = 3;
    };

    extern "kernel32" fn GetSystemTimeAdjustment(timeAdjustment: *DWORD, timeIncrement: *DWORD, timeAdjustmentDisabled: *BOOL) callconv(WINAPI) BOOL;
    extern "kernel32" fn GetThreadTimes(in_hProcess: HANDLE, creationTime: *FILETIME, exitTime: *FILETIME, kernelTime: *FILETIME, userTime: *FILETIME) callconv(WINAPI) BOOL;
    const GetCurrentProcess = std.os.windows.kernel32.GetCurrentProcess;
};

const FD_WASI_INVALID = std.math.maxInt(u32);
const FD_OS_INVALID = switch (builtin.os.tag) {
    .windows => std.os.windows.INVALID_HANDLE_VALUE,
    else => -1,
};

const Helpers = struct {
    fn signedCast(comptime T: type, value: anytype, errno: *Errno) T {
        if (value >= 0) {
            return @intCast(T, value);
        }
        errno.* = Errno.INVAL;
        return 0;
    }

    fn writeIntToMemory(comptime T: type, value: T, offset: usize, module: *ModuleInstance, errno: *Errno) void {
        if (module.memoryWriteInt(T, value, offset) == false) {
            errno.* = Errno.INVAL;
        }
    }

    fn stringsSizesGet(module: *ModuleInstance, strings: [][]const u8, params: []const Val, returns: []Val) void {
        const strings_count: u32 = @intCast(u32, strings.len);
        var strings_length: u32 = 0;
        for (strings) |string| {
            strings_length += @intCast(u32, string.len) + 1; // +1 for required null terminator of each string
        }

        var errno = Errno.SUCCESS;

        const dest_string_count = Helpers.signedCast(u32, params[0].I32, &errno);
        const dest_string_length = Helpers.signedCast(u32, params[1].I32, &errno);

        if (errno == .SUCCESS) {
            writeIntToMemory(u32, strings_count, dest_string_count, module, &errno);
            writeIntToMemory(u32, strings_length, dest_string_length, module, &errno);
        }

        returns[0] = Val{ .I32 = @enumToInt(errno) };
    }

    fn stringsGet(module: *ModuleInstance, strings: [][]const u8, params: []const Val, returns: []Val) void {
        var errno = Errno.SUCCESS;

        const dest_string_ptrs_begin = Helpers.signedCast(u32, params[0].I32, &errno);
        const dest_string_mem_begin = Helpers.signedCast(u32, params[1].I32, &errno);

        if (errno == .SUCCESS) {
            var dest_string_ptrs: u32 = dest_string_ptrs_begin;
            var dest_string_strings: u32 = dest_string_mem_begin;

            for (strings) |string| {
                writeIntToMemory(u32, dest_string_strings, dest_string_ptrs, module, &errno);

                var mem: []u8 = module.memorySlice(dest_string_strings, string.len + 1);
                std.mem.copy(u8, mem[0..string.len], string);
                mem[string.len] = 0; // null terminator

                dest_string_ptrs += @sizeOf(u32);
                dest_string_strings += @intCast(u32, string.len + 1);
            }
        }

        returns[0] = Val{ .I32 = @enumToInt(errno) };
    }

    fn convertClockId(wasi_clockid: i32, errno: *Errno) i32 {
        return switch (wasi_clockid) {
            std.os.wasi.CLOCK.REALTIME => if (builtin.os.tag != .windows) std.os.system.CLOCK.REALTIME else WindowsApi.CLOCK.REALTIME,
            std.os.wasi.CLOCK.MONOTONIC => if (builtin.os.tag != .windows) std.os.system.CLOCK.MONOTONIC else WindowsApi.CLOCK.MONOTONIC,
            std.os.wasi.CLOCK.PROCESS_CPUTIME_ID => if (builtin.os.tag != .windows) std.os.system.CLOCK.PROCESS_CPUTIME_ID else WindowsApi.CLOCK.PROCESS_CPUTIME_ID,
            std.os.wasi.CLOCK.THREAD_CPUTIME_ID => if (builtin.os.tag != .windows) std.os.system.CLOCK.THREAD_CPUTIME_ID else WindowsApi.CLOCK.THREAD_CPUTIME_ID,
            else => {
                errno.* = Errno.INVAL;
                return 0;
            },
        };
    }

    fn filetimeToU64(ft: std.os.windows.FILETIME) u64 {
        const v: u64 = (@intCast(u64, ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
        return v;
    }

    fn decodeLookupFlags(value: i32) WasiLookupFlags {
        return WasiLookupFlags{
            .symlink_follow = (value & 0x01),
        };
    }

    fn decodeOpenFlags(value: i32) WasiOpenFlags {
        return WasiOpenFlags{
            .creat = (value & 0x01) != 0,
            .directory = (value & 0x02) != 0,
            .excl = (value & 0x04) != 0,
            .trunc = (value & 0x08) != 0,
        };
    }

    fn decodeRights(value: i64) WasiRights {
        return WasiRights{
            .fd_datasync = (value & 0x0001) != 0,
            .fd_read = (value & 0x0002) != 0,
            .fd_seek = (value & 0x0004) != 0,
            .fd_fdstat_set_flags = (value & 0x0008) != 0,

            .fd_sync = (value & 0x0010) != 0,
            .fd_tell = (value & 0x0020) != 0,
            .fd_write = (value & 0x0040) != 0,
            .fd_advise = (value & 0x0080) != 0,

            .fd_allocate = (value & 0x0100) != 0,
            .path_create_directory = (value & 0x0200) != 0,
            .path_create_file = (value & 0x0400) != 0,
            .path_link_source = (value & 0x0800) != 0,

            .path_link_target = (value & 0x1000) != 0,
            .path_open = (value & 0x2000) != 0,
            .fd_readdir = (value & 0x4000) != 0,
            .path_readlink = (value & 0x8000) != 0,

            .path_rename_source = (value & 0x10000) != 0,
            .path_rename_target = (value & 0x20000) != 0,
            .path_filestat_get = (value & 0x40000) != 0,
            .path_filestat_set_size = (value & 0x80000) != 0,

            .path_filestat_set_times = (value & 0x100000) != 0,
            .fd_filestat_get = (value & 0x200000) != 0,
            .fd_filestat_set_size = (value & 0x400000) != 0,
            .fd_filestat_set_times = (value & 0x800000) != 0,

            .path_symlink = (value & 0x1000000) != 0,
            .path_remove_directory = (value & 0x2000000) != 0,
            .path_unlink_file = (value & 0x4000000) != 0,
            .poll_fd_readwrite = (value & 0x8000000) != 0,

            .sock_shutdown = (value & 0x10000000) != 0,
            .sock_accept = (value & 0x20000000) != 0,
        };
    }

    fn decodeFdFlags(value: i32) WasiFdFlags {
        return WasiFdFlags{
            .append = (value & 0x01) != 0,
            .dsync = (value & 0x02) != 0,
            .nonblock = (value & 0x04) != 0,
            .rsync = (value & 0x08) != 0,
            .sync = (value & 0x10) != 0,
        };
    }

    fn fdstat_get_windows(fd: std.os.fd_t, errno: *Errno) std.os.wasi.fdstat_t {
        var stat_wasi = std.os.wasi.fdstat_t{
            .fs_filetype = std.os.wasi.filetype_t.REGULAR_FILE,
            .fs_flags = 0,
            .fs_rights_base = std.os.wasi.RIGHT.ALL,
            .fs_rights_inheriting = std.os.wasi.RIGHT.ALL,
        };

        if (std.os.windows.GetFileInformationByHandle(fd)) |info| {
            const attributes = info.dwFileAttributes;

            if (attributes & std.os.windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
                stat_wasi.fs_filetype = std.os.wasi.filetype_t.DIRECTORY;
            } else if (attributes & std.os.windows.FILE_ATTRIBUTE_REPARSE_POINT != 0) {
                stat_wasi.fs_filetype = std.os.wasi.filetype_t.SYMBOLIC_LINK;
            }

            if (attributes & std.os.windows.FILE_ATTRIBUTE_READONLY != 0) {
                stat_wasi.fs_rights_base &= ~std.os.wasi.RIGHT.FD_WRITE;
            }
        } else |err| {
            errno.* = Errno.translateError(err);
        }

        return stat_wasi;
    }

    fn fdstat_get_posix(fd: std.os.fd_t, errno: *Errno) std.os.wasi.fdstat_t {
        var stat_wasi = std.os.wasi.fdstat_t{
            .fs_filetype = std.os.wasi.filetype_t.UNKNOWN,
            .fs_flags = 0,
            .fs_rights_base = std.os.wasi.RIGHT.ALL,
            .fs_rights_inheriting = std.os.wasi.RIGHT.ALL,
        };

        if (std.os.fcntl(fd, std.os.F.GETFL, 0)) |fd_flags| {
            if (std.os.fstat(fd)) |fd_stat| {

                // filetype
                if (std.os.S.ISREG(fd_stat.mode)) {
                    stat_wasi.fs_filetype = std.os.wasi.filetype_t.REGULAR_FILE;
                } else if (std.os.S.ISDIR(fd_stat.mode)) {
                    stat_wasi.fs_filetype = std.os.wasi.filetype_t.DIRECTORY;
                } else if (std.os.S.ISCHR(fd_stat.mode)) {
                    stat_wasi.fs_filetype = std.os.wasi.filetype_t.CHARACTER_DEVICE;
                } else if (std.os.S.ISBLK(fd_stat.mode)) {
                    stat_wasi.fs_filetype = std.os.wasi.filetype_t.BLOCK_DEVICE;
                } else if (std.os.S.ISLNK(fd_stat.mode)) {
                    stat_wasi.fs_filetype = std.os.wasi.filetype_t.SYMBOLIC_LINK;
                }
                // if (std.os.S.ISSOCK(fd_stat.mode)) {
                //     stat_wasi.fs_filetype = std.os.wasi.filetype_t.SOCKET_STREAM; // not sure if this is SOCKET_STREAM or SOCKET_DGRAM
                // }

                // flags
                if (fd_flags & std.os.O.APPEND) {
                    stat_wasi.fs_flags |= std.os.wasi.FDFLAG.APPEND;
                }
                if (fd_flags & std.os.O.DSYNC) {
                    stat_wasi.fs_flags |= std.os.wasi.FDFLAG.DSYNC;
                }
                if (fd_flags & std.os.O.NONBLOCK) {
                    stat_wasi.fs_flags |= std.os.wasi.FDFLAG.NONBLOCK;
                }
                if (fd_flags & std.os.O.RSYNC) {
                    stat_wasi.fs_flags |= std.os.wasi.FDFLAG.RSYNC;
                }
                if (fd_flags & std.os.O.SYNC) {
                    stat_wasi.fs_flags |= std.os.wasi.FDFLAG.SYNC;
                }

                // rights
                if (fd_flags & std.os.O.RDWR) {
                    // noop since all rights includes this by default
                } else if (fd_flags & std.os.O.RDONLY) {
                    stat_wasi.fs_rights_base &= ~std.os.wasi.RIGHT.FD_WRITE;
                } else if (fd_flags & std.os.O.WRONLY) {
                    stat_wasi.fs_rights_base &= ~std.os.wasi.RIGHT.FD_READ;
                }
            } else |err| {
                errno = Errno.translateError(err);
            }
        } else |err| {
            errno = Errno.translateError(err);
        }

        return stat_wasi;
    }

    fn initIovecs(comptime iov_type: type, stack_iov: []iov_type, errno: *Errno, module: *ModuleInstance, iovec_array_begin: u32, iovec_array_count: u32) ?[]iov_type {
        if (iovec_array_count < stack_iov.len) {
            const iov = stack_iov[0..iovec_array_count];
            const iovec_array_bytes_length = @sizeOf(u32) * 2 * iovec_array_count;
            const iovec_mem: []const u8 = module.memorySlice(iovec_array_begin, iovec_array_bytes_length);
            var stream = std.io.fixedBufferStream(iovec_mem);
            var reader = stream.reader();

            for (iov) |*iovec| {
                const iov_base: u32 = reader.readIntLittle(u32) catch {
                    errno.* = Errno.INVAL;
                    return null;
                };

                const iov_len: u32 = reader.readIntLittle(u32) catch {
                    errno.* = Errno.INVAL;
                    return null;
                };

                const mem: []u8 = module.memorySlice(iov_base, iov_len);
                iovec.iov_base = mem.ptr;
                iovec.iov_len = mem.len;
            }

            return iov;
        } else {
            errno.* = Errno.TOOBIG;
        }

        return null;
    }
};

fn wasi_proc_exit(_: ?*anyopaque, _: *ModuleInstance, params: []const Val, _: []Val) void {
    const raw_exit_code = params[0].I32;

    if (raw_exit_code >= 0 and raw_exit_code < std.math.maxInt(u8)) {
        const exit_code = @intCast(u8, raw_exit_code);
        std.os.exit(exit_code);
    } else {
        std.os.exit(1);
    }
}

fn wasi_args_sizes_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var context = WasiContext.fromUserdata(userdata);
    Helpers.stringsSizesGet(module, context.argv, params, returns);
}

fn wasi_args_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var context = WasiContext.fromUserdata(userdata);
    Helpers.stringsGet(module, context.argv, params, returns);
}

fn wasi_environ_sizes_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var context = WasiContext.fromUserdata(userdata);
    Helpers.stringsSizesGet(module, context.env, params, returns);
}

fn wasi_environ_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var context = WasiContext.fromUserdata(userdata);
    Helpers.stringsGet(module, context.env, params, returns);
}

fn wasi_clock_res_get(_: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const system_clockid: i32 = Helpers.convertClockId(params[0].I32, &errno);
    const timestamp_mem_begin = Helpers.signedCast(u32, params[1].I32, &errno);

    if (errno == .SUCCESS) {
        var freqency_ns: u64 = 0;
        if (builtin.os.tag == .windows) {
            // Follow the mingw pattern since clock_getres() isn't linked in libc for windows
            if (system_clockid == std.os.wasi.CLOCK.REALTIME or system_clockid == std.os.wasi.CLOCK.MONOTONIC) {
                const ns_per_second: u64 = 1000000000;
                const tick_frequency: u64 = std.os.windows.QueryPerformanceFrequency();
                freqency_ns = (ns_per_second + (tick_frequency >> 1)) / tick_frequency;
                if (freqency_ns < 1) {
                    freqency_ns = 1;
                }
            } else {
                var timeAdjustment: WindowsApi.DWORD = undefined;
                var timeIncrement: WindowsApi.DWORD = undefined;
                var timeAdjustmentDisabled: WindowsApi.BOOL = undefined;
                if (WindowsApi.GetSystemTimeAdjustment(&timeAdjustment, &timeIncrement, &timeAdjustmentDisabled) == std.os.windows.TRUE) {
                    freqency_ns = timeIncrement * 100;
                } else {
                    errno = Errno.INVAL;
                }
            }
        } else {
            var ts: std.os.system.timespec = undefined;
            if (std.os.clock_getres(system_clockid, &ts)) {
                freqency_ns = @intCast(u64, ts.tv_nsec);
            } else |_| {
                errno = Errno.INVAL;
            }
        }

        Helpers.writeIntToMemory(u64, freqency_ns, timestamp_mem_begin, module, &errno);
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_clock_time_get(_: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const system_clockid: i32 = Helpers.convertClockId(params[0].I32, &errno);
    //const precision = params[1].I64; // unused
    const timestamp_mem_begin = Helpers.signedCast(u32, params[2].I32, &errno);

    if (errno == .SUCCESS) {
        const ns_per_second = 1000000000;
        var timestamp_ns: u64 = 0;

        if (builtin.os.tag == .windows) {
            switch (system_clockid) {
                std.os.wasi.CLOCK.REALTIME => {
                    var ft: WindowsApi.FILETIME = undefined;
                    std.os.windows.kernel32.GetSystemTimeAsFileTime(&ft);

                    // Windows epoch starts on Jan 1, 1601. Unix epoch starts on Jan 1, 1970.
                    const win_epoch_to_unix_epoch_100ns: u64 = 116444736000000000;
                    const timestamp_windows_100ns: u64 = Helpers.filetimeToU64(ft);

                    const timestamp_100ns: u64 = timestamp_windows_100ns - win_epoch_to_unix_epoch_100ns;
                    timestamp_ns = timestamp_100ns * 100;
                },
                std.os.wasi.CLOCK.MONOTONIC => {
                    const ticks: u64 = std.os.windows.QueryPerformanceCounter();
                    const ticks_per_second: u64 = std.os.windows.QueryPerformanceFrequency();

                    // break up into 2 calculations to avoid overflow
                    const timestamp_secs_part: u64 = ticks / ticks_per_second;
                    const timestamp_ns_part: u64 = ((ticks % ticks_per_second) * ns_per_second + (ticks_per_second >> 1)) / ticks_per_second;

                    timestamp_ns = timestamp_secs_part + timestamp_ns_part;
                },
                std.os.wasi.CLOCK.PROCESS_CPUTIME_ID => {
                    var createTime: WindowsApi.FILETIME = undefined;
                    var exitTime: WindowsApi.FILETIME = undefined;
                    var kernelTime: WindowsApi.FILETIME = undefined;
                    var userTime: WindowsApi.FILETIME = undefined;
                    if (std.os.windows.kernel32.GetProcessTimes(WindowsApi.GetCurrentProcess(), &createTime, &exitTime, &kernelTime, &userTime) == std.os.windows.TRUE) {
                        const timestamp_100ns: u64 = Helpers.filetimeToU64(kernelTime) + Helpers.filetimeToU64(userTime);
                        timestamp_ns = timestamp_100ns * 100;
                    } else {
                        errno = Errno.INVAL;
                    }
                },
                std.os.wasi.CLOCK.THREAD_CPUTIME_ID => {
                    var createTime: WindowsApi.FILETIME = undefined;
                    var exitTime: WindowsApi.FILETIME = undefined;
                    var kernelTime: WindowsApi.FILETIME = undefined;
                    var userTime: WindowsApi.FILETIME = undefined;
                    if (WindowsApi.GetThreadTimes(WindowsApi.GetCurrentProcess(), &createTime, &exitTime, &kernelTime, &userTime) == std.os.windows.TRUE) {
                        const timestamp_100ns: u64 = Helpers.filetimeToU64(kernelTime) + Helpers.filetimeToU64(userTime);
                        timestamp_ns = timestamp_100ns * 100;
                    } else {
                        errno = Errno.INVAL;
                    }
                },
                else => unreachable,
            }
        } else {
            var ts: std.os.system.timespec = undefined;
            if (std.os.clock_gettime(system_clockid, &ts)) {
                const sec_part = @intCast(u64, ts.tv_sec);
                const nsec_part = @intCast(u64, ts.tv_nsec);
                timestamp_ns = (sec_part * ns_per_second) + nsec_part;
            } else |_| {
                errno = Errno.INVAL;
            }
        }

        Helpers.writeIntToMemory(u64, timestamp_ns, timestamp_mem_begin, module, &errno);
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_datasync(userdata: ?*anyopaque, _: *ModuleInstance, params: []const Val, returns: []Val) void {
    const context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);

    var errno = Errno.SUCCESS;

    if (context.fdLookup(fd_wasi)) |fd_os| {
        std.os.fdatasync(fd_os) catch |err| {
            errno = Errno.translateError(err);
        };
    } else {
        errno = Errno.BADF;
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_fdstat_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const fdstat_mem_offset = Helpers.signedCast(u32, params[1].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi)) |fd_os| {
            const stat: std.os.wasi.fdstat_t = if (builtin.os.tag == .windows) Helpers.fdstat_get_windows(fd_os, &errno) else Helpers.fdstat_get_posix(fd_os, &errno);

            if (errno == .SUCCESS) {
                Helpers.writeIntToMemory(u8, @enumToInt(stat.fs_filetype), fdstat_mem_offset + 0, module, &errno);
                Helpers.writeIntToMemory(u16, stat.fs_flags, fdstat_mem_offset + 2, module, &errno);
                Helpers.writeIntToMemory(u64, stat.fs_rights_base, fdstat_mem_offset + 8, module, &errno);
                Helpers.writeIntToMemory(u64, stat.fs_rights_inheriting, fdstat_mem_offset + 16, module, &errno);
            }
        } else {
            errno = .BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_fdstat_set_flags(_: ?*anyopaque, _: *ModuleInstance, params: []const Val, returns: []Val) void {
    std.debug.assert(params.len == 2);
    std.debug.assert(std.meta.activeTag(params[0]) == .I32);
    std.debug.assert(std.meta.activeTag(params[1]) == .I32);
    std.debug.assert(returns.len == 1);

    std.debug.print("called wasi_fd_fdstat_set_flags\n", .{});

    // TODO
    var errno = Errno.SUCCESS;
    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_prestat_get(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const prestat_mem_offset = Helpers.signedCast(u32, params[1].I32, &errno);

    if (errno == .SUCCESS) {
        const fd_os: ?std.os.fd_t = context.fdLookup(fd_wasi);
        if (fd_wasi >= 3 and fd_os != null) { // std handles are 0, 1, 2 so skip those
            var name_buffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
            const path: []const u8 = std.os.getFdPath(fd_os.?, &name_buffer) catch unreachable;
            const pr_name_len: u32 = @intCast(u32, path.len + 1); // allow space for null terminator

            Helpers.writeIntToMemory(u32, std.os.wasi.PREOPENTYPE_DIR, prestat_mem_offset + 0, module, &errno);
            Helpers.writeIntToMemory(u32, pr_name_len, prestat_mem_offset + @sizeOf(u32), module, &errno);
        } else {
            errno = Errno.BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_prestat_dir_name(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const context = WasiContext.fromUserdata(userdata);
    const fd_dir_wasi = Helpers.signedCast(u32, params[0].I32, &errno);
    const path_mem_offset = Helpers.signedCast(u32, params[1].I32, &errno);
    const path_mem_length = Helpers.signedCast(u32, params[2].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdDirPath(fd_dir_wasi)) |path_source| {
            var path_dest: []u8 = module.memorySlice(path_mem_offset, path_mem_length);
            std.mem.copy(u8, path_dest, path_source);
            const null_offset: usize = std.math.min(path_source.len, path_dest.len);
            path_dest[null_offset] = 0; // null terminator
        } else {
            errno = Errno.BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_read(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const iovec_array_begin = Helpers.signedCast(u32, params[1].I32, &errno);
    const iovec_array_count = Helpers.signedCast(u32, params[2].I32, &errno);
    const bytes_read_out_offset = Helpers.signedCast(u32, params[3].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi)) |fd_os| {
            var stack_iov = [_]std.os.iovec{undefined} ** 1024;
            if (Helpers.initIovecs(std.os.iovec, &stack_iov, &errno, module, iovec_array_begin, iovec_array_count)) |iov| {
                if (std.os.readv(fd_os, iov)) |read_bytes| {
                    if (read_bytes <= std.math.maxInt(u32)) {
                        Helpers.writeIntToMemory(u32, @intCast(u32, read_bytes), bytes_read_out_offset, module, &errno);
                    } else {
                        errno = Errno.TOOBIG;
                    }
                } else |err| {
                    errno = Errno.translateError(err);
                }
            }
        } else {
            errno = Errno.BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_pread(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const iovec_array_begin = Helpers.signedCast(u32, params[1].I32, &errno);
    const iovec_array_count = Helpers.signedCast(u32, params[2].I32, &errno);
    const read_offset = @bitCast(u64, params[3].I64);
    const bytes_read_out_offset = Helpers.signedCast(u32, params[4].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi)) |fd_os| {
            var stack_iov = [_]std.os.iovec{undefined} ** 1024;
            if (Helpers.initIovecs(std.os.iovec, &stack_iov, &errno, module, iovec_array_begin, iovec_array_count)) |iov| {
                if (std.os.preadv(fd_os, iov, read_offset)) |read_bytes| {
                    if (read_bytes <= std.math.maxInt(u32)) {
                        Helpers.writeIntToMemory(u32, @intCast(u32, read_bytes), bytes_read_out_offset, module, &errno);
                    } else {
                        errno = Errno.TOOBIG;
                    }
                } else |err| {
                    errno = Errno.translateError(err);
                }
            }
        } else {
            errno = Errno.BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_close(userdata: ?*anyopaque, _: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);

    const fd_wasi = @bitCast(u32, params[0].I32);

    if (errno == .SUCCESS) {
        if (context.fdRemove(fd_wasi)) |fd_os| {
            std.os.close(fd_os);
        } else {
            errno = Errno.BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_seek(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const offset = params[1].I64;
    const whence_raw = params[2].I32;
    const filepos_out_offset = Helpers.signedCast(u32, params[3].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi)) |fd_os| {
            if (Whence.fromInt(whence_raw)) |whence| {
                switch (whence) {
                    .Set => {
                        if (offset >= 0) {
                            const offset_unsigned = @intCast(u64, offset);
                            std.os.lseek_SET(fd_os, offset_unsigned) catch |err| {
                                errno = Errno.translateError(err);
                            };
                        }
                    },
                    .Cur => {
                        std.os.lseek_CUR(fd_os, offset) catch |err| {
                            errno = Errno.translateError(err);
                        };
                    },
                    .End => {
                        std.os.lseek_END(fd_os, offset) catch |err| {
                            errno = Errno.translateError(err);
                        };
                    },
                }

                if (std.os.lseek_CUR_get(fd_os)) |filepos| {
                    Helpers.writeIntToMemory(u64, filepos, filepos_out_offset, module, &errno);
                } else |err| {
                    errno = Errno.translateError(err);
                }
            } else {
                errno = Errno.INVAL;
            }
        } else {
            errno = Errno.BADF;
        }
    }
    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_tell(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const context = WasiContext.fromUserdata(userdata);

    const fd_wasi = @bitCast(u32, params[0].I32);
    const filepos_out_offset = Helpers.signedCast(u32, params[1].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi)) |fd_os| {
            if (std.os.lseek_CUR_get(fd_os)) |filepos| {
                Helpers.writeIntToMemory(u64, filepos, filepos_out_offset, module, &errno);
            } else |err| {
                errno = Errno.translateError(err);
            }
        } else {
            errno = Errno.BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_write(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const iovec_array_begin = Helpers.signedCast(u32, params[1].I32, &errno);
    const iovec_array_count = Helpers.signedCast(u32, params[2].I32, &errno);
    const bytes_written_out_offset = Helpers.signedCast(u32, params[3].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi)) |fd_os| {
            var stack_iov = [_]std.os.iovec_const{undefined} ** 1024;
            if (Helpers.initIovecs(std.os.iovec_const, &stack_iov, &errno, module, iovec_array_begin, iovec_array_count)) |iov| {
                if (std.os.writev(fd_os, iov)) |written_bytes| {
                    Helpers.writeIntToMemory(u32, @intCast(u32, written_bytes), bytes_written_out_offset, module, &errno);
                } else |err| {
                    errno = Errno.translateError(err);
                }
            }
        } else {
            errno = Errno.BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_fd_pwrite(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_wasi = @bitCast(u32, params[0].I32);
    const iovec_array_begin = Helpers.signedCast(u32, params[1].I32, &errno);
    const iovec_array_count = Helpers.signedCast(u32, params[2].I32, &errno);
    const write_offset = Helpers.signedCast(u64, params[3].I64, &errno);
    const bytes_written_out_offset = Helpers.signedCast(u32, params[4].I32, &errno);

    if (errno == .SUCCESS) {
        if (context.fdLookup(fd_wasi)) |fd_os| {
            var stack_iov = [_]std.os.iovec_const{undefined} ** 1024;
            if (Helpers.initIovecs(std.os.iovec_const, &stack_iov, &errno, module, iovec_array_begin, iovec_array_count)) |iov| {
                if (std.os.pwritev(fd_os, iov, write_offset)) |written_bytes| {
                    Helpers.writeIntToMemory(u32, @intCast(u32, written_bytes), bytes_written_out_offset, module, &errno);
                } else |err| {
                    errno = Errno.translateError(err);
                }
            }
        } else {
            errno = Errno.BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_path_open(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);
    const fd_dir_wasi: u32 = Helpers.signedCast(u32, params[0].I32, &errno);
    // const dirflags: WasiLookupFlags = Helpers.decodeLookupFlags(params[1].I32);
    const path_mem_offset: u32 = Helpers.signedCast(u32, params[2].I32, &errno);
    const path_mem_length: u32 = Helpers.signedCast(u32, params[3].I32, &errno);
    const openflags: WasiOpenFlags = Helpers.decodeOpenFlags(params[4].I32);
    const rights_base: WasiRights = Helpers.decodeRights(params[5].I64);
    // const rights_inheriting: WasiRights = Helpers.decodeRights(params[6].I64);
    const fdflags: WasiFdFlags = Helpers.decodeFdFlags(params[7].I32);
    const fd_out_mem_offset = Helpers.signedCast(u32, params[8].I32, &errno);

    if (errno == .SUCCESS) {
        const path: []const u8 = module.memorySlice(path_mem_offset, path_mem_length);

        if (context.fdLookup(fd_dir_wasi)) |fd_dir| {
            if (context.hasPathAccess(fd_dir, path)) {
                var flags: u32 = 0;
                if (openflags.creat) {
                    flags |= std.os.O.CREAT;
                }
                if (openflags.directory) {
                    flags |= std.os.O.DIRECTORY;
                }
                if (openflags.excl) {
                    flags |= std.os.O.EXCL;
                }
                if (openflags.trunc) {
                    flags |= std.os.O.TRUNC;
                }

                if (fdflags.append) {
                    flags |= std.os.O.APPEND;
                }
                if (fdflags.dsync) {
                    flags |= std.os.O.DSYNC;
                }
                if (fdflags.nonblock) {
                    flags |= std.os.O.NONBLOCK;
                }
                if (fdflags.rsync) {
                    flags |= std.os.O.RSYNC;
                }
                if (fdflags.sync) {
                    flags |= std.os.O.SYNC;
                }

                if (rights_base.fd_read and rights_base.fd_write) {
                    flags |= std.os.O.RDWR;
                } else if (rights_base.fd_read) {
                    flags |= std.os.O.RDONLY;
                } else if (rights_base.fd_write) {
                    flags |= std.os.O.WRONLY;
                }

                // 644 means rw perm owner, r perm group, r perm others
                var mode: std.os.mode_t = if (builtin.os.tag != .windows) 644 else undefined;

                if (std.os.openat(fd_dir, path, flags, mode)) |fd_opened| {
                    if (context.fdAdd(fd_opened)) |fd_opened_wasi| {
                        Helpers.writeIntToMemory(u32, fd_opened_wasi, fd_out_mem_offset, module, &errno);
                    } else |err| {
                        errno = Errno.translateError(err);
                    }
                } else |err| {
                    errno = Errno.translateError(err);
                }
            } else {
                errno = Errno.NOTCAPABLE;
            }
        } else {
            errno = Errno.BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_path_remove_directory(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);

    const fd_dir_wasi = Helpers.signedCast(u32, params[0].I32, &errno);
    const path_mem_offset = Helpers.signedCast(u32, params[1].I32, &errno);
    const path_mem_length = Helpers.signedCast(u32, params[2].I32, &errno);

    if (errno == .SUCCESS) {
        const path: []const u8 = module.memorySlice(path_mem_offset, path_mem_length);
        if (context.fdLookup(fd_dir_wasi)) |fd_dir| {
            if (context.hasPathAccess(fd_dir, path)) {
                std.os.unlinkat(fd_dir, path, std.os.AT.REMOVEDIR) catch |err| {
                    errno = Errno.translateError(err);
                };
            } else {
                errno = Errno.NOTCAPABLE;
            }
        } else {
            errno = Errno.BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_path_unlink_file(userdata: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    var context = WasiContext.fromUserdata(userdata);

    const fd_dir_wasi = Helpers.signedCast(u32, params[0].I32, &errno);
    const path_mem_offset = Helpers.signedCast(u32, params[1].I32, &errno);
    const path_mem_length = Helpers.signedCast(u32, params[2].I32, &errno);

    if (errno == .SUCCESS) {
        const path: []const u8 = module.memorySlice(path_mem_offset, path_mem_length);
        if (context.fdLookup(fd_dir_wasi)) |fd_dir| {
            if (context.hasPathAccess(fd_dir, path)) {
                std.os.unlinkat(fd_dir, path, 0) catch |err| {
                    errno = Errno.translateError(err);
                };
            } else {
                errno = Errno.NOTCAPABLE;
            }
        } else {
            errno = Errno.BADF;
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

fn wasi_random_get(_: ?*anyopaque, module: *ModuleInstance, params: []const Val, returns: []Val) void {
    var errno = Errno.SUCCESS;

    const array_begin_offset: u32 = Helpers.signedCast(u32, params[0].I32, &errno);
    const array_length: u32 = Helpers.signedCast(u32, params[1].I32, &errno);

    if (errno == .SUCCESS) {
        if (array_length > 0) {
            var mem: []u8 = module.memorySlice(array_begin_offset, array_length);
            std.crypto.random.bytes(mem);
        }
    }

    returns[0] = Val{ .I32 = @enumToInt(errno) };
}

pub const WasiOpts = struct {
    argv: ?[][]const u8 = null,
    env: ?[][]const u8 = null,
    dirs: ?[][]const u8 = null,
};

pub fn initImports(opts: WasiOpts, allocator: std.mem.Allocator) WasiInitError!ModuleImports {
    var context: *WasiContext = try allocator.create(WasiContext);
    errdefer allocator.destroy(context);
    context.* = try WasiContext.init(&opts, allocator);
    errdefer context.deinit();

    var imports: ModuleImports = try ModuleImports.init("wasi_snapshot_preview1", null, context, allocator);

    const void_returns = &[0]ValType{};

    try imports.addHostFunction("args_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_args_get);
    try imports.addHostFunction("args_sizes_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_args_sizes_get);
    try imports.addHostFunction("clock_res_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_clock_res_get);
    try imports.addHostFunction("clock_time_get", &[_]ValType{ .I32, .I64, .I32 }, &[_]ValType{.I32}, wasi_clock_time_get);
    try imports.addHostFunction("environ_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_environ_get);
    try imports.addHostFunction("environ_sizes_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_environ_sizes_get);
    try imports.addHostFunction("fd_close", &[_]ValType{.I32}, &[_]ValType{.I32}, wasi_fd_close);
    try imports.addHostFunction("fd_datasync", &[_]ValType{.I32}, &[_]ValType{.I32}, wasi_fd_datasync);
    try imports.addHostFunction("fd_fdstat_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_fdstat_get);
    try imports.addHostFunction("fd_fdstat_set_flags", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_fdstat_set_flags);
    try imports.addHostFunction("fd_prestat_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_prestat_get);
    try imports.addHostFunction("fd_prestat_dir_name", &[_]ValType{ .I32, .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_prestat_dir_name);
    try imports.addHostFunction("fd_read", &[_]ValType{ .I32, .I32, .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_read);
    try imports.addHostFunction("fd_pread", &[_]ValType{ .I32, .I32, .I32, .I64, .I32 }, &[_]ValType{.I32}, wasi_fd_pread);
    try imports.addHostFunction("fd_seek", &[_]ValType{ .I32, .I64, .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_seek);
    try imports.addHostFunction("fd_tell", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_tell);
    try imports.addHostFunction("fd_write", &[_]ValType{ .I32, .I32, .I32, .I32 }, &[_]ValType{.I32}, wasi_fd_write);
    try imports.addHostFunction("fd_pwrite", &[_]ValType{ .I32, .I32, .I32, .I64, .I32 }, &[_]ValType{.I32}, wasi_fd_pwrite);
    try imports.addHostFunction("random_get", &[_]ValType{ .I32, .I32 }, &[_]ValType{.I32}, wasi_random_get);
    try imports.addHostFunction("path_open", &[_]ValType{ .I32, .I32, .I32, .I32, .I32, .I64, .I64, .I32, .I32 }, &[_]ValType{.I32}, wasi_path_open);
    try imports.addHostFunction("path_remove_directory", &[_]ValType{ .I32, .I32, .I32 }, &[_]ValType{.I32}, wasi_path_remove_directory);
    try imports.addHostFunction("path_unlink_file", &[_]ValType{ .I32, .I32, .I32 }, &[_]ValType{.I32}, wasi_path_unlink_file);
    try imports.addHostFunction("proc_exit", &[_]ValType{.I32}, void_returns, wasi_proc_exit);

    return imports;
}

pub fn deinitImports(imports: *ModuleImports) void {
    var context = WasiContext.fromUserdata(imports.userdata);
    context.deinit();
    imports.allocator.destroy(context);

    imports.deinit();
}
