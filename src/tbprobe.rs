use ::libc;
use libc::uint64_t;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn __assert_fail(
        __assertion: *const libc::c_char,
        __file: *const libc::c_char,
        __line: libc::c_uint,
        __function: *const libc::c_char,
    ) -> !;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn perror(__s: *const libc::c_char);
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn exit(_: libc::c_int) -> !;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
    fn strcpy(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strcat(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    fn pthread_mutex_destroy(__mutex: *mut pthread_mutex_t) -> libc::c_int;
    fn pthread_mutex_init(
        __mutex: *mut pthread_mutex_t,
        __mutexattr: *const pthread_mutexattr_t,
    ) -> libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn mmap(
        __addr: *mut libc::c_void,
        __len: size_t,
        __prot: libc::c_int,
        __flags: libc::c_int,
        __fd: libc::c_int,
        __offset: __off_t,
    ) -> *mut libc::c_void;
    fn munmap(__addr: *mut libc::c_void, __len: size_t) -> libc::c_int;
    fn fstat(__fd: libc::c_int, __buf: *mut stat) -> libc::c_int;
}
pub type __int8_t = libc::c_schar;
pub type __uint8_t = libc::c_uchar;
pub type __int16_t = libc::c_short;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __syscall_ulong_t = libc::c_ulong;
pub type int8_t = __int8_t;
pub type int16_t = __int16_t;
pub type int32_t = __int32_t;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
// pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type atomic_bool = bool;
pub type C2RustUnnamed = libc::c_uint;
pub const memory_order_release: C2RustUnnamed = 2;
pub const memory_order_acquire: C2RustUnnamed = 1;
pub const memory_order_relaxed: C2RustUnnamed = 0;
pub const PYRRHIC_PRIME_BPAWN: C2RustUnnamed_4 = 11695583624105689831;
pub const PYRRHIC_BPAWN: C2RustUnnamed_3 = 9;
pub const PYRRHIC_PRIME_BKNIGHT: C2RustUnnamed_4 = 13469005675588064321;
pub const PYRRHIC_BKNIGHT: C2RustUnnamed_3 = 10;
pub const PYRRHIC_PRIME_BBISHOP: C2RustUnnamed_4 = 15394650811035483107;
pub const PYRRHIC_BBISHOP: C2RustUnnamed_3 = 11;
pub const PYRRHIC_PRIME_BROOK: C2RustUnnamed_4 = 18264461213049635989;
pub const PYRRHIC_BROOK: C2RustUnnamed_3 = 12;
pub const PYRRHIC_PRIME_BQUEEN: C2RustUnnamed_4 = 15484752644942473553;
pub const PYRRHIC_BQUEEN: C2RustUnnamed_3 = 13;
pub const PYRRHIC_PRIME_WPAWN: C2RustUnnamed_4 = 17008651141875982339;
pub const PYRRHIC_WPAWN: C2RustUnnamed_3 = 1;
pub const PYRRHIC_PRIME_WKNIGHT: C2RustUnnamed_4 = 15202887380319082783;
pub const PYRRHIC_WKNIGHT: C2RustUnnamed_3 = 2;
pub const PYRRHIC_PRIME_WBISHOP: C2RustUnnamed_4 = 12311744257139811149;
pub const PYRRHIC_WBISHOP: C2RustUnnamed_3 = 3;
pub const PYRRHIC_PRIME_WROOK: C2RustUnnamed_4 = 10979190538029446137;
pub const PYRRHIC_WROOK: C2RustUnnamed_3 = 4;
pub const PYRRHIC_PRIME_WQUEEN: C2RustUnnamed_4 = 11811845319353239651;
pub const PYRRHIC_WQUEEN: C2RustUnnamed_3 = 5;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct BaseEntry {
    pub key: uint64_t,
    pub data: [*mut uint8_t; 3],
    pub mapping: [map_t; 3],
    pub ready: [atomic_bool; 3],
    pub num: uint8_t,
    pub symmetric: bool,
    pub hasPawns: bool,
    pub hasDtm: bool,
    pub hasDtz: bool,
    pub c2rust_unnamed: C2RustUnnamed_0,
    pub dtmLossOnly: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub kk_enc: bool,
    pub pawns: [uint8_t; 2],
}
pub type map_t = size_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PieceEntry {
    pub be: BaseEntry,
    pub ei: [EncInfo; 5],
    pub dtmMap: *mut uint16_t,
    pub dtmMapIdx: [[uint16_t; 2]; 2],
    pub dtzMap: *mut libc::c_void,
    pub dtzMapIdx: [uint16_t; 4],
    pub dtzFlags: uint8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EncInfo {
    pub precomp: *mut PairsData,
    pub factor: [size_t; 7],
    pub pieces: [uint8_t; 7],
    pub norm: [uint8_t; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PairsData {
    pub indexTable: *mut uint8_t,
    pub sizeTable: *mut uint16_t,
    pub data: *mut uint8_t,
    pub offset: *mut uint16_t,
    pub symLen: *mut uint8_t,
    pub symPat: *mut uint8_t,
    pub blockSize: uint8_t,
    pub idxBits: uint8_t,
    pub minLen: uint8_t,
    pub constValue: [uint8_t; 2],
    pub base: [uint64_t; 1],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PawnEntry {
    pub be: BaseEntry,
    pub ei: [EncInfo; 24],
    pub dtmMap: *mut uint16_t,
    pub dtmMapIdx: [[[uint16_t; 2]; 2]; 6],
    pub dtzMap: *mut libc::c_void,
    pub dtzMapIdx: [[uint16_t; 4]; 4],
    pub dtzFlags: [uint8_t; 4],
    pub dtmSwitched: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TbHashEntry {
    pub key: uint64_t,
    pub ptr: *mut BaseEntry,
}
pub const DTZ: C2RustUnnamed_1 = 2;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: libc::c_int,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atime: __time_t,
    pub st_atimensec: __syscall_ulong_t,
    pub st_mtime: __time_t,
    pub st_mtimensec: __syscall_ulong_t,
    pub st_ctime: __time_t,
    pub st_ctimensec: __syscall_ulong_t,
    pub __glibc_reserved: [__syscall_slong_t; 3],
}
pub const DTM: C2RustUnnamed_1 = 1;
pub const PYRRHIC_PAWN: C2RustUnnamed_3 = 1;
pub const PYRRHIC_KING: C2RustUnnamed_3 = 6;
pub const WDL: C2RustUnnamed_1 = 0;
pub const PYRRHIC_QUEEN: C2RustUnnamed_3 = 5;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutexattr_t {
    pub __size: [libc::c_char; 4],
    pub __align: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [libc::c_char; 40],
    pub __align: libc::c_long,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_mutex_s {
    pub __lock: libc::c_int,
    pub __count: libc::c_uint,
    pub __owner: libc::c_int,
    pub __nusers: libc::c_uint,
    pub __kind: libc::c_int,
    pub __spins: libc::c_short,
    pub __elision: libc::c_short,
    pub __list: __pthread_list_t,
}
pub type __pthread_list_t = __pthread_internal_list;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_internal_list {
    pub __prev: *mut __pthread_internal_list,
    pub __next: *mut __pthread_internal_list,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PyrrhicPosition {
    pub white: uint64_t,
    pub black: uint64_t,
    pub kings: uint64_t,
    pub queens: uint64_t,
    pub rooks: uint64_t,
    pub bishops: uint64_t,
    pub knights: uint64_t,
    pub pawns: uint64_t,
    pub rule50: uint8_t,
    pub ep: uint8_t,
    pub turn: bool,
}
pub const RANK_ENC: C2RustUnnamed_2 = 2;
pub const PIECE_ENC: C2RustUnnamed_2 = 0;
pub const FILE_ENC: C2RustUnnamed_2 = 1;
pub const PYRRHIC_WHITE: C2RustUnnamed_3 = 1;
pub const PYRRHIC_ROOK: C2RustUnnamed_3 = 4;
pub const PYRRHIC_BISHOP: C2RustUnnamed_3 = 3;
pub const PYRRHIC_KNIGHT: C2RustUnnamed_3 = 2;
pub const PYRRHIC_BLACK: C2RustUnnamed_3 = 0;
pub const PYRRHIC_PRIME_NONE: C2RustUnnamed_4 = 0;
pub const PYRRHIC_PRIME_BKING: C2RustUnnamed_4 = 0;
pub const PYRRHIC_PRIME_WKING: C2RustUnnamed_4 = 0;
pub type PyrrhicMove = uint16_t;
pub const PYRRHIC_PROMOSQS: C2RustUnnamed_4 = 18374686479671623935;
pub const PYRRHIC_PROMOTES_BISHOP: C2RustUnnamed_3 = 3;
pub const PYRRHIC_PROMOTES_ROOK: C2RustUnnamed_3 = 2;
pub const PYRRHIC_PROMOTES_KNIGHT: C2RustUnnamed_3 = 4;
pub const PYRRHIC_PROMOTES_QUEEN: C2RustUnnamed_3 = 1;
pub const PYRRHIC_PROMOTES_NONE: C2RustUnnamed_3 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TbRootMove {
    pub move_0: PyrrhicMove,
    pub pv: [PyrrhicMove; 256],
    pub pvSize: libc::c_uint,
    pub tbScore: int32_t,
    pub tbRank: int32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TbRootMoves {
    pub size: libc::c_uint,
    pub moves: [TbRootMove; 256],
}
pub type C2RustUnnamed_1 = libc::c_uint;
pub type C2RustUnnamed_2 = libc::c_uint;
pub type C2RustUnnamed_3 = libc::c_uint;
pub const PYRRHIC_BKING: C2RustUnnamed_3 = 14;
pub const PYRRHIC_WKING: C2RustUnnamed_3 = 6;
pub type C2RustUnnamed_4 = libc::c_ulong;
#[no_mangle]
pub unsafe extern "C" fn atomic_init(mut var: *mut atomic_bool, mut val: bool) {
    *var = val;
}
#[no_mangle]
pub unsafe extern "C" fn atomic_load_explicit(
    mut var: *mut atomic_bool,
    mut ordering: libc::c_int,
) -> bool {
    return *var;
}
#[no_mangle]
pub unsafe extern "C" fn atomic_store_explicit(
    mut var: *mut atomic_bool,
    mut val: bool,
    mut ordering: libc::c_int,
) {
    *var = val;
}
pub fn poplsb(mut x: &mut uint64_t) -> uint64_t {
    let lsb = x.trailing_zeros();
    *x &= x.wrapping_sub(1);
    lsb as uint64_t
}

use cozy_chess::*;
pub fn pawnAttacks(c: uint64_t, sq: uint64_t) -> uint64_t {
    let attacks = get_pawn_attacks(
        Square::index(sq as usize),
        if c == 0 { Color::Black } else { Color::White },
    );
    attacks.0
}
pub fn knightAttacks(sq: uint64_t) -> uint64_t {
    get_knight_moves(Square::index(sq as usize)).0
}
pub fn popcount(x: uint64_t) -> uint64_t {
    x.count_ones() as u64
}
pub fn bishopAttacks(sq: uint64_t, occ: uint64_t) -> uint64_t {
    get_bishop_moves(Square::index(sq as usize), BitBoard(occ)).0
}
pub fn getlsb(x: uint64_t) -> uint64_t {
    x.trailing_zeros() as u64
}
pub fn rookAttacks(sq: uint64_t, occ: uint64_t) -> uint64_t {
    get_rook_moves(Square::index(sq as usize), BitBoard(occ)).0
}
pub fn kingAttacks(sq: uint64_t) -> uint64_t {
    get_king_moves(Square::index(sq as usize)).0
}
pub fn queenAttacks(sq: uint64_t, occ: uint64_t) -> uint64_t {
    bishopAttacks(sq, occ) | rookAttacks(sq, occ)
}

#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
#[inline]
unsafe extern "C" fn __bswap_64(mut __bsx: __uint64_t) -> __uint64_t {
    return ((__bsx as libc::c_ulonglong & 0xff00000000000000 as libc::c_ulonglong)
        >> 56 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff000000000000 as libc::c_ulonglong) >> 40 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff0000000000 as libc::c_ulonglong) >> 24 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff00000000 as libc::c_ulonglong) >> 8 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff000000 as libc::c_ulonglong) << 8 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff0000 as libc::c_ulonglong) << 24 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff00 as libc::c_ulonglong) << 40 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff as libc::c_ulonglong) << 56 as libc::c_int)
        as __uint64_t;
}
unsafe extern "C" fn from_le_u32(mut x: uint32_t) -> uint32_t {
    return x;
}
unsafe extern "C" fn from_le_u16(mut x: uint16_t) -> uint16_t {
    return x;
}
unsafe extern "C" fn from_be_u64(mut x: uint64_t) -> uint64_t {
    return __bswap_64(x);
}
unsafe extern "C" fn from_be_u32(mut x: uint32_t) -> uint32_t {
    return __bswap_32(x);
}
#[inline]
unsafe extern "C" fn read_le_u32(mut p: *mut libc::c_void) -> uint32_t {
    let le_u32 = (p as *mut uint32_t).read_unaligned();
    return from_le_u32(le_u32);
}
#[inline]
unsafe extern "C" fn read_le_u16(mut p: *mut libc::c_void) -> uint16_t {
    let le_u16 = (p as *mut uint16_t).read_unaligned();
    return from_le_u16(le_u16);
}
unsafe extern "C" fn file_size(mut fd: libc::c_int) -> size_t {
    let mut buf: stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atime: 0,
        st_atimensec: 0,
        st_mtime: 0,
        st_mtimensec: 0,
        st_ctime: 0,
        st_ctimensec: 0,
        __glibc_reserved: [0; 3],
    };
    if fstat(fd, &mut buf) != 0 {
        return 0 as libc::c_int as size_t;
    } else {
        return buf.st_size as size_t;
    };
}
static mut tbMutex: pthread_mutex_t = pthread_mutex_t {
    __data: __pthread_mutex_s {
        __lock: 0,
        __count: 0,
        __owner: 0,
        __nusers: 0,
        __kind: 0,
        __spins: 0,
        __elision: 0,
        __list: __pthread_internal_list {
            __prev: 0 as *const __pthread_internal_list as *mut __pthread_internal_list,
            __next: 0 as *const __pthread_internal_list as *mut __pthread_internal_list,
        },
    },
};
static mut initialized: libc::c_int = 0 as libc::c_int;
static mut numPaths: libc::c_int = 0 as libc::c_int;
static mut pathString: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut paths: *mut *mut libc::c_char = 0 as *const *mut libc::c_char as *mut *mut libc::c_char;
unsafe extern "C" fn open_tb(
    mut str: *const libc::c_char,
    mut suffix: *const libc::c_char,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut file: *mut libc::c_char = 0 as *mut libc::c_char;
    i = 0 as libc::c_int;
    while i < numPaths {
        file = malloc(
            (strlen(*paths.offset(i as isize)))
                .wrapping_add(strlen(str))
                .wrapping_add(strlen(suffix))
                .wrapping_add(2 as libc::c_int as libc::c_ulong),
        ) as *mut libc::c_char;
        strcpy(file, *paths.offset(i as isize));
        strcat(file, b"/\0" as *const u8 as *const libc::c_char);
        strcat(file, str);
        strcat(file, suffix);
        fd = open(file, 0 as libc::c_int);
        free(file as *mut libc::c_void);
        if fd != -(1 as libc::c_int) {
            return fd;
        }
        i += 1;
        i;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn close_tb(mut fd: libc::c_int) {
    close(fd);
}
unsafe extern "C" fn map_file(mut fd: libc::c_int, mut mapping: *mut map_t) -> *mut libc::c_void {
    let mut statbuf: stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atime: 0,
        st_atimensec: 0,
        st_mtime: 0,
        st_mtimensec: 0,
        st_ctime: 0,
        st_ctimensec: 0,
        __glibc_reserved: [0; 3],
    };
    if fstat(fd, &mut statbuf) != 0 {
        perror(b"fstat\0" as *const u8 as *const libc::c_char);
        close_tb(fd);
        return 0 as *mut libc::c_void;
    }
    *mapping = statbuf.st_size as map_t;
    let mut data: *mut libc::c_void = mmap(
        0 as *mut libc::c_void,
        statbuf.st_size as size_t,
        0x1 as libc::c_int,
        0x1 as libc::c_int,
        fd,
        0 as libc::c_int as __off_t,
    );
    if data == -(1 as libc::c_int) as *mut libc::c_void {
        perror(b"mmap\0" as *const u8 as *const libc::c_char);
        return 0 as *mut libc::c_void;
    }
    return data;
}
unsafe extern "C" fn unmap_file(mut data: *mut libc::c_void, mut size: map_t) {
    if data.is_null() {
        return;
    }
    if munmap(data, size) < 0 as libc::c_int {
        perror(b"munmap\0" as *const u8 as *const libc::c_char);
    }
}
#[no_mangle]
pub static mut TB_MaxCardinality: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut TB_MaxCardinalityDTM: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut TB_LARGEST: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut TB_NUM_WDL: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut TB_NUM_DTM: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut TB_NUM_DTZ: libc::c_int = 0 as libc::c_int;
static mut tbSuffix: [*const libc::c_char; 3] = [
    b".rtbw\0" as *const u8 as *const libc::c_char,
    b".rtbm\0" as *const u8 as *const libc::c_char,
    b".rtbz\0" as *const u8 as *const libc::c_char,
];
static mut tbMagic: [uint32_t; 3] = [
    0x5d23e871 as libc::c_int as uint32_t,
    0x88ac504b as libc::c_uint,
    0xa50c66d7 as libc::c_uint,
];
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_move_from(mut move_0: PyrrhicMove) -> libc::c_uint {
    return (move_0 as libc::c_int >> 6 as libc::c_int & 0x3f as libc::c_int) as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_move_to(mut move_0: PyrrhicMove) -> libc::c_uint {
    return (move_0 as libc::c_int >> 0 as libc::c_int & 0x3f as libc::c_int) as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_move_promotes(mut move_0: PyrrhicMove) -> libc::c_uint {
    return (move_0 as libc::c_int >> 12 as libc::c_int & 0x7 as libc::c_int) as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_colour_of_piece(mut piece: uint8_t) -> libc::c_int {
    return (piece as libc::c_int >> 3 as libc::c_int == 0) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_type_of_piece(mut piece: uint8_t) -> libc::c_int {
    return piece as libc::c_int & 0x7 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_test_bit(mut bb: uint64_t, mut sq: libc::c_int) -> bool {
    return bb >> sq & 0x1 as libc::c_int as uint64_t != 0;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_enable_bit(mut b: *mut uint64_t, mut sq: libc::c_int) {
    *b = (*b as libc::c_ulonglong | (1 as libc::c_ulonglong) << sq) as uint64_t;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_disable_bit(mut b: *mut uint64_t, mut sq: libc::c_int) {
    *b = (*b as libc::c_ulonglong & !((1 as libc::c_ulonglong) << sq)) as uint64_t;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_promo_square(mut sq: libc::c_int) -> bool {
    return PYRRHIC_PROMOSQS as libc::c_ulong >> sq & 0x1 as libc::c_int as libc::c_ulong != 0;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_pawn_start_square(
    mut colour: libc::c_int,
    mut sq: libc::c_int,
) -> bool {
    return sq >> 3 as libc::c_int
        == (if colour != 0 {
            1 as libc::c_int
        } else {
            6 as libc::c_int
        });
}
#[no_mangle]
pub static mut pyrrhic_piece_to_char: [libc::c_char; 16] =
    unsafe { *::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b" PNBRQK  pnbrqk\0") };
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_pieces_by_type(
    mut pos: *const PyrrhicPosition,
    mut colour: libc::c_int,
    mut piece: libc::c_int,
) -> uint64_t {
    if PYRRHIC_PAWN as libc::c_int <= piece && piece <= PYRRHIC_KING as libc::c_int {
    } else {
        __assert_fail(
            b"PYRRHIC_PAWN <= piece && piece <= PYRRHIC_KING\0" as *const u8 as *const libc::c_char,
            b"./tbchess.c\0" as *const u8 as *const libc::c_char,
            94 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<&[u8; 67], &[libc::c_char; 67]>(
                b"uint64_t pyrrhic_pieces_by_type(const PyrrhicPosition *, int, int)\0",
            ))
            .as_ptr(),
        );
    };
    if colour == PYRRHIC_WHITE as libc::c_int || colour == PYRRHIC_BLACK as libc::c_int {
    } else {
        __assert_fail(
            b"colour == PYRRHIC_WHITE || colour == PYRRHIC_BLACK\0" as *const u8
                as *const libc::c_char,
            b"./tbchess.c\0" as *const u8 as *const libc::c_char,
            95 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<&[u8; 67], &[libc::c_char; 67]>(
                b"uint64_t pyrrhic_pieces_by_type(const PyrrhicPosition *, int, int)\0",
            ))
            .as_ptr(),
        );
    };
    let mut side: uint64_t = if colour == PYRRHIC_WHITE as libc::c_int {
        (*pos).white
    } else {
        (*pos).black
    };
    match piece {
        1 => return (*pos).pawns & side,
        2 => return (*pos).knights & side,
        3 => return (*pos).bishops & side,
        4 => return (*pos).rooks & side,
        5 => return (*pos).queens & side,
        6 => return (*pos).kings & side,
        _ => {
            if 0 as libc::c_int != 0 {
            } else {
                __assert_fail(
                    b"0\0" as *const u8 as *const libc::c_char,
                    b"./tbchess.c\0" as *const u8 as *const libc::c_char,
                    106 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<&[u8; 67], &[libc::c_char; 67]>(
                        b"uint64_t pyrrhic_pieces_by_type(const PyrrhicPosition *, int, int)\0",
                    ))
                    .as_ptr(),
                );
            };
            return 0 as libc::c_int as uint64_t;
        }
    };
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_char_to_piece_type(mut c: libc::c_char) -> libc::c_int {
    let mut i: libc::c_int = PYRRHIC_PAWN as libc::c_int;
    while i <= PYRRHIC_KING as libc::c_int {
        if c as libc::c_int == pyrrhic_piece_to_char[i as usize] as libc::c_int {
            return i;
        }
        i += 1;
        i;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_calc_key(
    mut pos: *const PyrrhicPosition,
    mut mirror: libc::c_int,
) -> uint64_t {
    let mut white: uint64_t = if mirror != 0 {
        (*pos).black
    } else {
        (*pos).white
    };
    let mut black: uint64_t = if mirror != 0 {
        (*pos).white
    } else {
        (*pos).black
    };
    return (popcount(white & (*pos).queens))
        .wrapping_mul(PYRRHIC_PRIME_WQUEEN as libc::c_ulong)
        .wrapping_add(
            (popcount(white & (*pos).rooks)).wrapping_mul(PYRRHIC_PRIME_WROOK as libc::c_ulong),
        )
        .wrapping_add(
            (popcount(white & (*pos).bishops)).wrapping_mul(PYRRHIC_PRIME_WBISHOP as libc::c_ulong),
        )
        .wrapping_add(
            (popcount(white & (*pos).knights)).wrapping_mul(PYRRHIC_PRIME_WKNIGHT as libc::c_ulong),
        )
        .wrapping_add(
            (popcount(white & (*pos).pawns)).wrapping_mul(PYRRHIC_PRIME_WPAWN as libc::c_ulong),
        )
        .wrapping_add(
            (popcount(black & (*pos).queens)).wrapping_mul(PYRRHIC_PRIME_BQUEEN as libc::c_ulong),
        )
        .wrapping_add(
            (popcount(black & (*pos).rooks)).wrapping_mul(PYRRHIC_PRIME_BROOK as libc::c_ulong),
        )
        .wrapping_add(
            (popcount(black & (*pos).bishops)).wrapping_mul(PYRRHIC_PRIME_BBISHOP as libc::c_ulong),
        )
        .wrapping_add(
            (popcount(black & (*pos).knights)).wrapping_mul(PYRRHIC_PRIME_BKNIGHT as libc::c_ulong),
        )
        .wrapping_add(
            (popcount(black & (*pos).pawns)).wrapping_mul(PYRRHIC_PRIME_BPAWN as libc::c_ulong),
        );
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_calc_key_from_pcs(
    mut pieces: *mut libc::c_int,
    mut mirror: libc::c_int,
) -> uint64_t {
    return (*pieces.offset(
        (PYRRHIC_WQUEEN as libc::c_int
            ^ (if mirror != 0 {
                8 as libc::c_int
            } else {
                0 as libc::c_int
            })) as isize,
    ) as libc::c_ulong)
        .wrapping_mul(PYRRHIC_PRIME_WQUEEN as libc::c_ulong)
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_WROOK as libc::c_int
                    ^ (if mirror != 0 {
                        8 as libc::c_int
                    } else {
                        0 as libc::c_int
                    })) as isize,
            ) as libc::c_ulong)
                .wrapping_mul(PYRRHIC_PRIME_WROOK as libc::c_ulong),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_WBISHOP as libc::c_int
                    ^ (if mirror != 0 {
                        8 as libc::c_int
                    } else {
                        0 as libc::c_int
                    })) as isize,
            ) as libc::c_ulong)
                .wrapping_mul(PYRRHIC_PRIME_WBISHOP as libc::c_ulong),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_WKNIGHT as libc::c_int
                    ^ (if mirror != 0 {
                        8 as libc::c_int
                    } else {
                        0 as libc::c_int
                    })) as isize,
            ) as libc::c_ulong)
                .wrapping_mul(PYRRHIC_PRIME_WKNIGHT as libc::c_ulong),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_WPAWN as libc::c_int
                    ^ (if mirror != 0 {
                        8 as libc::c_int
                    } else {
                        0 as libc::c_int
                    })) as isize,
            ) as libc::c_ulong)
                .wrapping_mul(PYRRHIC_PRIME_WPAWN as libc::c_ulong),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_BQUEEN as libc::c_int
                    ^ (if mirror != 0 {
                        8 as libc::c_int
                    } else {
                        0 as libc::c_int
                    })) as isize,
            ) as libc::c_ulong)
                .wrapping_mul(PYRRHIC_PRIME_BQUEEN as libc::c_ulong),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_BROOK as libc::c_int
                    ^ (if mirror != 0 {
                        8 as libc::c_int
                    } else {
                        0 as libc::c_int
                    })) as isize,
            ) as libc::c_ulong)
                .wrapping_mul(PYRRHIC_PRIME_BROOK as libc::c_ulong),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_BBISHOP as libc::c_int
                    ^ (if mirror != 0 {
                        8 as libc::c_int
                    } else {
                        0 as libc::c_int
                    })) as isize,
            ) as libc::c_ulong)
                .wrapping_mul(PYRRHIC_PRIME_BBISHOP as libc::c_ulong),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_BKNIGHT as libc::c_int
                    ^ (if mirror != 0 {
                        8 as libc::c_int
                    } else {
                        0 as libc::c_int
                    })) as isize,
            ) as libc::c_ulong)
                .wrapping_mul(PYRRHIC_PRIME_BKNIGHT as libc::c_ulong),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_BPAWN as libc::c_int
                    ^ (if mirror != 0 {
                        8 as libc::c_int
                    } else {
                        0 as libc::c_int
                    })) as isize,
            ) as libc::c_ulong)
                .wrapping_mul(PYRRHIC_PRIME_BPAWN as libc::c_ulong),
        );
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_calc_key_from_pieces(
    mut pieces: *mut uint8_t,
    mut length: libc::c_int,
) -> uint64_t {
    static mut PyrrhicPrimes: [uint64_t; 16] = [
        PYRRHIC_PRIME_NONE as libc::c_int as uint64_t,
        PYRRHIC_PRIME_WPAWN as libc::c_ulong,
        PYRRHIC_PRIME_WKNIGHT as libc::c_ulong,
        PYRRHIC_PRIME_WBISHOP as libc::c_ulong,
        PYRRHIC_PRIME_WROOK as libc::c_ulong,
        PYRRHIC_PRIME_WQUEEN as libc::c_ulong,
        PYRRHIC_PRIME_WKING as libc::c_int as uint64_t,
        PYRRHIC_PRIME_NONE as libc::c_int as uint64_t,
        PYRRHIC_PRIME_NONE as libc::c_int as uint64_t,
        PYRRHIC_PRIME_BPAWN as libc::c_ulong,
        PYRRHIC_PRIME_BKNIGHT as libc::c_ulong,
        PYRRHIC_PRIME_BBISHOP as libc::c_ulong,
        PYRRHIC_PRIME_BROOK as libc::c_ulong,
        PYRRHIC_PRIME_BQUEEN as libc::c_ulong,
        PYRRHIC_PRIME_BKING as libc::c_int as uint64_t,
        PYRRHIC_PRIME_NONE as libc::c_int as uint64_t,
    ];
    let mut key: uint64_t = 0 as libc::c_int as uint64_t;
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < length {
        key = key.wrapping_add(PyrrhicPrimes[*pieces.offset(i as isize) as usize]);
        i += 1;
        i;
    }
    return key;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_do_bb_move(
    mut bb: uint64_t,
    mut from: libc::c_uint,
    mut to: libc::c_uint,
) -> uint64_t {
    return (((bb >> from & 0x1 as libc::c_int as uint64_t) << to) as libc::c_ulonglong
        | bb as libc::c_ulonglong
            & (!((1 as libc::c_ulonglong) << from) & !((1 as libc::c_ulonglong) << to)))
        as uint64_t;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_make_move(
    mut promote: libc::c_uint,
    mut from: libc::c_uint,
    mut to: libc::c_uint,
) -> PyrrhicMove {
    return ((promote & 0x7 as libc::c_int as libc::c_uint) << 12 as libc::c_int
        | (from & 0x3f as libc::c_int as libc::c_uint) << 6 as libc::c_int
        | to & 0x3f as libc::c_int as libc::c_uint) as PyrrhicMove;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_add_move(
    mut moves: *mut PyrrhicMove,
    mut promotes: libc::c_int,
    mut from: libc::c_uint,
    mut to: libc::c_uint,
) -> *mut PyrrhicMove {
    if promotes == 0 {
        let fresh0 = moves;
        moves = moves.offset(1);
        *fresh0 = pyrrhic_make_move(
            PYRRHIC_PROMOTES_NONE as libc::c_int as libc::c_uint,
            from,
            to,
        );
    } else {
        let fresh1 = moves;
        moves = moves.offset(1);
        *fresh1 = pyrrhic_make_move(
            PYRRHIC_PROMOTES_QUEEN as libc::c_int as libc::c_uint,
            from,
            to,
        );
        let fresh2 = moves;
        moves = moves.offset(1);
        *fresh2 = pyrrhic_make_move(
            PYRRHIC_PROMOTES_KNIGHT as libc::c_int as libc::c_uint,
            from,
            to,
        );
        let fresh3 = moves;
        moves = moves.offset(1);
        *fresh3 = pyrrhic_make_move(
            PYRRHIC_PROMOTES_ROOK as libc::c_int as libc::c_uint,
            from,
            to,
        );
        let fresh4 = moves;
        moves = moves.offset(1);
        *fresh4 = pyrrhic_make_move(
            PYRRHIC_PROMOTES_BISHOP as libc::c_int as libc::c_uint,
            from,
            to,
        );
    }
    return moves;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_gen_captures(
    mut pos: *const PyrrhicPosition,
    mut moves: *mut PyrrhicMove,
) -> *mut PyrrhicMove {
    let mut us: uint64_t = if (*pos).turn as libc::c_int != 0 {
        (*pos).white
    } else {
        (*pos).black
    };
    let mut them: uint64_t = if (*pos).turn as libc::c_int != 0 {
        (*pos).black
    } else {
        (*pos).white
    };
    let mut b: uint64_t = 0;
    let mut att: uint64_t = 0;
    b = us & (*pos).kings;
    while b != 0 {
        att = kingAttacks(getlsb(b)) & them;
        while att != 0 {
            moves = pyrrhic_add_move(
                moves,
                0 as libc::c_int,
                getlsb(b) as libc::c_uint,
                getlsb(att) as libc::c_uint,
            );
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & ((*pos).rooks | (*pos).queens);
    while b != 0 {
        att = rookAttacks(getlsb(b), us | them) & them;
        while att != 0 {
            moves = pyrrhic_add_move(
                moves,
                0 as libc::c_int,
                getlsb(b) as libc::c_uint,
                getlsb(att) as libc::c_uint,
            );
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & ((*pos).bishops | (*pos).queens);
    while b != 0 {
        att = bishopAttacks(getlsb(b), us | them) & them;
        while att != 0 {
            moves = pyrrhic_add_move(
                moves,
                0 as libc::c_int,
                getlsb(b) as libc::c_uint,
                getlsb(att) as libc::c_uint,
            );
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & (*pos).knights;
    while b != 0 {
        att = knightAttacks(getlsb(b)) & them;
        while att != 0 {
            moves = pyrrhic_add_move(
                moves,
                0 as libc::c_int,
                getlsb(b) as libc::c_uint,
                getlsb(att) as libc::c_uint,
            );
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & (*pos).pawns;
    while b != 0 {
        if (*pos).ep as libc::c_int != 0
            && pyrrhic_test_bit(
                pawnAttacks(!(*pos).turn as libc::c_int as uint64_t, getlsb(b)),
                (*pos).ep as libc::c_int,
            ) as libc::c_int
                != 0
        {
            moves = pyrrhic_add_move(
                moves,
                0 as libc::c_int,
                getlsb(b) as libc::c_uint,
                (*pos).ep as libc::c_uint,
            );
        }
        att = pawnAttacks(!(*pos).turn as libc::c_int as uint64_t, getlsb(b)) & them;
        while att != 0 {
            moves = pyrrhic_add_move(
                moves,
                pyrrhic_promo_square(getlsb(att) as libc::c_int) as libc::c_int,
                getlsb(b) as libc::c_uint,
                getlsb(att) as libc::c_uint,
            );
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    return moves;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_gen_moves(
    mut pos: *const PyrrhicPosition,
    mut moves: *mut PyrrhicMove,
) -> *mut PyrrhicMove {
    let Forward: libc::c_uint = (if (*pos).turn as libc::c_int == PYRRHIC_WHITE as libc::c_int {
        8 as libc::c_int
    } else {
        -(8 as libc::c_int)
    }) as libc::c_uint;
    let mut us: uint64_t = if (*pos).turn as libc::c_int != 0 {
        (*pos).white
    } else {
        (*pos).black
    };
    let mut them: uint64_t = if (*pos).turn as libc::c_int != 0 {
        (*pos).black
    } else {
        (*pos).white
    };
    let mut b: uint64_t = 0;
    let mut att: uint64_t = 0;
    b = us & (*pos).kings;
    while b != 0 {
        att = kingAttacks(getlsb(b)) & !us;
        while att != 0 {
            moves = pyrrhic_add_move(
                moves,
                0 as libc::c_int,
                getlsb(b) as libc::c_uint,
                getlsb(att) as libc::c_uint,
            );
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & ((*pos).rooks | (*pos).queens);
    while b != 0 {
        att = rookAttacks(getlsb(b), us | them) & !us;
        while att != 0 {
            moves = pyrrhic_add_move(
                moves,
                0 as libc::c_int,
                getlsb(b) as libc::c_uint,
                getlsb(att) as libc::c_uint,
            );
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & ((*pos).bishops | (*pos).queens);
    while b != 0 {
        att = bishopAttacks(getlsb(b), us | them) & !us;
        while att != 0 {
            moves = pyrrhic_add_move(
                moves,
                0 as libc::c_int,
                getlsb(b) as libc::c_uint,
                getlsb(att) as libc::c_uint,
            );
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & (*pos).knights;
    while b != 0 {
        att = knightAttacks(getlsb(b)) & !us;
        while att != 0 {
            moves = pyrrhic_add_move(
                moves,
                0 as libc::c_int,
                getlsb(b) as libc::c_uint,
                getlsb(att) as libc::c_uint,
            );
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & (*pos).pawns;
    while b != 0 {
        let mut from: libc::c_uint = getlsb(b) as libc::c_uint;
        if (*pos).ep as libc::c_int != 0
            && pyrrhic_test_bit(
                pawnAttacks(!(*pos).turn as libc::c_int as uint64_t, from as uint64_t),
                (*pos).ep as libc::c_int,
            ) as libc::c_int
                != 0
        {
            moves = pyrrhic_add_move(moves, 0 as libc::c_int, from, (*pos).ep as libc::c_uint);
        }
        if !pyrrhic_test_bit(us | them, from.wrapping_add(Forward) as libc::c_int) {
            moves = pyrrhic_add_move(
                moves,
                pyrrhic_promo_square(from.wrapping_add(Forward) as libc::c_int) as libc::c_int,
                from,
                from.wrapping_add(Forward),
            );
        }
        if pyrrhic_pawn_start_square((*pos).turn as libc::c_int, from as libc::c_int) as libc::c_int
            != 0
            && !pyrrhic_test_bit(us | them, from.wrapping_add(Forward) as libc::c_int)
            && !pyrrhic_test_bit(
                us | them,
                from.wrapping_add((2 as libc::c_int as libc::c_uint).wrapping_mul(Forward))
                    as libc::c_int,
            )
        {
            moves = pyrrhic_add_move(
                moves,
                0 as libc::c_int,
                from,
                from.wrapping_add((2 as libc::c_int as libc::c_uint).wrapping_mul(Forward)),
            );
        }
        att = pawnAttacks(!(*pos).turn as libc::c_int as uint64_t, from as uint64_t) & them;
        while att != 0 {
            moves = pyrrhic_add_move(
                moves,
                pyrrhic_promo_square(getlsb(att) as libc::c_int) as libc::c_int,
                from,
                getlsb(att) as libc::c_uint,
            );
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    return moves;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_gen_legal(
    mut pos: *const PyrrhicPosition,
    mut moves: *mut PyrrhicMove,
) -> *mut PyrrhicMove {
    let mut _moves: [PyrrhicMove; 256] = [0; 256];
    let mut end: *mut PyrrhicMove = pyrrhic_gen_moves(pos, _moves.as_mut_ptr());
    let mut results: *mut PyrrhicMove = moves;
    let mut m: *mut PyrrhicMove = _moves.as_mut_ptr();
    while m < end {
        if pyrrhic_legal_move(pos, *m) {
            let fresh5 = results;
            results = results.offset(1);
            *fresh5 = *m;
        }
        m = m.offset(1);
        m;
    }
    return results;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_is_pawn_move(
    mut pos: *const PyrrhicPosition,
    mut move_0: PyrrhicMove,
) -> bool {
    let mut us: uint64_t = if (*pos).turn as libc::c_int != 0 {
        (*pos).white
    } else {
        (*pos).black
    };
    return pyrrhic_test_bit(us & (*pos).pawns, pyrrhic_move_from(move_0) as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_is_en_passant(
    mut pos: *const PyrrhicPosition,
    mut move_0: PyrrhicMove,
) -> bool {
    return pyrrhic_is_pawn_move(pos, move_0) as libc::c_int != 0
        && pyrrhic_move_to(move_0) == (*pos).ep as libc::c_uint
        && (*pos).ep as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_is_capture(
    mut pos: *const PyrrhicPosition,
    mut move_0: PyrrhicMove,
) -> bool {
    let mut them: uint64_t = if (*pos).turn as libc::c_int != 0 {
        (*pos).black
    } else {
        (*pos).white
    };
    return pyrrhic_test_bit(them, pyrrhic_move_to(move_0) as libc::c_int) as libc::c_int != 0
        || pyrrhic_is_en_passant(pos, move_0) as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_is_legal(mut pos: *const PyrrhicPosition) -> bool {
    let mut us: uint64_t = if (*pos).turn as libc::c_int != 0 {
        (*pos).black
    } else {
        (*pos).white
    };
    let mut them: uint64_t = if (*pos).turn as libc::c_int != 0 {
        (*pos).white
    } else {
        (*pos).black
    };
    let mut sq: libc::c_uint = getlsb((*pos).kings & us) as libc::c_uint;
    return kingAttacks(sq as uint64_t) & (*pos).kings & them == 0
        && rookAttacks(sq as uint64_t, us | them) & ((*pos).rooks | (*pos).queens) & them == 0
        && bishopAttacks(sq as uint64_t, us | them) & ((*pos).bishops | (*pos).queens) & them == 0
        && knightAttacks(sq as uint64_t) & (*pos).knights & them == 0
        && pawnAttacks((*pos).turn as libc::c_int as uint64_t, sq as uint64_t)
            & (*pos).pawns
            & them
            == 0;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_is_check(mut pos: *const PyrrhicPosition) -> bool {
    let mut us: uint64_t = if (*pos).turn as libc::c_int != 0 {
        (*pos).white
    } else {
        (*pos).black
    };
    let mut them: uint64_t = if (*pos).turn as libc::c_int != 0 {
        (*pos).black
    } else {
        (*pos).white
    };
    let mut sq: libc::c_uint = getlsb((*pos).kings & us) as libc::c_uint;
    return rookAttacks(sq as uint64_t, us | them) & (((*pos).rooks | (*pos).queens) & them) != 0
        || bishopAttacks(sq as uint64_t, us | them) & (((*pos).bishops | (*pos).queens) & them)
            != 0
        || knightAttacks(sq as uint64_t) & ((*pos).knights & them) != 0
        || pawnAttacks(!(*pos).turn as libc::c_int as uint64_t, sq as uint64_t)
            & ((*pos).pawns & them)
            != 0;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_is_mate(mut pos: *const PyrrhicPosition) -> bool {
    if !pyrrhic_is_check(pos) {
        return 0 as libc::c_int != 0;
    }
    let mut pos1: PyrrhicPosition = PyrrhicPosition {
        white: 0,
        black: 0,
        kings: 0,
        queens: 0,
        rooks: 0,
        bishops: 0,
        knights: 0,
        pawns: 0,
        rule50: 0,
        ep: 0,
        turn: false,
    };
    let mut moves0: [PyrrhicMove; 256] = [0; 256];
    let mut moves: *mut PyrrhicMove = moves0.as_mut_ptr();
    let mut end: *mut PyrrhicMove = pyrrhic_gen_moves(pos, moves);
    while moves < end {
        if pyrrhic_do_move(&mut pos1, pos, *moves) {
            return 0 as libc::c_int != 0;
        }
        moves = moves.offset(1);
        moves;
    }
    return 1 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_do_move(
    mut pos: *mut PyrrhicPosition,
    mut pos0: *const PyrrhicPosition,
    mut move_0: PyrrhicMove,
) -> bool {
    let mut from: libc::c_uint = pyrrhic_move_from(move_0);
    let mut to: libc::c_uint = pyrrhic_move_to(move_0);
    let mut promotes: libc::c_uint = pyrrhic_move_promotes(move_0);
    (*pos).turn = !(*pos0).turn;
    (*pos).white = pyrrhic_do_bb_move((*pos0).white, from, to);
    (*pos).black = pyrrhic_do_bb_move((*pos0).black, from, to);
    (*pos).kings = pyrrhic_do_bb_move((*pos0).kings, from, to);
    (*pos).queens = pyrrhic_do_bb_move((*pos0).queens, from, to);
    (*pos).rooks = pyrrhic_do_bb_move((*pos0).rooks, from, to);
    (*pos).bishops = pyrrhic_do_bb_move((*pos0).bishops, from, to);
    (*pos).knights = pyrrhic_do_bb_move((*pos0).knights, from, to);
    (*pos).pawns = pyrrhic_do_bb_move((*pos0).pawns, from, to);
    (*pos).ep = 0 as libc::c_int as uint8_t;
    if promotes != PYRRHIC_PROMOTES_NONE as libc::c_int as libc::c_uint {
        pyrrhic_disable_bit(&mut (*pos).pawns, to as libc::c_int);
        match promotes {
            1 => {
                pyrrhic_enable_bit(&mut (*pos).queens, to as libc::c_int);
            }
            2 => {
                pyrrhic_enable_bit(&mut (*pos).rooks, to as libc::c_int);
            }
            3 => {
                pyrrhic_enable_bit(&mut (*pos).bishops, to as libc::c_int);
            }
            4 => {
                pyrrhic_enable_bit(&mut (*pos).knights, to as libc::c_int);
            }
            _ => {}
        }
        (*pos).rule50 = 0 as libc::c_int as uint8_t;
    } else if pyrrhic_test_bit((*pos0).pawns, from as libc::c_int) {
        (*pos).rule50 = 0 as libc::c_int as uint8_t;
        if from ^ to == 16 as libc::c_int as libc::c_uint
            && (*pos0).turn as libc::c_int == PYRRHIC_WHITE as libc::c_int
            && pawnAttacks(
                (PYRRHIC_WHITE as libc::c_int == 0) as libc::c_int as uint64_t,
                from.wrapping_add(8 as libc::c_int as libc::c_uint) as uint64_t,
            ) & (*pos0).pawns
                & (*pos0).black
                != 0
        {
            (*pos).ep = from.wrapping_add(8 as libc::c_int as libc::c_uint) as uint8_t;
        }
        if from ^ to == 16 as libc::c_int as libc::c_uint
            && (*pos0).turn as libc::c_int == PYRRHIC_BLACK as libc::c_int
            && pawnAttacks(
                (PYRRHIC_BLACK as libc::c_int == 0) as libc::c_int as uint64_t,
                from.wrapping_sub(8 as libc::c_int as libc::c_uint) as uint64_t,
            ) & (*pos0).pawns
                & (*pos0).white
                != 0
        {
            (*pos).ep = from.wrapping_sub(8 as libc::c_int as libc::c_uint) as uint8_t;
        } else if to == (*pos0).ep as libc::c_uint {
            pyrrhic_disable_bit(
                &mut (*pos).white,
                (if (*pos0).turn as libc::c_int != 0 {
                    to.wrapping_sub(8 as libc::c_int as libc::c_uint)
                } else {
                    to.wrapping_add(8 as libc::c_int as libc::c_uint)
                }) as libc::c_int,
            );
            pyrrhic_disable_bit(
                &mut (*pos).black,
                (if (*pos0).turn as libc::c_int != 0 {
                    to.wrapping_sub(8 as libc::c_int as libc::c_uint)
                } else {
                    to.wrapping_add(8 as libc::c_int as libc::c_uint)
                }) as libc::c_int,
            );
            pyrrhic_disable_bit(
                &mut (*pos).pawns,
                (if (*pos0).turn as libc::c_int != 0 {
                    to.wrapping_sub(8 as libc::c_int as libc::c_uint)
                } else {
                    to.wrapping_add(8 as libc::c_int as libc::c_uint)
                }) as libc::c_int,
            );
        }
    } else if pyrrhic_test_bit((*pos0).white | (*pos0).black, to as libc::c_int) {
        (*pos).rule50 = 0 as libc::c_int as uint8_t;
    } else {
        (*pos).rule50 = ((*pos0).rule50 as libc::c_int + 1 as libc::c_int) as uint8_t;
    }
    return pyrrhic_is_legal(pos);
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_legal_move(
    mut pos: *const PyrrhicPosition,
    mut move_0: PyrrhicMove,
) -> bool {
    let mut pos1: PyrrhicPosition = PyrrhicPosition {
        white: 0,
        black: 0,
        kings: 0,
        queens: 0,
        rooks: 0,
        bishops: 0,
        knights: 0,
        pawns: 0,
        rule50: 0,
        ep: 0,
        turn: false,
    };
    return pyrrhic_do_move(&mut pos1, pos, move_0);
}
static mut tbNumPiece: libc::c_int = 0;
static mut tbNumPawn: libc::c_int = 0;
static mut numWdl: libc::c_int = 0;
static mut numDtm: libc::c_int = 0;
static mut numDtz: libc::c_int = 0;
static mut pieceEntry: *mut PieceEntry = 0 as *const PieceEntry as *mut PieceEntry;
static mut pawnEntry: *mut PawnEntry = 0 as *const PawnEntry as *mut PawnEntry;
static mut tbHash: [TbHashEntry; 4096] = [TbHashEntry {
    key: 0,
    ptr: 0 as *const BaseEntry as *mut BaseEntry,
}; 4096];
unsafe extern "C" fn dtz_to_wdl(mut cnt50: libc::c_int, mut dtz: libc::c_int) -> libc::c_uint {
    let mut wdl: libc::c_int = 0 as libc::c_int;
    if dtz > 0 as libc::c_int {
        wdl = if dtz + cnt50 <= 100 as libc::c_int {
            2 as libc::c_int
        } else {
            1 as libc::c_int
        };
    } else if dtz < 0 as libc::c_int {
        wdl = if -dtz + cnt50 <= 100 as libc::c_int {
            -(2 as libc::c_int)
        } else {
            -(1 as libc::c_int)
        };
    }
    return (wdl + 2 as libc::c_int) as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn tb_probe_wdl(
    mut white: uint64_t,
    mut black: uint64_t,
    mut kings: uint64_t,
    mut queens: uint64_t,
    mut rooks: uint64_t,
    mut bishops: uint64_t,
    mut knights: uint64_t,
    mut pawns: uint64_t,
    mut ep: libc::c_uint,
    mut turn: bool,
) -> libc::c_uint {
    let mut pos: PyrrhicPosition = {
        let mut init = PyrrhicPosition {
            white: white,
            black: black,
            kings: kings,
            queens: queens,
            rooks: rooks,
            bishops: bishops,
            knights: knights,
            pawns: pawns,
            rule50: 0 as libc::c_int as uint8_t,
            ep: ep as uint8_t,
            turn: turn,
        };
        init
    };
    let mut success: libc::c_int = 0;
    let mut v: libc::c_int = probe_wdl(&mut pos, &mut success);
    if success == 0 as libc::c_int {
        return 0xffffffff as libc::c_uint;
    }
    return (v + 2 as libc::c_int) as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn tb_probe_root(
    mut white: uint64_t,
    mut black: uint64_t,
    mut kings: uint64_t,
    mut queens: uint64_t,
    mut rooks: uint64_t,
    mut bishops: uint64_t,
    mut knights: uint64_t,
    mut pawns: uint64_t,
    mut rule50: libc::c_uint,
    mut ep: libc::c_uint,
    mut turn: bool,
    mut results: *mut libc::c_uint,
) -> libc::c_uint {
    let mut pos: PyrrhicPosition = {
        let mut init = PyrrhicPosition {
            white: white,
            black: black,
            kings: kings,
            queens: queens,
            rooks: rooks,
            bishops: bishops,
            knights: knights,
            pawns: pawns,
            rule50: rule50 as uint8_t,
            ep: ep as uint8_t,
            turn: turn,
        };
        init
    };
    let mut dtz: libc::c_int = 0;
    let mut move_0: PyrrhicMove = probe_root(&mut pos, &mut dtz, results);
    if move_0 as libc::c_int == 0 as libc::c_int {
        return 0xffffffff as libc::c_uint;
    }
    if move_0 as libc::c_int == 0xfffe as libc::c_int {
        return (0 as libc::c_int & !(0xf as libc::c_int)
            | (4 as libc::c_int) << 0 as libc::c_int & 0xf as libc::c_int)
            as libc::c_uint;
    }
    if move_0 as libc::c_int == 0xffff as libc::c_int {
        return (0 as libc::c_int & !(0xf as libc::c_int)
            | (2 as libc::c_int) << 0 as libc::c_int & 0xf as libc::c_int)
            as libc::c_uint;
    }
    let mut res: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    res = res & !(0xf as libc::c_int) as libc::c_uint
        | dtz_to_wdl(rule50 as libc::c_int, dtz) << 0 as libc::c_int
            & 0xf as libc::c_int as libc::c_uint;
    res = res & !(0xfff00000 as libc::c_uint)
        | ((if dtz < 0 as libc::c_int { -dtz } else { dtz }) << 20 as libc::c_int) as libc::c_uint
            & 0xfff00000 as libc::c_uint;
    res = res & !(0xfc00 as libc::c_int) as libc::c_uint
        | pyrrhic_move_from(move_0) << 10 as libc::c_int & 0xfc00 as libc::c_int as libc::c_uint;
    res = res & !(0x3f0 as libc::c_int) as libc::c_uint
        | pyrrhic_move_to(move_0) << 4 as libc::c_int & 0x3f0 as libc::c_int as libc::c_uint;
    res = res & !(0x70000 as libc::c_int) as libc::c_uint
        | pyrrhic_move_promotes(move_0) << 16 as libc::c_int
            & 0x70000 as libc::c_int as libc::c_uint;
    res = res & !(0x80000 as libc::c_int) as libc::c_uint
        | ((pyrrhic_is_en_passant(&mut pos, move_0) as libc::c_int) << 19 as libc::c_int
            & 0x80000 as libc::c_int) as libc::c_uint;
    return res;
}
#[no_mangle]
pub unsafe extern "C" fn tb_probe_root_dtz(
    mut white: uint64_t,
    mut black: uint64_t,
    mut kings: uint64_t,
    mut queens: uint64_t,
    mut rooks: uint64_t,
    mut bishops: uint64_t,
    mut knights: uint64_t,
    mut pawns: uint64_t,
    mut rule50: libc::c_uint,
    mut ep: libc::c_uint,
    mut turn: bool,
    mut hasRepeated: bool,
    mut useRule50: bool,
    mut results: *mut TbRootMoves,
) -> libc::c_int {
    let mut pos: PyrrhicPosition = {
        let mut init = PyrrhicPosition {
            white: white,
            black: black,
            kings: kings,
            queens: queens,
            rooks: rooks,
            bishops: bishops,
            knights: knights,
            pawns: pawns,
            rule50: rule50 as uint8_t,
            ep: ep as uint8_t,
            turn: turn,
        };
        init
    };
    return root_probe_dtz(&mut pos, hasRepeated, useRule50, results);
}
#[no_mangle]
pub unsafe extern "C" fn tb_probe_root_wdl(
    mut white: uint64_t,
    mut black: uint64_t,
    mut kings: uint64_t,
    mut queens: uint64_t,
    mut rooks: uint64_t,
    mut bishops: uint64_t,
    mut knights: uint64_t,
    mut pawns: uint64_t,
    mut rule50: libc::c_uint,
    mut ep: libc::c_uint,
    mut turn: bool,
    mut useRule50: bool,
    mut results: *mut TbRootMoves,
) -> libc::c_int {
    let mut pos: PyrrhicPosition = {
        let mut init = PyrrhicPosition {
            white: white,
            black: black,
            kings: kings,
            queens: queens,
            rooks: rooks,
            bishops: bishops,
            knights: knights,
            pawns: pawns,
            rule50: rule50 as uint8_t,
            ep: ep as uint8_t,
            turn: turn,
        };
        init
    };
    return root_probe_wdl(&mut pos, useRule50, results);
}
unsafe extern "C" fn prt_str(
    mut pos: *const PyrrhicPosition,
    mut str: *mut libc::c_char,
    mut flip: libc::c_int,
) {
    let mut color: libc::c_int = if flip != 0 {
        PYRRHIC_BLACK as libc::c_int
    } else {
        PYRRHIC_WHITE as libc::c_int
    };
    let mut pt: libc::c_int = PYRRHIC_KING as libc::c_int;
    while pt >= PYRRHIC_PAWN as libc::c_int {
        let mut i: libc::c_int = popcount(pyrrhic_pieces_by_type(pos, color, pt)) as libc::c_int;
        while i > 0 as libc::c_int {
            let fresh6 = str;
            str = str.offset(1);
            *fresh6 = pyrrhic_piece_to_char[pt as usize];
            i -= 1;
            i;
        }
        pt -= 1;
        pt;
    }
    let fresh7 = str;
    str = str.offset(1);
    *fresh7 = 'v' as i32 as libc::c_char;
    let mut pt_0: libc::c_int = PYRRHIC_KING as libc::c_int;
    while pt_0 >= PYRRHIC_PAWN as libc::c_int {
        let mut i_0: libc::c_int =
            popcount(pyrrhic_pieces_by_type(pos, color ^ 1 as libc::c_int, pt_0)) as libc::c_int;
        while i_0 > 0 as libc::c_int {
            let fresh8 = str;
            str = str.offset(1);
            *fresh8 = pyrrhic_piece_to_char[pt_0 as usize];
            i_0 -= 1;
            i_0;
        }
        pt_0 -= 1;
        pt_0;
    }
    let fresh9 = str;
    str = str.offset(1);
    *fresh9 = 0 as libc::c_int as libc::c_char;
}
unsafe extern "C" fn test_tb(
    mut str: *const libc::c_char,
    mut suffix: *const libc::c_char,
) -> libc::c_int {
    let mut fd: libc::c_int = open_tb(str, suffix);
    if fd != -(1 as libc::c_int) {
        let mut size: size_t = file_size(fd);
        close_tb(fd);
        if size & 63 as libc::c_int as size_t != 16 as libc::c_int as size_t {
            fprintf(
                stderr,
                b"Incomplete tablebase file %s.%s\n\0" as *const u8 as *const libc::c_char,
                str,
                suffix,
            );
            printf(
                b"info string Incomplete tablebase file %s.%s\n\0" as *const u8
                    as *const libc::c_char,
                str,
                suffix,
            );
            fd = -(1 as libc::c_int);
        }
    }
    return (fd != -(1 as libc::c_int)) as libc::c_int;
}
unsafe extern "C" fn map_tb(
    mut name: *const libc::c_char,
    mut suffix: *const libc::c_char,
    mut mapping: *mut map_t,
) -> *mut libc::c_void {
    let mut fd: libc::c_int = open_tb(name, suffix);
    if fd == -(1 as libc::c_int) {
        return 0 as *mut libc::c_void;
    }
    let mut data: *mut libc::c_void = map_file(fd, mapping);
    if data.is_null() {
        fprintf(
            stderr,
            b"Could not map %s%s into memory.\n\0" as *const u8 as *const libc::c_char,
            name,
            suffix,
        );
        exit(1 as libc::c_int);
    }
    close_tb(fd);
    return data;
}
unsafe extern "C" fn add_to_hash(mut ptr: *mut BaseEntry, mut key: uint64_t) {
    let mut idx: libc::c_int = 0;
    idx = (key
        >> 64 as libc::c_int
            - (if (7 as libc::c_int) < 7 as libc::c_int {
                11 as libc::c_int
            } else {
                12 as libc::c_int
            })) as libc::c_int;
    while !(tbHash[idx as usize].ptr).is_null() {
        idx = idx + 1 as libc::c_int
            & ((1 as libc::c_int)
                << (if (7 as libc::c_int) < 7 as libc::c_int {
                    11 as libc::c_int
                } else {
                    12 as libc::c_int
                }))
                - 1 as libc::c_int;
    }
    tbHash[idx as usize].key = key;
    tbHash[idx as usize].ptr = ptr;
}
unsafe extern "C" fn init_tb(mut str: *mut libc::c_char) {
    if test_tb(str, tbSuffix[WDL as libc::c_int as usize]) == 0 {
        return;
    }
    let mut pcs: [libc::c_int; 16] = [0; 16];
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < 16 as libc::c_int {
        pcs[i as usize] = 0 as libc::c_int;
        i += 1;
        i;
    }
    let mut color: libc::c_int = 0 as libc::c_int;
    let mut s: *mut libc::c_char = str;
    while *s != 0 {
        if *s as libc::c_int == 'v' as i32 {
            color = 8 as libc::c_int;
        } else {
            let mut piece_type: libc::c_int = pyrrhic_char_to_piece_type(*s);
            if piece_type != 0 {
                if piece_type | color < 16 as libc::c_int {
                } else {
                    __assert_fail(
                        b"(piece_type | color) < 16\0" as *const u8 as *const libc::c_char,
                        b"tbprobe.c\0" as *const u8 as *const libc::c_char,
                        550 as libc::c_int as libc::c_uint,
                        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                            b"void init_tb(char *)\0",
                        ))
                        .as_ptr(),
                    );
                };
                pcs[(piece_type | color) as usize] += 1;
                pcs[(piece_type | color) as usize];
            }
        }
        s = s.offset(1);
        s;
    }
    let mut key: uint64_t = pyrrhic_calc_key_from_pcs(pcs.as_mut_ptr(), 0 as libc::c_int);
    let mut key2: uint64_t = pyrrhic_calc_key_from_pcs(pcs.as_mut_ptr(), 1 as libc::c_int);
    let mut hasPawns: bool = pcs[PYRRHIC_WPAWN as libc::c_int as usize] != 0
        || pcs[PYRRHIC_BPAWN as libc::c_int as usize] != 0;
    let mut be: *mut BaseEntry = if hasPawns as libc::c_int != 0 {
        let fresh10 = tbNumPawn;
        tbNumPawn = tbNumPawn + 1;
        &mut (*pawnEntry.offset(fresh10 as isize)).be
    } else {
        let fresh11 = tbNumPiece;
        tbNumPiece = tbNumPiece + 1;
        &mut (*pieceEntry.offset(fresh11 as isize)).be
    };
    (*be).hasPawns = hasPawns;
    (*be).key = key;
    (*be).symmetric = key == key2;
    (*be).num = 0 as libc::c_int as uint8_t;
    let mut i_0: libc::c_int = 0 as libc::c_int;
    while i_0 < 16 as libc::c_int {
        (*be).num = ((*be).num as libc::c_int + pcs[i_0 as usize]) as uint8_t;
        i_0 += 1;
        i_0;
    }
    numWdl += 1;
    numWdl;
    (*be).hasDtm = test_tb(str, tbSuffix[DTM as libc::c_int as usize]) != 0;
    numDtm += (*be).hasDtm as libc::c_int;
    (*be).hasDtz = test_tb(str, tbSuffix[DTZ as libc::c_int as usize]) != 0;
    numDtz += (*be).hasDtz as libc::c_int;
    if (*be).num as libc::c_int > TB_MaxCardinality {
        TB_MaxCardinality = (*be).num as libc::c_int;
    }
    if (*be).hasDtm {
        if (*be).num as libc::c_int > TB_MaxCardinalityDTM {
            TB_MaxCardinalityDTM = (*be).num as libc::c_int;
        }
    }
    let mut type_0: libc::c_int = 0 as libc::c_int;
    while type_0 < 3 as libc::c_int {
        atomic_init(
            &mut *((*be).ready).as_mut_ptr().offset(type_0 as isize),
            0 as libc::c_int != 0,
        );
        type_0 += 1;
        type_0;
    }
    if !(*be).hasPawns {
        let mut j: libc::c_int = 0 as libc::c_int;
        let mut i_1: libc::c_int = 0 as libc::c_int;
        while i_1 < 16 as libc::c_int {
            if pcs[i_1 as usize] == 1 as libc::c_int {
                j += 1;
                j;
            }
            i_1 += 1;
            i_1;
        }
        (*be).c2rust_unnamed.kk_enc = j == 2 as libc::c_int;
    } else {
        (*be).c2rust_unnamed.pawns[0 as libc::c_int as usize] =
            pcs[PYRRHIC_WPAWN as libc::c_int as usize] as uint8_t;
        (*be).c2rust_unnamed.pawns[1 as libc::c_int as usize] =
            pcs[PYRRHIC_BPAWN as libc::c_int as usize] as uint8_t;
        if pcs[PYRRHIC_BPAWN as libc::c_int as usize] != 0
            && (pcs[PYRRHIC_WPAWN as libc::c_int as usize] == 0
                || pcs[PYRRHIC_WPAWN as libc::c_int as usize]
                    > pcs[PYRRHIC_BPAWN as libc::c_int as usize])
        {
            let mut tmp: libc::c_int =
                (*be).c2rust_unnamed.pawns[0 as libc::c_int as usize] as libc::c_int;
            (*be).c2rust_unnamed.pawns[0 as libc::c_int as usize] =
                (*be).c2rust_unnamed.pawns[1 as libc::c_int as usize];
            (*be).c2rust_unnamed.pawns[1 as libc::c_int as usize] = tmp as uint8_t;
        }
    }
    add_to_hash(be, key);
    if key != key2 {
        add_to_hash(be, key2);
    }
}
#[no_mangle]
pub unsafe extern "C" fn num_tables(mut be: *mut BaseEntry, type_0: libc::c_int) -> libc::c_int {
    return if (*be).hasPawns as libc::c_int != 0 {
        if type_0 == DTM as libc::c_int {
            6 as libc::c_int
        } else {
            4 as libc::c_int
        }
    } else {
        1 as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn first_ei(mut be: *mut BaseEntry, type_0: libc::c_int) -> *mut EncInfo {
    return if (*be).hasPawns as libc::c_int != 0 {
        &mut *((*(be as *mut PawnEntry)).ei).as_mut_ptr().offset(
            (if type_0 == WDL as libc::c_int {
                0 as libc::c_int
            } else if type_0 == DTM as libc::c_int {
                8 as libc::c_int
            } else {
                20 as libc::c_int
            }) as isize,
        ) as *mut EncInfo
    } else {
        &mut *((*(be as *mut PieceEntry)).ei).as_mut_ptr().offset(
            (if type_0 == WDL as libc::c_int {
                0 as libc::c_int
            } else if type_0 == DTM as libc::c_int {
                2 as libc::c_int
            } else {
                4 as libc::c_int
            }) as isize,
        ) as *mut EncInfo
    };
}
unsafe extern "C" fn free_tb_entry(mut be: *mut BaseEntry) {
    let mut type_0: libc::c_int = 0 as libc::c_int;
    while type_0 < 3 as libc::c_int {
        if atomic_load_explicit(
            &mut *((*be).ready).as_mut_ptr().offset(type_0 as isize),
            memory_order_relaxed as libc::c_int,
        ) {
            unmap_file(
                (*be).data[type_0 as usize] as *mut libc::c_void,
                (*be).mapping[type_0 as usize],
            );
            let mut num: libc::c_int = num_tables(be, type_0);
            let mut ei: *mut EncInfo = first_ei(be, type_0);
            let mut t: libc::c_int = 0 as libc::c_int;
            while t < num {
                free((*ei.offset(t as isize)).precomp as *mut libc::c_void);
                if type_0 != DTZ as libc::c_int {
                    free((*ei.offset((num + t) as isize)).precomp as *mut libc::c_void);
                }
                t += 1;
                t;
            }
            atomic_store_explicit(
                &mut *((*be).ready).as_mut_ptr().offset(type_0 as isize),
                0 as libc::c_int != 0,
                memory_order_relaxed as libc::c_int,
            );
        }
        type_0 += 1;
        type_0;
    }
}
#[no_mangle]
pub unsafe extern "C" fn tb_init(mut path: *const libc::c_char) -> bool {
    if initialized == 0 {
        init_indices();
        initialized = 1 as libc::c_int;
    }
    TB_LARGEST = 0 as libc::c_int;
    TB_NUM_WDL = 0 as libc::c_int;
    TB_NUM_DTZ = 0 as libc::c_int;
    TB_NUM_DTM = 0 as libc::c_int;
    if !pathString.is_null() {
        free(pathString as *mut libc::c_void);
        free(paths as *mut libc::c_void);
        let mut i: libc::c_int = 0 as libc::c_int;
        while i < tbNumPiece {
            free_tb_entry(&mut *pieceEntry.offset(i as isize) as *mut PieceEntry as *mut BaseEntry);
            i += 1;
            i;
        }
        let mut i_0: libc::c_int = 0 as libc::c_int;
        while i_0 < tbNumPawn {
            free_tb_entry(&mut *pawnEntry.offset(i_0 as isize) as *mut PawnEntry as *mut BaseEntry);
            i_0 += 1;
            i_0;
        }
        pthread_mutex_destroy(&mut tbMutex);
        pathString = 0 as *mut libc::c_char;
        numDtz = 0 as libc::c_int;
        numDtm = numDtz;
        numWdl = numDtm;
    }
    let mut p: *const libc::c_char = path;
    if strlen(p) == 0 as libc::c_int as libc::c_ulong
        || strcmp(p, b"<empty>\0" as *const u8 as *const libc::c_char) == 0
    {
        return 1 as libc::c_int != 0;
    }
    pathString =
        malloc((strlen(p)).wrapping_add(1 as libc::c_int as libc::c_ulong)) as *mut libc::c_char;
    strcpy(pathString, p);
    numPaths = 0 as libc::c_int;
    let mut i_1: libc::c_int = 0 as libc::c_int;
    loop {
        if *pathString.offset(i_1 as isize) as libc::c_int != ':' as i32 {
            numPaths += 1;
            numPaths;
        }
        while *pathString.offset(i_1 as isize) as libc::c_int != 0
            && *pathString.offset(i_1 as isize) as libc::c_int != ':' as i32
        {
            i_1 += 1;
            i_1;
        }
        if *pathString.offset(i_1 as isize) == 0 {
            break;
        }
        *pathString.offset(i_1 as isize) = 0 as libc::c_int as libc::c_char;
        i_1 += 1;
        i_1;
    }
    paths = malloc(
        (numPaths as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong),
    ) as *mut *mut libc::c_char;
    let mut i_2: libc::c_int = 0 as libc::c_int;
    let mut j: libc::c_int = 0 as libc::c_int;
    while i_2 < numPaths {
        while *pathString.offset(j as isize) == 0 {
            j += 1;
            j;
        }
        let ref mut fresh12 = *paths.offset(i_2 as isize);
        *fresh12 = &mut *pathString.offset(j as isize) as *mut libc::c_char;
        while *pathString.offset(j as isize) != 0 {
            j += 1;
            j;
        }
        i_2 += 1;
        i_2;
    }
    pthread_mutex_init(&mut tbMutex, 0 as *const pthread_mutexattr_t);
    tbNumPawn = 0 as libc::c_int;
    tbNumPiece = tbNumPawn;
    TB_MaxCardinalityDTM = 0 as libc::c_int;
    TB_MaxCardinality = TB_MaxCardinalityDTM;
    if pieceEntry.is_null() {
        pieceEntry = malloc(
            ((if (7 as libc::c_int) < 7 as libc::c_int {
                254 as libc::c_int
            } else {
                650 as libc::c_int
            }) as libc::c_ulong)
                .wrapping_mul(::core::mem::size_of::<PieceEntry>() as libc::c_ulong),
        ) as *mut PieceEntry;
        pawnEntry = malloc(
            ((if (7 as libc::c_int) < 7 as libc::c_int {
                256 as libc::c_int
            } else {
                861 as libc::c_int
            }) as libc::c_ulong)
                .wrapping_mul(::core::mem::size_of::<PawnEntry>() as libc::c_ulong),
        ) as *mut PawnEntry;
        if pieceEntry.is_null() || pawnEntry.is_null() {
            fprintf(
                stderr,
                b"Out of memory.\n\0" as *const u8 as *const libc::c_char,
            );
            exit(1 as libc::c_int);
        }
    }
    let mut i_3: libc::c_int = 0 as libc::c_int;
    while i_3
        < (1 as libc::c_int)
            << (if (7 as libc::c_int) < 7 as libc::c_int {
                11 as libc::c_int
            } else {
                12 as libc::c_int
            })
    {
        tbHash[i_3 as usize].key = 0 as libc::c_int as uint64_t;
        tbHash[i_3 as usize].ptr = 0 as *mut BaseEntry;
        i_3 += 1;
        i_3;
    }
    let mut str: [libc::c_char; 16] = [0; 16];
    let mut i_4: libc::c_int = 0;
    let mut j_0: libc::c_int = 0;
    let mut k: libc::c_int = 0;
    let mut l: libc::c_int = 0;
    let mut m: libc::c_int = 0;
    i_4 = 0 as libc::c_int;
    while i_4 < 5 as libc::c_int {
        snprintf(
            str.as_mut_ptr(),
            16 as libc::c_int as libc::c_ulong,
            b"K%cvK\0" as *const u8 as *const libc::c_char,
            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - i_4) as usize] as libc::c_int,
        );
        init_tb(str.as_mut_ptr());
        i_4 += 1;
        i_4;
    }
    i_4 = 0 as libc::c_int;
    while i_4 < 5 as libc::c_int {
        j_0 = i_4;
        while j_0 < 5 as libc::c_int {
            snprintf(
                str.as_mut_ptr(),
                16 as libc::c_int as libc::c_ulong,
                b"K%cvK%c\0" as *const u8 as *const libc::c_char,
                pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - i_4) as usize] as libc::c_int,
                pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - j_0) as usize] as libc::c_int,
            );
            init_tb(str.as_mut_ptr());
            j_0 += 1;
            j_0;
        }
        i_4 += 1;
        i_4;
    }
    i_4 = 0 as libc::c_int;
    while i_4 < 5 as libc::c_int {
        j_0 = i_4;
        while j_0 < 5 as libc::c_int {
            snprintf(
                str.as_mut_ptr(),
                16 as libc::c_int as libc::c_ulong,
                b"K%c%cvK\0" as *const u8 as *const libc::c_char,
                pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - i_4) as usize] as libc::c_int,
                pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - j_0) as usize] as libc::c_int,
            );
            init_tb(str.as_mut_ptr());
            j_0 += 1;
            j_0;
        }
        i_4 += 1;
        i_4;
    }
    i_4 = 0 as libc::c_int;
    while i_4 < 5 as libc::c_int {
        j_0 = i_4;
        while j_0 < 5 as libc::c_int {
            k = 0 as libc::c_int;
            while k < 5 as libc::c_int {
                snprintf(
                    str.as_mut_ptr(),
                    16 as libc::c_int as libc::c_ulong,
                    b"K%c%cvK%c\0" as *const u8 as *const libc::c_char,
                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - i_4) as usize]
                        as libc::c_int,
                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - j_0) as usize]
                        as libc::c_int,
                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - k) as usize]
                        as libc::c_int,
                );
                init_tb(str.as_mut_ptr());
                k += 1;
                k;
            }
            j_0 += 1;
            j_0;
        }
        i_4 += 1;
        i_4;
    }
    i_4 = 0 as libc::c_int;
    while i_4 < 5 as libc::c_int {
        j_0 = i_4;
        while j_0 < 5 as libc::c_int {
            k = j_0;
            while k < 5 as libc::c_int {
                snprintf(
                    str.as_mut_ptr(),
                    16 as libc::c_int as libc::c_ulong,
                    b"K%c%c%cvK\0" as *const u8 as *const libc::c_char,
                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - i_4) as usize]
                        as libc::c_int,
                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - j_0) as usize]
                        as libc::c_int,
                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - k) as usize]
                        as libc::c_int,
                );
                init_tb(str.as_mut_ptr());
                k += 1;
                k;
            }
            j_0 += 1;
            j_0;
        }
        i_4 += 1;
        i_4;
    }
    if !((::core::mem::size_of::<size_t>() as libc::c_ulong) < 8 as libc::c_int as libc::c_ulong
        || (7 as libc::c_int) < 6 as libc::c_int)
    {
        i_4 = 0 as libc::c_int;
        while i_4 < 5 as libc::c_int {
            j_0 = i_4;
            while j_0 < 5 as libc::c_int {
                k = i_4;
                while k < 5 as libc::c_int {
                    l = if i_4 == k { j_0 } else { k };
                    while l < 5 as libc::c_int {
                        snprintf(
                            str.as_mut_ptr(),
                            16 as libc::c_int as libc::c_ulong,
                            b"K%c%cvK%c%c\0" as *const u8 as *const libc::c_char,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - i_4) as usize]
                                as libc::c_int,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - j_0) as usize]
                                as libc::c_int,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - k) as usize]
                                as libc::c_int,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - l) as usize]
                                as libc::c_int,
                        );
                        init_tb(str.as_mut_ptr());
                        l += 1;
                        l;
                    }
                    k += 1;
                    k;
                }
                j_0 += 1;
                j_0;
            }
            i_4 += 1;
            i_4;
        }
        i_4 = 0 as libc::c_int;
        while i_4 < 5 as libc::c_int {
            j_0 = i_4;
            while j_0 < 5 as libc::c_int {
                k = j_0;
                while k < 5 as libc::c_int {
                    l = 0 as libc::c_int;
                    while l < 5 as libc::c_int {
                        snprintf(
                            str.as_mut_ptr(),
                            16 as libc::c_int as libc::c_ulong,
                            b"K%c%c%cvK%c\0" as *const u8 as *const libc::c_char,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - i_4) as usize]
                                as libc::c_int,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - j_0) as usize]
                                as libc::c_int,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - k) as usize]
                                as libc::c_int,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - l) as usize]
                                as libc::c_int,
                        );
                        init_tb(str.as_mut_ptr());
                        l += 1;
                        l;
                    }
                    k += 1;
                    k;
                }
                j_0 += 1;
                j_0;
            }
            i_4 += 1;
            i_4;
        }
        i_4 = 0 as libc::c_int;
        while i_4 < 5 as libc::c_int {
            j_0 = i_4;
            while j_0 < 5 as libc::c_int {
                k = j_0;
                while k < 5 as libc::c_int {
                    l = k;
                    while l < 5 as libc::c_int {
                        snprintf(
                            str.as_mut_ptr(),
                            16 as libc::c_int as libc::c_ulong,
                            b"K%c%c%c%cvK\0" as *const u8 as *const libc::c_char,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - i_4) as usize]
                                as libc::c_int,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - j_0) as usize]
                                as libc::c_int,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - k) as usize]
                                as libc::c_int,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as libc::c_int - l) as usize]
                                as libc::c_int,
                        );
                        init_tb(str.as_mut_ptr());
                        l += 1;
                        l;
                    }
                    k += 1;
                    k;
                }
                j_0 += 1;
                j_0;
            }
            i_4 += 1;
            i_4;
        }
        if !((7 as libc::c_int) < 7 as libc::c_int) {
            i_4 = 0 as libc::c_int;
            while i_4 < 5 as libc::c_int {
                j_0 = i_4;
                while j_0 < 5 as libc::c_int {
                    k = j_0;
                    while k < 5 as libc::c_int {
                        l = k;
                        while l < 5 as libc::c_int {
                            m = l;
                            while m < 5 as libc::c_int {
                                snprintf(
                                    str.as_mut_ptr(),
                                    16 as libc::c_int as libc::c_ulong,
                                    b"K%c%c%c%c%cvK\0" as *const u8 as *const libc::c_char,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - i_4) as usize]
                                        as libc::c_int,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - j_0) as usize]
                                        as libc::c_int,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - k) as usize]
                                        as libc::c_int,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - l) as usize]
                                        as libc::c_int,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - m) as usize]
                                        as libc::c_int,
                                );
                                init_tb(str.as_mut_ptr());
                                m += 1;
                                m;
                            }
                            l += 1;
                            l;
                        }
                        k += 1;
                        k;
                    }
                    j_0 += 1;
                    j_0;
                }
                i_4 += 1;
                i_4;
            }
            i_4 = 0 as libc::c_int;
            while i_4 < 5 as libc::c_int {
                j_0 = i_4;
                while j_0 < 5 as libc::c_int {
                    k = j_0;
                    while k < 5 as libc::c_int {
                        l = k;
                        while l < 5 as libc::c_int {
                            m = 0 as libc::c_int;
                            while m < 5 as libc::c_int {
                                snprintf(
                                    str.as_mut_ptr(),
                                    16 as libc::c_int as libc::c_ulong,
                                    b"K%c%c%c%cvK%c\0" as *const u8 as *const libc::c_char,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - i_4) as usize]
                                        as libc::c_int,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - j_0) as usize]
                                        as libc::c_int,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - k) as usize]
                                        as libc::c_int,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - l) as usize]
                                        as libc::c_int,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - m) as usize]
                                        as libc::c_int,
                                );
                                init_tb(str.as_mut_ptr());
                                m += 1;
                                m;
                            }
                            l += 1;
                            l;
                        }
                        k += 1;
                        k;
                    }
                    j_0 += 1;
                    j_0;
                }
                i_4 += 1;
                i_4;
            }
            i_4 = 0 as libc::c_int;
            while i_4 < 5 as libc::c_int {
                j_0 = i_4;
                while j_0 < 5 as libc::c_int {
                    k = j_0;
                    while k < 5 as libc::c_int {
                        l = 0 as libc::c_int;
                        while l < 5 as libc::c_int {
                            m = l;
                            while m < 5 as libc::c_int {
                                snprintf(
                                    str.as_mut_ptr(),
                                    16 as libc::c_int as libc::c_ulong,
                                    b"K%c%c%cvK%c%c\0" as *const u8 as *const libc::c_char,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - i_4) as usize]
                                        as libc::c_int,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - j_0) as usize]
                                        as libc::c_int,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - k) as usize]
                                        as libc::c_int,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - l) as usize]
                                        as libc::c_int,
                                    pyrrhic_piece_to_char
                                        [(PYRRHIC_QUEEN as libc::c_int - m) as usize]
                                        as libc::c_int,
                                );
                                init_tb(str.as_mut_ptr());
                                m += 1;
                                m;
                            }
                            l += 1;
                            l;
                        }
                        k += 1;
                        k;
                    }
                    j_0 += 1;
                    j_0;
                }
                i_4 += 1;
                i_4;
            }
        }
    }
    TB_LARGEST = TB_MaxCardinality;
    if TB_MaxCardinalityDTM > TB_LARGEST {
        TB_LARGEST = TB_MaxCardinalityDTM;
    }
    TB_NUM_WDL = numWdl;
    TB_NUM_DTZ = numDtz;
    TB_NUM_DTM = numDtm;
    return 1 as libc::c_int != 0;
}
#[no_mangle]
pub unsafe extern "C" fn tb_free() {
    tb_init(b"\0" as *const u8 as *const libc::c_char);
    free(pieceEntry as *mut libc::c_void);
    free(pawnEntry as *mut libc::c_void);
}
static mut OffDiag: [int8_t; 64] = [
    0 as libc::c_int as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    1 as libc::c_int as int8_t,
    0 as libc::c_int as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    0 as libc::c_int as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    0 as libc::c_int as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    0 as libc::c_int as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    0 as libc::c_int as int8_t,
    -(1 as libc::c_int) as int8_t,
    -(1 as libc::c_int) as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    0 as libc::c_int as int8_t,
    -(1 as libc::c_int) as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    1 as libc::c_int as int8_t,
    0 as libc::c_int as int8_t,
];
static mut Triangle: [uint8_t; 64] = [
    6 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
];
static mut FlipDiag: [uint8_t; 64] = [
    0 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    16 as libc::c_int as uint8_t,
    24 as libc::c_int as uint8_t,
    32 as libc::c_int as uint8_t,
    40 as libc::c_int as uint8_t,
    48 as libc::c_int as uint8_t,
    56 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    17 as libc::c_int as uint8_t,
    25 as libc::c_int as uint8_t,
    33 as libc::c_int as uint8_t,
    41 as libc::c_int as uint8_t,
    49 as libc::c_int as uint8_t,
    57 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    18 as libc::c_int as uint8_t,
    26 as libc::c_int as uint8_t,
    34 as libc::c_int as uint8_t,
    42 as libc::c_int as uint8_t,
    50 as libc::c_int as uint8_t,
    58 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    19 as libc::c_int as uint8_t,
    27 as libc::c_int as uint8_t,
    35 as libc::c_int as uint8_t,
    43 as libc::c_int as uint8_t,
    51 as libc::c_int as uint8_t,
    59 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    20 as libc::c_int as uint8_t,
    28 as libc::c_int as uint8_t,
    36 as libc::c_int as uint8_t,
    44 as libc::c_int as uint8_t,
    52 as libc::c_int as uint8_t,
    60 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    21 as libc::c_int as uint8_t,
    29 as libc::c_int as uint8_t,
    37 as libc::c_int as uint8_t,
    45 as libc::c_int as uint8_t,
    53 as libc::c_int as uint8_t,
    61 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    22 as libc::c_int as uint8_t,
    30 as libc::c_int as uint8_t,
    38 as libc::c_int as uint8_t,
    46 as libc::c_int as uint8_t,
    54 as libc::c_int as uint8_t,
    62 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    23 as libc::c_int as uint8_t,
    31 as libc::c_int as uint8_t,
    39 as libc::c_int as uint8_t,
    47 as libc::c_int as uint8_t,
    55 as libc::c_int as uint8_t,
    63 as libc::c_int as uint8_t,
];
static mut Lower: [uint8_t; 64] = [
    28 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    29 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
    30 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    16 as libc::c_int as uint8_t,
    17 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    31 as libc::c_int as uint8_t,
    18 as libc::c_int as uint8_t,
    19 as libc::c_int as uint8_t,
    20 as libc::c_int as uint8_t,
    21 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    18 as libc::c_int as uint8_t,
    32 as libc::c_int as uint8_t,
    22 as libc::c_int as uint8_t,
    23 as libc::c_int as uint8_t,
    24 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    19 as libc::c_int as uint8_t,
    22 as libc::c_int as uint8_t,
    33 as libc::c_int as uint8_t,
    25 as libc::c_int as uint8_t,
    26 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    16 as libc::c_int as uint8_t,
    20 as libc::c_int as uint8_t,
    23 as libc::c_int as uint8_t,
    25 as libc::c_int as uint8_t,
    34 as libc::c_int as uint8_t,
    27 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    17 as libc::c_int as uint8_t,
    21 as libc::c_int as uint8_t,
    24 as libc::c_int as uint8_t,
    26 as libc::c_int as uint8_t,
    27 as libc::c_int as uint8_t,
    35 as libc::c_int as uint8_t,
];
static mut Diag: [uint8_t; 64] = [
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    8 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    9 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    10 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    11 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    12 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    13 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    5 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    14 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    6 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    15 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    7 as libc::c_int as uint8_t,
];
static mut Flap: [[uint8_t; 64]; 2] = [
    [
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        6 as libc::c_int as uint8_t,
        12 as libc::c_int as uint8_t,
        18 as libc::c_int as uint8_t,
        18 as libc::c_int as uint8_t,
        12 as libc::c_int as uint8_t,
        6 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        7 as libc::c_int as uint8_t,
        13 as libc::c_int as uint8_t,
        19 as libc::c_int as uint8_t,
        19 as libc::c_int as uint8_t,
        13 as libc::c_int as uint8_t,
        7 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        8 as libc::c_int as uint8_t,
        14 as libc::c_int as uint8_t,
        20 as libc::c_int as uint8_t,
        20 as libc::c_int as uint8_t,
        14 as libc::c_int as uint8_t,
        8 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
        9 as libc::c_int as uint8_t,
        15 as libc::c_int as uint8_t,
        21 as libc::c_int as uint8_t,
        21 as libc::c_int as uint8_t,
        15 as libc::c_int as uint8_t,
        9 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
        4 as libc::c_int as uint8_t,
        10 as libc::c_int as uint8_t,
        16 as libc::c_int as uint8_t,
        22 as libc::c_int as uint8_t,
        22 as libc::c_int as uint8_t,
        16 as libc::c_int as uint8_t,
        10 as libc::c_int as uint8_t,
        4 as libc::c_int as uint8_t,
        5 as libc::c_int as uint8_t,
        11 as libc::c_int as uint8_t,
        17 as libc::c_int as uint8_t,
        23 as libc::c_int as uint8_t,
        23 as libc::c_int as uint8_t,
        17 as libc::c_int as uint8_t,
        11 as libc::c_int as uint8_t,
        5 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
    ],
    [
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        4 as libc::c_int as uint8_t,
        5 as libc::c_int as uint8_t,
        6 as libc::c_int as uint8_t,
        7 as libc::c_int as uint8_t,
        7 as libc::c_int as uint8_t,
        6 as libc::c_int as uint8_t,
        5 as libc::c_int as uint8_t,
        4 as libc::c_int as uint8_t,
        8 as libc::c_int as uint8_t,
        9 as libc::c_int as uint8_t,
        10 as libc::c_int as uint8_t,
        11 as libc::c_int as uint8_t,
        11 as libc::c_int as uint8_t,
        10 as libc::c_int as uint8_t,
        9 as libc::c_int as uint8_t,
        8 as libc::c_int as uint8_t,
        12 as libc::c_int as uint8_t,
        13 as libc::c_int as uint8_t,
        14 as libc::c_int as uint8_t,
        15 as libc::c_int as uint8_t,
        15 as libc::c_int as uint8_t,
        14 as libc::c_int as uint8_t,
        13 as libc::c_int as uint8_t,
        12 as libc::c_int as uint8_t,
        16 as libc::c_int as uint8_t,
        17 as libc::c_int as uint8_t,
        18 as libc::c_int as uint8_t,
        19 as libc::c_int as uint8_t,
        19 as libc::c_int as uint8_t,
        18 as libc::c_int as uint8_t,
        17 as libc::c_int as uint8_t,
        16 as libc::c_int as uint8_t,
        20 as libc::c_int as uint8_t,
        21 as libc::c_int as uint8_t,
        22 as libc::c_int as uint8_t,
        23 as libc::c_int as uint8_t,
        23 as libc::c_int as uint8_t,
        22 as libc::c_int as uint8_t,
        21 as libc::c_int as uint8_t,
        20 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
    ],
];
static mut PawnTwist: [[uint8_t; 64]; 2] = [
    [
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        47 as libc::c_int as uint8_t,
        35 as libc::c_int as uint8_t,
        23 as libc::c_int as uint8_t,
        11 as libc::c_int as uint8_t,
        10 as libc::c_int as uint8_t,
        22 as libc::c_int as uint8_t,
        34 as libc::c_int as uint8_t,
        46 as libc::c_int as uint8_t,
        45 as libc::c_int as uint8_t,
        33 as libc::c_int as uint8_t,
        21 as libc::c_int as uint8_t,
        9 as libc::c_int as uint8_t,
        8 as libc::c_int as uint8_t,
        20 as libc::c_int as uint8_t,
        32 as libc::c_int as uint8_t,
        44 as libc::c_int as uint8_t,
        43 as libc::c_int as uint8_t,
        31 as libc::c_int as uint8_t,
        19 as libc::c_int as uint8_t,
        7 as libc::c_int as uint8_t,
        6 as libc::c_int as uint8_t,
        18 as libc::c_int as uint8_t,
        30 as libc::c_int as uint8_t,
        42 as libc::c_int as uint8_t,
        41 as libc::c_int as uint8_t,
        29 as libc::c_int as uint8_t,
        17 as libc::c_int as uint8_t,
        5 as libc::c_int as uint8_t,
        4 as libc::c_int as uint8_t,
        16 as libc::c_int as uint8_t,
        28 as libc::c_int as uint8_t,
        40 as libc::c_int as uint8_t,
        39 as libc::c_int as uint8_t,
        27 as libc::c_int as uint8_t,
        15 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        14 as libc::c_int as uint8_t,
        26 as libc::c_int as uint8_t,
        38 as libc::c_int as uint8_t,
        37 as libc::c_int as uint8_t,
        25 as libc::c_int as uint8_t,
        13 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        12 as libc::c_int as uint8_t,
        24 as libc::c_int as uint8_t,
        36 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
    ],
    [
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        47 as libc::c_int as uint8_t,
        45 as libc::c_int as uint8_t,
        43 as libc::c_int as uint8_t,
        41 as libc::c_int as uint8_t,
        40 as libc::c_int as uint8_t,
        42 as libc::c_int as uint8_t,
        44 as libc::c_int as uint8_t,
        46 as libc::c_int as uint8_t,
        39 as libc::c_int as uint8_t,
        37 as libc::c_int as uint8_t,
        35 as libc::c_int as uint8_t,
        33 as libc::c_int as uint8_t,
        32 as libc::c_int as uint8_t,
        34 as libc::c_int as uint8_t,
        36 as libc::c_int as uint8_t,
        38 as libc::c_int as uint8_t,
        31 as libc::c_int as uint8_t,
        29 as libc::c_int as uint8_t,
        27 as libc::c_int as uint8_t,
        25 as libc::c_int as uint8_t,
        24 as libc::c_int as uint8_t,
        26 as libc::c_int as uint8_t,
        28 as libc::c_int as uint8_t,
        30 as libc::c_int as uint8_t,
        23 as libc::c_int as uint8_t,
        21 as libc::c_int as uint8_t,
        19 as libc::c_int as uint8_t,
        17 as libc::c_int as uint8_t,
        16 as libc::c_int as uint8_t,
        18 as libc::c_int as uint8_t,
        20 as libc::c_int as uint8_t,
        22 as libc::c_int as uint8_t,
        15 as libc::c_int as uint8_t,
        13 as libc::c_int as uint8_t,
        11 as libc::c_int as uint8_t,
        9 as libc::c_int as uint8_t,
        8 as libc::c_int as uint8_t,
        10 as libc::c_int as uint8_t,
        12 as libc::c_int as uint8_t,
        14 as libc::c_int as uint8_t,
        7 as libc::c_int as uint8_t,
        5 as libc::c_int as uint8_t,
        3 as libc::c_int as uint8_t,
        1 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        2 as libc::c_int as uint8_t,
        4 as libc::c_int as uint8_t,
        6 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
    ],
];
static mut KKIdx: [[int16_t; 64]; 10] = [
    [
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        0 as libc::c_int as int16_t,
        1 as libc::c_int as int16_t,
        2 as libc::c_int as int16_t,
        3 as libc::c_int as int16_t,
        4 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        5 as libc::c_int as int16_t,
        6 as libc::c_int as int16_t,
        7 as libc::c_int as int16_t,
        8 as libc::c_int as int16_t,
        9 as libc::c_int as int16_t,
        10 as libc::c_int as int16_t,
        11 as libc::c_int as int16_t,
        12 as libc::c_int as int16_t,
        13 as libc::c_int as int16_t,
        14 as libc::c_int as int16_t,
        15 as libc::c_int as int16_t,
        16 as libc::c_int as int16_t,
        17 as libc::c_int as int16_t,
        18 as libc::c_int as int16_t,
        19 as libc::c_int as int16_t,
        20 as libc::c_int as int16_t,
        21 as libc::c_int as int16_t,
        22 as libc::c_int as int16_t,
        23 as libc::c_int as int16_t,
        24 as libc::c_int as int16_t,
        25 as libc::c_int as int16_t,
        26 as libc::c_int as int16_t,
        27 as libc::c_int as int16_t,
        28 as libc::c_int as int16_t,
        29 as libc::c_int as int16_t,
        30 as libc::c_int as int16_t,
        31 as libc::c_int as int16_t,
        32 as libc::c_int as int16_t,
        33 as libc::c_int as int16_t,
        34 as libc::c_int as int16_t,
        35 as libc::c_int as int16_t,
        36 as libc::c_int as int16_t,
        37 as libc::c_int as int16_t,
        38 as libc::c_int as int16_t,
        39 as libc::c_int as int16_t,
        40 as libc::c_int as int16_t,
        41 as libc::c_int as int16_t,
        42 as libc::c_int as int16_t,
        43 as libc::c_int as int16_t,
        44 as libc::c_int as int16_t,
        45 as libc::c_int as int16_t,
        46 as libc::c_int as int16_t,
        47 as libc::c_int as int16_t,
        48 as libc::c_int as int16_t,
        49 as libc::c_int as int16_t,
        50 as libc::c_int as int16_t,
        51 as libc::c_int as int16_t,
        52 as libc::c_int as int16_t,
        53 as libc::c_int as int16_t,
        54 as libc::c_int as int16_t,
        55 as libc::c_int as int16_t,
        56 as libc::c_int as int16_t,
        57 as libc::c_int as int16_t,
    ],
    [
        58 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        59 as libc::c_int as int16_t,
        60 as libc::c_int as int16_t,
        61 as libc::c_int as int16_t,
        62 as libc::c_int as int16_t,
        63 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        64 as libc::c_int as int16_t,
        65 as libc::c_int as int16_t,
        66 as libc::c_int as int16_t,
        67 as libc::c_int as int16_t,
        68 as libc::c_int as int16_t,
        69 as libc::c_int as int16_t,
        70 as libc::c_int as int16_t,
        71 as libc::c_int as int16_t,
        72 as libc::c_int as int16_t,
        73 as libc::c_int as int16_t,
        74 as libc::c_int as int16_t,
        75 as libc::c_int as int16_t,
        76 as libc::c_int as int16_t,
        77 as libc::c_int as int16_t,
        78 as libc::c_int as int16_t,
        79 as libc::c_int as int16_t,
        80 as libc::c_int as int16_t,
        81 as libc::c_int as int16_t,
        82 as libc::c_int as int16_t,
        83 as libc::c_int as int16_t,
        84 as libc::c_int as int16_t,
        85 as libc::c_int as int16_t,
        86 as libc::c_int as int16_t,
        87 as libc::c_int as int16_t,
        88 as libc::c_int as int16_t,
        89 as libc::c_int as int16_t,
        90 as libc::c_int as int16_t,
        91 as libc::c_int as int16_t,
        92 as libc::c_int as int16_t,
        93 as libc::c_int as int16_t,
        94 as libc::c_int as int16_t,
        95 as libc::c_int as int16_t,
        96 as libc::c_int as int16_t,
        97 as libc::c_int as int16_t,
        98 as libc::c_int as int16_t,
        99 as libc::c_int as int16_t,
        100 as libc::c_int as int16_t,
        101 as libc::c_int as int16_t,
        102 as libc::c_int as int16_t,
        103 as libc::c_int as int16_t,
        104 as libc::c_int as int16_t,
        105 as libc::c_int as int16_t,
        106 as libc::c_int as int16_t,
        107 as libc::c_int as int16_t,
        108 as libc::c_int as int16_t,
        109 as libc::c_int as int16_t,
        110 as libc::c_int as int16_t,
        111 as libc::c_int as int16_t,
        112 as libc::c_int as int16_t,
        113 as libc::c_int as int16_t,
        114 as libc::c_int as int16_t,
        115 as libc::c_int as int16_t,
    ],
    [
        116 as libc::c_int as int16_t,
        117 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        118 as libc::c_int as int16_t,
        119 as libc::c_int as int16_t,
        120 as libc::c_int as int16_t,
        121 as libc::c_int as int16_t,
        122 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        123 as libc::c_int as int16_t,
        124 as libc::c_int as int16_t,
        125 as libc::c_int as int16_t,
        126 as libc::c_int as int16_t,
        127 as libc::c_int as int16_t,
        128 as libc::c_int as int16_t,
        129 as libc::c_int as int16_t,
        130 as libc::c_int as int16_t,
        131 as libc::c_int as int16_t,
        132 as libc::c_int as int16_t,
        133 as libc::c_int as int16_t,
        134 as libc::c_int as int16_t,
        135 as libc::c_int as int16_t,
        136 as libc::c_int as int16_t,
        137 as libc::c_int as int16_t,
        138 as libc::c_int as int16_t,
        139 as libc::c_int as int16_t,
        140 as libc::c_int as int16_t,
        141 as libc::c_int as int16_t,
        142 as libc::c_int as int16_t,
        143 as libc::c_int as int16_t,
        144 as libc::c_int as int16_t,
        145 as libc::c_int as int16_t,
        146 as libc::c_int as int16_t,
        147 as libc::c_int as int16_t,
        148 as libc::c_int as int16_t,
        149 as libc::c_int as int16_t,
        150 as libc::c_int as int16_t,
        151 as libc::c_int as int16_t,
        152 as libc::c_int as int16_t,
        153 as libc::c_int as int16_t,
        154 as libc::c_int as int16_t,
        155 as libc::c_int as int16_t,
        156 as libc::c_int as int16_t,
        157 as libc::c_int as int16_t,
        158 as libc::c_int as int16_t,
        159 as libc::c_int as int16_t,
        160 as libc::c_int as int16_t,
        161 as libc::c_int as int16_t,
        162 as libc::c_int as int16_t,
        163 as libc::c_int as int16_t,
        164 as libc::c_int as int16_t,
        165 as libc::c_int as int16_t,
        166 as libc::c_int as int16_t,
        167 as libc::c_int as int16_t,
        168 as libc::c_int as int16_t,
        169 as libc::c_int as int16_t,
        170 as libc::c_int as int16_t,
        171 as libc::c_int as int16_t,
        172 as libc::c_int as int16_t,
        173 as libc::c_int as int16_t,
    ],
    [
        174 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        175 as libc::c_int as int16_t,
        176 as libc::c_int as int16_t,
        177 as libc::c_int as int16_t,
        178 as libc::c_int as int16_t,
        179 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        180 as libc::c_int as int16_t,
        181 as libc::c_int as int16_t,
        182 as libc::c_int as int16_t,
        183 as libc::c_int as int16_t,
        184 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        185 as libc::c_int as int16_t,
        186 as libc::c_int as int16_t,
        187 as libc::c_int as int16_t,
        188 as libc::c_int as int16_t,
        189 as libc::c_int as int16_t,
        190 as libc::c_int as int16_t,
        191 as libc::c_int as int16_t,
        192 as libc::c_int as int16_t,
        193 as libc::c_int as int16_t,
        194 as libc::c_int as int16_t,
        195 as libc::c_int as int16_t,
        196 as libc::c_int as int16_t,
        197 as libc::c_int as int16_t,
        198 as libc::c_int as int16_t,
        199 as libc::c_int as int16_t,
        200 as libc::c_int as int16_t,
        201 as libc::c_int as int16_t,
        202 as libc::c_int as int16_t,
        203 as libc::c_int as int16_t,
        204 as libc::c_int as int16_t,
        205 as libc::c_int as int16_t,
        206 as libc::c_int as int16_t,
        207 as libc::c_int as int16_t,
        208 as libc::c_int as int16_t,
        209 as libc::c_int as int16_t,
        210 as libc::c_int as int16_t,
        211 as libc::c_int as int16_t,
        212 as libc::c_int as int16_t,
        213 as libc::c_int as int16_t,
        214 as libc::c_int as int16_t,
        215 as libc::c_int as int16_t,
        216 as libc::c_int as int16_t,
        217 as libc::c_int as int16_t,
        218 as libc::c_int as int16_t,
        219 as libc::c_int as int16_t,
        220 as libc::c_int as int16_t,
        221 as libc::c_int as int16_t,
        222 as libc::c_int as int16_t,
        223 as libc::c_int as int16_t,
        224 as libc::c_int as int16_t,
        225 as libc::c_int as int16_t,
        226 as libc::c_int as int16_t,
        227 as libc::c_int as int16_t,
        228 as libc::c_int as int16_t,
    ],
    [
        229 as libc::c_int as int16_t,
        230 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        231 as libc::c_int as int16_t,
        232 as libc::c_int as int16_t,
        233 as libc::c_int as int16_t,
        234 as libc::c_int as int16_t,
        235 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        236 as libc::c_int as int16_t,
        237 as libc::c_int as int16_t,
        238 as libc::c_int as int16_t,
        239 as libc::c_int as int16_t,
        240 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        241 as libc::c_int as int16_t,
        242 as libc::c_int as int16_t,
        243 as libc::c_int as int16_t,
        244 as libc::c_int as int16_t,
        245 as libc::c_int as int16_t,
        246 as libc::c_int as int16_t,
        247 as libc::c_int as int16_t,
        248 as libc::c_int as int16_t,
        249 as libc::c_int as int16_t,
        250 as libc::c_int as int16_t,
        251 as libc::c_int as int16_t,
        252 as libc::c_int as int16_t,
        253 as libc::c_int as int16_t,
        254 as libc::c_int as int16_t,
        255 as libc::c_int as int16_t,
        256 as libc::c_int as int16_t,
        257 as libc::c_int as int16_t,
        258 as libc::c_int as int16_t,
        259 as libc::c_int as int16_t,
        260 as libc::c_int as int16_t,
        261 as libc::c_int as int16_t,
        262 as libc::c_int as int16_t,
        263 as libc::c_int as int16_t,
        264 as libc::c_int as int16_t,
        265 as libc::c_int as int16_t,
        266 as libc::c_int as int16_t,
        267 as libc::c_int as int16_t,
        268 as libc::c_int as int16_t,
        269 as libc::c_int as int16_t,
        270 as libc::c_int as int16_t,
        271 as libc::c_int as int16_t,
        272 as libc::c_int as int16_t,
        273 as libc::c_int as int16_t,
        274 as libc::c_int as int16_t,
        275 as libc::c_int as int16_t,
        276 as libc::c_int as int16_t,
        277 as libc::c_int as int16_t,
        278 as libc::c_int as int16_t,
        279 as libc::c_int as int16_t,
        280 as libc::c_int as int16_t,
        281 as libc::c_int as int16_t,
        282 as libc::c_int as int16_t,
        283 as libc::c_int as int16_t,
    ],
    [
        284 as libc::c_int as int16_t,
        285 as libc::c_int as int16_t,
        286 as libc::c_int as int16_t,
        287 as libc::c_int as int16_t,
        288 as libc::c_int as int16_t,
        289 as libc::c_int as int16_t,
        290 as libc::c_int as int16_t,
        291 as libc::c_int as int16_t,
        292 as libc::c_int as int16_t,
        293 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        294 as libc::c_int as int16_t,
        295 as libc::c_int as int16_t,
        296 as libc::c_int as int16_t,
        297 as libc::c_int as int16_t,
        298 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        299 as libc::c_int as int16_t,
        300 as libc::c_int as int16_t,
        301 as libc::c_int as int16_t,
        302 as libc::c_int as int16_t,
        303 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        304 as libc::c_int as int16_t,
        305 as libc::c_int as int16_t,
        306 as libc::c_int as int16_t,
        307 as libc::c_int as int16_t,
        308 as libc::c_int as int16_t,
        309 as libc::c_int as int16_t,
        310 as libc::c_int as int16_t,
        311 as libc::c_int as int16_t,
        312 as libc::c_int as int16_t,
        313 as libc::c_int as int16_t,
        314 as libc::c_int as int16_t,
        315 as libc::c_int as int16_t,
        316 as libc::c_int as int16_t,
        317 as libc::c_int as int16_t,
        318 as libc::c_int as int16_t,
        319 as libc::c_int as int16_t,
        320 as libc::c_int as int16_t,
        321 as libc::c_int as int16_t,
        322 as libc::c_int as int16_t,
        323 as libc::c_int as int16_t,
        324 as libc::c_int as int16_t,
        325 as libc::c_int as int16_t,
        326 as libc::c_int as int16_t,
        327 as libc::c_int as int16_t,
        328 as libc::c_int as int16_t,
        329 as libc::c_int as int16_t,
        330 as libc::c_int as int16_t,
        331 as libc::c_int as int16_t,
        332 as libc::c_int as int16_t,
        333 as libc::c_int as int16_t,
        334 as libc::c_int as int16_t,
        335 as libc::c_int as int16_t,
        336 as libc::c_int as int16_t,
        337 as libc::c_int as int16_t,
        338 as libc::c_int as int16_t,
    ],
    [
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        339 as libc::c_int as int16_t,
        340 as libc::c_int as int16_t,
        341 as libc::c_int as int16_t,
        342 as libc::c_int as int16_t,
        343 as libc::c_int as int16_t,
        344 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        345 as libc::c_int as int16_t,
        346 as libc::c_int as int16_t,
        347 as libc::c_int as int16_t,
        348 as libc::c_int as int16_t,
        349 as libc::c_int as int16_t,
        350 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        441 as libc::c_int as int16_t,
        351 as libc::c_int as int16_t,
        352 as libc::c_int as int16_t,
        353 as libc::c_int as int16_t,
        354 as libc::c_int as int16_t,
        355 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        442 as libc::c_int as int16_t,
        356 as libc::c_int as int16_t,
        357 as libc::c_int as int16_t,
        358 as libc::c_int as int16_t,
        359 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        443 as libc::c_int as int16_t,
        360 as libc::c_int as int16_t,
        361 as libc::c_int as int16_t,
        362 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        444 as libc::c_int as int16_t,
        363 as libc::c_int as int16_t,
        364 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        445 as libc::c_int as int16_t,
        365 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        446 as libc::c_int as int16_t,
    ],
    [
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        366 as libc::c_int as int16_t,
        367 as libc::c_int as int16_t,
        368 as libc::c_int as int16_t,
        369 as libc::c_int as int16_t,
        370 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        371 as libc::c_int as int16_t,
        372 as libc::c_int as int16_t,
        373 as libc::c_int as int16_t,
        374 as libc::c_int as int16_t,
        375 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        376 as libc::c_int as int16_t,
        377 as libc::c_int as int16_t,
        378 as libc::c_int as int16_t,
        379 as libc::c_int as int16_t,
        380 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        447 as libc::c_int as int16_t,
        381 as libc::c_int as int16_t,
        382 as libc::c_int as int16_t,
        383 as libc::c_int as int16_t,
        384 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        448 as libc::c_int as int16_t,
        385 as libc::c_int as int16_t,
        386 as libc::c_int as int16_t,
        387 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        449 as libc::c_int as int16_t,
        388 as libc::c_int as int16_t,
        389 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        450 as libc::c_int as int16_t,
        390 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        451 as libc::c_int as int16_t,
    ],
    [
        452 as libc::c_int as int16_t,
        391 as libc::c_int as int16_t,
        392 as libc::c_int as int16_t,
        393 as libc::c_int as int16_t,
        394 as libc::c_int as int16_t,
        395 as libc::c_int as int16_t,
        396 as libc::c_int as int16_t,
        397 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        398 as libc::c_int as int16_t,
        399 as libc::c_int as int16_t,
        400 as libc::c_int as int16_t,
        401 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        402 as libc::c_int as int16_t,
        403 as libc::c_int as int16_t,
        404 as libc::c_int as int16_t,
        405 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        406 as libc::c_int as int16_t,
        407 as libc::c_int as int16_t,
        408 as libc::c_int as int16_t,
        409 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        453 as libc::c_int as int16_t,
        410 as libc::c_int as int16_t,
        411 as libc::c_int as int16_t,
        412 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        454 as libc::c_int as int16_t,
        413 as libc::c_int as int16_t,
        414 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        455 as libc::c_int as int16_t,
        415 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        456 as libc::c_int as int16_t,
    ],
    [
        457 as libc::c_int as int16_t,
        416 as libc::c_int as int16_t,
        417 as libc::c_int as int16_t,
        418 as libc::c_int as int16_t,
        419 as libc::c_int as int16_t,
        420 as libc::c_int as int16_t,
        421 as libc::c_int as int16_t,
        422 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        458 as libc::c_int as int16_t,
        423 as libc::c_int as int16_t,
        424 as libc::c_int as int16_t,
        425 as libc::c_int as int16_t,
        426 as libc::c_int as int16_t,
        427 as libc::c_int as int16_t,
        428 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        429 as libc::c_int as int16_t,
        430 as libc::c_int as int16_t,
        431 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        432 as libc::c_int as int16_t,
        433 as libc::c_int as int16_t,
        434 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        435 as libc::c_int as int16_t,
        436 as libc::c_int as int16_t,
        437 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        459 as libc::c_int as int16_t,
        438 as libc::c_int as int16_t,
        439 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        460 as libc::c_int as int16_t,
        440 as libc::c_int as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        -(1 as libc::c_int) as int16_t,
        461 as libc::c_int as int16_t,
    ],
];
static mut FileToFile: [uint8_t; 8] = [
    0 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    3 as libc::c_int as uint8_t,
    2 as libc::c_int as uint8_t,
    1 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
];
static mut WdlToMap: [libc::c_int; 5] = [
    1 as libc::c_int,
    3 as libc::c_int,
    0 as libc::c_int,
    2 as libc::c_int,
    0 as libc::c_int,
];
static mut PAFlags: [uint8_t; 5] = [
    8 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    4 as libc::c_int as uint8_t,
];
static mut Binomial: [[size_t; 64]; 7] = [[0; 64]; 7];
static mut PawnIdx: [[[size_t; 24]; 6]; 2] = [[[0; 24]; 6]; 2];
static mut PawnFactorFile: [[size_t; 4]; 6] = [[0; 4]; 6];
static mut PawnFactorRank: [[size_t; 6]; 6] = [[0; 6]; 6];
unsafe extern "C" fn init_indices() {
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut k: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 7 as libc::c_int {
        j = 0 as libc::c_int;
        while j < 64 as libc::c_int {
            let mut f: size_t = 1 as libc::c_int as size_t;
            let mut l: size_t = 1 as libc::c_int as size_t;
            k = 0 as libc::c_int;
            while k < i {
                f = f * (j - k) as size_t;
                l = l * (k + 1 as libc::c_int) as size_t;
                k += 1;
                k;
            }
            Binomial[i as usize][j as usize] = f / l;
            j += 1;
            j;
        }
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < 6 as libc::c_int {
        let mut s: size_t = 0 as libc::c_int as size_t;
        j = 0 as libc::c_int;
        while j < 24 as libc::c_int {
            PawnIdx[0 as libc::c_int as usize][i as usize][j as usize] = s;
            s = s.wrapping_add(
                Binomial[i as usize][PawnTwist[0 as libc::c_int as usize][((1 as libc::c_int
                    + j % 6 as libc::c_int)
                    * 8 as libc::c_int
                    + j / 6 as libc::c_int)
                    as usize] as usize],
            );
            if (j + 1 as libc::c_int) % 6 as libc::c_int == 0 as libc::c_int {
                PawnFactorFile[i as usize][(j / 6 as libc::c_int) as usize] = s;
                s = 0 as libc::c_int as size_t;
            }
            j += 1;
            j;
        }
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < 6 as libc::c_int {
        let mut s_0: size_t = 0 as libc::c_int as size_t;
        j = 0 as libc::c_int;
        while j < 24 as libc::c_int {
            PawnIdx[1 as libc::c_int as usize][i as usize][j as usize] = s_0;
            s_0 = s_0.wrapping_add(
                Binomial[i as usize][PawnTwist[1 as libc::c_int as usize][((1 as libc::c_int
                    + j / 4 as libc::c_int)
                    * 8 as libc::c_int
                    + j % 4 as libc::c_int)
                    as usize] as usize],
            );
            if (j + 1 as libc::c_int) % 4 as libc::c_int == 0 as libc::c_int {
                PawnFactorRank[i as usize][(j / 4 as libc::c_int) as usize] = s_0;
                s_0 = 0 as libc::c_int as size_t;
            }
            j += 1;
            j;
        }
        i += 1;
        i;
    }
}
#[no_mangle]
pub unsafe extern "C" fn leading_pawn(
    mut p: *mut libc::c_int,
    mut be: *mut BaseEntry,
    enc: libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 1 as libc::c_int;
    while i < (*be).c2rust_unnamed.pawns[0 as libc::c_int as usize] as libc::c_int {
        if Flap[(enc - 1 as libc::c_int) as usize][*p.offset(0 as libc::c_int as isize) as usize]
            as libc::c_int
            > Flap[(enc - 1 as libc::c_int) as usize][*p.offset(i as isize) as usize] as libc::c_int
        {
            let mut tmp: libc::c_int = *p.offset(0 as libc::c_int as isize);
            *p.offset(0 as libc::c_int as isize) = *p.offset(i as isize);
            *p.offset(i as isize) = tmp;
        }
        i += 1;
        i;
    }
    return if enc == FILE_ENC as libc::c_int {
        FileToFile[(*p.offset(0 as libc::c_int as isize) & 7 as libc::c_int) as usize]
            as libc::c_int
    } else {
        *p.offset(0 as libc::c_int as isize) - 8 as libc::c_int >> 3 as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn encode(
    mut p: *mut libc::c_int,
    mut ei: *mut EncInfo,
    mut be: *mut BaseEntry,
    enc: libc::c_int,
) -> size_t {
    let mut n: libc::c_int = (*be).num as libc::c_int;
    let mut idx: size_t = 0;
    let mut k: libc::c_int = 0;
    if *p.offset(0 as libc::c_int as isize) & 0x4 as libc::c_int != 0 {
        let mut i: libc::c_int = 0 as libc::c_int;
        while i < n {
            *p.offset(i as isize) ^= 0x7 as libc::c_int;
            i += 1;
            i;
        }
    }
    if enc == PIECE_ENC as libc::c_int {
        if *p.offset(0 as libc::c_int as isize) & 0x20 as libc::c_int != 0 {
            let mut i_0: libc::c_int = 0 as libc::c_int;
            while i_0 < n {
                *p.offset(i_0 as isize) ^= 0x38 as libc::c_int;
                i_0 += 1;
                i_0;
            }
        }
        let mut i_1: libc::c_int = 0 as libc::c_int;
        while i_1 < n {
            if OffDiag[*p.offset(i_1 as isize) as usize] != 0 {
                if OffDiag[*p.offset(i_1 as isize) as usize] as libc::c_int > 0 as libc::c_int
                    && i_1
                        < (if (*be).c2rust_unnamed.kk_enc as libc::c_int != 0 {
                            2 as libc::c_int
                        } else {
                            3 as libc::c_int
                        })
                {
                    let mut j: libc::c_int = 0 as libc::c_int;
                    while j < n {
                        *p.offset(j as isize) =
                            FlipDiag[*p.offset(j as isize) as usize] as libc::c_int;
                        j += 1;
                        j;
                    }
                }
                break;
            } else {
                i_1 += 1;
                i_1;
            }
        }
        if (*be).c2rust_unnamed.kk_enc {
            idx = KKIdx[Triangle[*p.offset(0 as libc::c_int as isize) as usize] as usize]
                [*p.offset(1 as libc::c_int as isize) as usize] as size_t;
            k = 2 as libc::c_int;
        } else {
            let mut s1: libc::c_int = (*p.offset(1 as libc::c_int as isize)
                > *p.offset(0 as libc::c_int as isize))
                as libc::c_int;
            let mut s2: libc::c_int = (*p.offset(2 as libc::c_int as isize)
                > *p.offset(0 as libc::c_int as isize))
                as libc::c_int
                + (*p.offset(2 as libc::c_int as isize) > *p.offset(1 as libc::c_int as isize))
                    as libc::c_int;
            if OffDiag[*p.offset(0 as libc::c_int as isize) as usize] != 0 {
                idx = (Triangle[*p.offset(0 as libc::c_int as isize) as usize] as libc::c_int
                    * 63 as libc::c_int
                    * 62 as libc::c_int
                    + (*p.offset(1 as libc::c_int as isize) - s1) * 62 as libc::c_int
                    + (*p.offset(2 as libc::c_int as isize) - s2)) as size_t;
            } else if OffDiag[*p.offset(1 as libc::c_int as isize) as usize] != 0 {
                idx = (6 as libc::c_int * 63 as libc::c_int * 62 as libc::c_int
                    + Diag[*p.offset(0 as libc::c_int as isize) as usize] as libc::c_int
                        * 28 as libc::c_int
                        * 62 as libc::c_int
                    + Lower[*p.offset(1 as libc::c_int as isize) as usize] as libc::c_int
                        * 62 as libc::c_int
                    + *p.offset(2 as libc::c_int as isize)
                    - s2) as size_t;
            } else if OffDiag[*p.offset(2 as libc::c_int as isize) as usize] != 0 {
                idx = (6 as libc::c_int * 63 as libc::c_int * 62 as libc::c_int
                    + 4 as libc::c_int * 28 as libc::c_int * 62 as libc::c_int
                    + Diag[*p.offset(0 as libc::c_int as isize) as usize] as libc::c_int
                        * 7 as libc::c_int
                        * 28 as libc::c_int
                    + (Diag[*p.offset(1 as libc::c_int as isize) as usize] as libc::c_int - s1)
                        * 28 as libc::c_int
                    + Lower[*p.offset(2 as libc::c_int as isize) as usize] as libc::c_int)
                    as size_t;
            } else {
                idx = (6 as libc::c_int * 63 as libc::c_int * 62 as libc::c_int
                    + 4 as libc::c_int * 28 as libc::c_int * 62 as libc::c_int
                    + 4 as libc::c_int * 7 as libc::c_int * 28 as libc::c_int
                    + Diag[*p.offset(0 as libc::c_int as isize) as usize] as libc::c_int
                        * 7 as libc::c_int
                        * 6 as libc::c_int
                    + (Diag[*p.offset(1 as libc::c_int as isize) as usize] as libc::c_int - s1)
                        * 6 as libc::c_int
                    + (Diag[*p.offset(2 as libc::c_int as isize) as usize] as libc::c_int - s2))
                    as size_t;
            }
            k = 3 as libc::c_int;
        }
        idx = idx * (*ei).factor[0 as libc::c_int as usize];
    } else {
        let mut i_2: libc::c_int = 1 as libc::c_int;
        while i_2 < (*be).c2rust_unnamed.pawns[0 as libc::c_int as usize] as libc::c_int {
            let mut j_0: libc::c_int = i_2 + 1 as libc::c_int;
            while j_0 < (*be).c2rust_unnamed.pawns[0 as libc::c_int as usize] as libc::c_int {
                if (PawnTwist[(enc - 1 as libc::c_int) as usize][*p.offset(i_2 as isize) as usize]
                    as libc::c_int)
                    < PawnTwist[(enc - 1 as libc::c_int) as usize][*p.offset(j_0 as isize) as usize]
                        as libc::c_int
                {
                    let mut tmp: libc::c_int = *p.offset(i_2 as isize);
                    *p.offset(i_2 as isize) = *p.offset(j_0 as isize);
                    *p.offset(j_0 as isize) = tmp;
                }
                j_0 += 1;
                j_0;
            }
            i_2 += 1;
            i_2;
        }
        k = (*be).c2rust_unnamed.pawns[0 as libc::c_int as usize] as libc::c_int;
        idx = PawnIdx[(enc - 1 as libc::c_int) as usize][(k - 1 as libc::c_int) as usize][Flap
            [(enc - 1 as libc::c_int) as usize][*p.offset(0 as libc::c_int as isize) as usize]
            as usize];
        let mut i_3: libc::c_int = 1 as libc::c_int;
        while i_3 < k {
            idx = idx.wrapping_add(
                Binomial[(k - i_3) as usize][PawnTwist[(enc - 1 as libc::c_int) as usize]
                    [*p.offset(i_3 as isize) as usize]
                    as usize],
            );
            i_3 += 1;
            i_3;
        }
        idx = idx * (*ei).factor[0 as libc::c_int as usize];
        if (*be).c2rust_unnamed.pawns[1 as libc::c_int as usize] != 0 {
            let mut t: libc::c_int =
                k + (*be).c2rust_unnamed.pawns[1 as libc::c_int as usize] as libc::c_int;
            let mut i_4: libc::c_int = k;
            while i_4 < t {
                let mut j_1: libc::c_int = i_4 + 1 as libc::c_int;
                while j_1 < t {
                    if *p.offset(i_4 as isize) > *p.offset(j_1 as isize) {
                        let mut tmp_0: libc::c_int = *p.offset(i_4 as isize);
                        *p.offset(i_4 as isize) = *p.offset(j_1 as isize);
                        *p.offset(j_1 as isize) = tmp_0;
                    }
                    j_1 += 1;
                    j_1;
                }
                i_4 += 1;
                i_4;
            }
            let mut s: size_t = 0 as libc::c_int as size_t;
            let mut i_5: libc::c_int = k;
            while i_5 < t {
                let mut sq: libc::c_int = *p.offset(i_5 as isize);
                let mut skips: libc::c_int = 0 as libc::c_int;
                let mut j_2: libc::c_int = 0 as libc::c_int;
                while j_2 < k {
                    skips += (sq > *p.offset(j_2 as isize)) as libc::c_int;
                    j_2 += 1;
                    j_2;
                }
                s = s.wrapping_add(
                    Binomial[(i_5 - k + 1 as libc::c_int) as usize]
                        [(sq - skips - 8 as libc::c_int) as usize],
                );
                i_5 += 1;
                i_5;
            }
            idx = idx.wrapping_add(s * (*ei).factor[k as usize]);
            k = t;
        }
    }
    while k < n {
        let mut t_0: libc::c_int = k + (*ei).norm[k as usize] as libc::c_int;
        let mut i_6: libc::c_int = k;
        while i_6 < t_0 {
            let mut j_3: libc::c_int = i_6 + 1 as libc::c_int;
            while j_3 < t_0 {
                if *p.offset(i_6 as isize) > *p.offset(j_3 as isize) {
                    let mut tmp_1: libc::c_int = *p.offset(i_6 as isize);
                    *p.offset(i_6 as isize) = *p.offset(j_3 as isize);
                    *p.offset(j_3 as isize) = tmp_1;
                }
                j_3 += 1;
                j_3;
            }
            i_6 += 1;
            i_6;
        }
        let mut s_0: size_t = 0 as libc::c_int as size_t;
        let mut i_7: libc::c_int = k;
        while i_7 < t_0 {
            let mut sq_0: libc::c_int = *p.offset(i_7 as isize);
            let mut skips_0: libc::c_int = 0 as libc::c_int;
            let mut j_4: libc::c_int = 0 as libc::c_int;
            while j_4 < k {
                skips_0 += (sq_0 > *p.offset(j_4 as isize)) as libc::c_int;
                j_4 += 1;
                j_4;
            }
            s_0 = s_0.wrapping_add(
                Binomial[(i_7 - k + 1 as libc::c_int) as usize][(sq_0 - skips_0) as usize],
            );
            i_7 += 1;
            i_7;
        }
        idx = idx.wrapping_add(s_0 * (*ei).factor[k as usize]);
        k = t_0;
    }
    return idx;
}
unsafe extern "C" fn encode_piece(
    mut p: *mut libc::c_int,
    mut ei: *mut EncInfo,
    mut be: *mut BaseEntry,
) -> size_t {
    return encode(p, ei, be, PIECE_ENC as libc::c_int);
}
unsafe extern "C" fn encode_pawn_f(
    mut p: *mut libc::c_int,
    mut ei: *mut EncInfo,
    mut be: *mut BaseEntry,
) -> size_t {
    return encode(p, ei, be, FILE_ENC as libc::c_int);
}
unsafe extern "C" fn encode_pawn_r(
    mut p: *mut libc::c_int,
    mut ei: *mut EncInfo,
    mut be: *mut BaseEntry,
) -> size_t {
    return encode(p, ei, be, RANK_ENC as libc::c_int);
}
unsafe extern "C" fn subfactor(mut k: size_t, mut n: size_t) -> size_t {
    let mut f: size_t = n;
    let mut l: size_t = 1 as libc::c_int as size_t;
    let mut i: size_t = 1 as libc::c_int as size_t;
    while i < k {
        f = f * n.wrapping_sub(i);
        l = l * i.wrapping_add(1 as libc::c_int as size_t);
        i = i.wrapping_add(1);
        i;
    }
    return f / l;
}
unsafe extern "C" fn init_enc_info(
    mut ei: *mut EncInfo,
    mut be: *mut BaseEntry,
    mut tb: *mut uint8_t,
    mut shift: libc::c_int,
    mut t: libc::c_int,
    enc: libc::c_int,
) -> size_t {
    let mut morePawns: bool = enc != PIECE_ENC as libc::c_int
        && (*be).c2rust_unnamed.pawns[1 as libc::c_int as usize] as libc::c_int > 0 as libc::c_int;
    let mut i: libc::c_int = 0 as libc::c_int;
    while i < (*be).num as libc::c_int {
        (*ei).pieces[i as usize] =
            (*tb.offset((i + 1 as libc::c_int + morePawns as libc::c_int) as isize) as libc::c_int
                >> shift
                & 0xf as libc::c_int) as uint8_t;
        (*ei).norm[i as usize] = 0 as libc::c_int as uint8_t;
        i += 1;
        i;
    }
    let mut order: libc::c_int =
        *tb.offset(0 as libc::c_int as isize) as libc::c_int >> shift & 0xf as libc::c_int;
    let mut order2: libc::c_int = if morePawns as libc::c_int != 0 {
        *tb.offset(1 as libc::c_int as isize) as libc::c_int >> shift & 0xf as libc::c_int
    } else {
        0xf as libc::c_int
    };
    (*ei).norm[0 as libc::c_int as usize] = (if enc != PIECE_ENC as libc::c_int {
        (*be).c2rust_unnamed.pawns[0 as libc::c_int as usize] as libc::c_int
    } else if (*be).c2rust_unnamed.kk_enc as libc::c_int != 0 {
        2 as libc::c_int
    } else {
        3 as libc::c_int
    }) as uint8_t;
    let mut k: libc::c_int = (*ei).norm[0 as libc::c_int as usize] as libc::c_int;
    if morePawns {
        (*ei).norm[k as usize] = (*be).c2rust_unnamed.pawns[1 as libc::c_int as usize];
        k += (*ei).norm[k as usize] as libc::c_int;
    }
    let mut i_0: libc::c_int = k;
    while i_0 < (*be).num as libc::c_int {
        let mut j: libc::c_int = i_0;
        while j < (*be).num as libc::c_int
            && (*ei).pieces[j as usize] as libc::c_int == (*ei).pieces[i_0 as usize] as libc::c_int
        {
            (*ei).norm[i_0 as usize] = ((*ei).norm[i_0 as usize]).wrapping_add(1);
            (*ei).norm[i_0 as usize];
            j += 1;
            j;
        }
        i_0 += (*ei).norm[i_0 as usize] as libc::c_int;
    }
    let mut n: libc::c_int = 64 as libc::c_int - k;
    let mut f: size_t = 1 as libc::c_int as size_t;
    let mut i_1: libc::c_int = 0 as libc::c_int;
    while k < (*be).num as libc::c_int || i_1 == order || i_1 == order2 {
        if i_1 == order {
            (*ei).factor[0 as libc::c_int as usize] = f;
            f = f * if enc == FILE_ENC as libc::c_int {
                PawnFactorFile[((*ei).norm[0 as libc::c_int as usize] as libc::c_int
                    - 1 as libc::c_int) as usize][t as usize]
            } else if enc == RANK_ENC as libc::c_int {
                PawnFactorRank[((*ei).norm[0 as libc::c_int as usize] as libc::c_int
                    - 1 as libc::c_int) as usize][t as usize]
            } else {
                (if (*be).c2rust_unnamed.kk_enc as libc::c_int != 0 {
                    462 as libc::c_int
                } else {
                    31332 as libc::c_int
                }) as size_t
            };
        } else if i_1 == order2 {
            (*ei).factor[(*ei).norm[0 as libc::c_int as usize] as usize] = f;
            f = f * subfactor(
                (*ei).norm[(*ei).norm[0 as libc::c_int as usize] as usize] as size_t,
                (48 as libc::c_int - (*ei).norm[0 as libc::c_int as usize] as libc::c_int)
                    as size_t,
            );
        } else {
            (*ei).factor[k as usize] = f;
            f = f * subfactor((*ei).norm[k as usize] as size_t, n as size_t);
            n -= (*ei).norm[k as usize] as libc::c_int;
            k += (*ei).norm[k as usize] as libc::c_int;
        }
        i_1 += 1;
        i_1;
    }
    return f;
}
unsafe extern "C" fn calc_symLen(
    mut d: *mut PairsData,
    mut s: uint32_t,
    mut tmp: *mut libc::c_char,
) {
    let mut w: *mut uint8_t = ((*d).symPat).offset((3 as libc::c_int as uint32_t * s) as isize);
    let mut s2: uint32_t = ((*w.offset(2 as libc::c_int as isize) as libc::c_int)
        << 4 as libc::c_int
        | *w.offset(1 as libc::c_int as isize) as libc::c_int >> 4 as libc::c_int)
        as uint32_t;
    if s2 == 0xfff as libc::c_int as uint32_t {
        *((*d).symLen).offset(s as isize) = 0 as libc::c_int as uint8_t;
    } else {
        let mut s1: uint32_t =
            ((*w.offset(1 as libc::c_int as isize) as libc::c_int & 0xf as libc::c_int)
                << 8 as libc::c_int
                | *w.offset(0 as libc::c_int as isize) as libc::c_int) as uint32_t;
        if *tmp.offset(s1 as isize) == 0 {
            calc_symLen(d, s1, tmp);
        }
        if *tmp.offset(s2 as isize) == 0 {
            calc_symLen(d, s2, tmp);
        }
        *((*d).symLen).offset(s as isize) = (*((*d).symLen).offset(s1 as isize) as libc::c_int
            + *((*d).symLen).offset(s2 as isize) as libc::c_int
            + 1 as libc::c_int) as uint8_t;
    }
    *tmp.offset(s as isize) = 1 as libc::c_int as libc::c_char;
}
unsafe extern "C" fn setup_pairs(
    mut ptr: *mut *mut uint8_t,
    mut tb_size: size_t,
    mut size: *mut size_t,
    mut flags: *mut uint8_t,
    mut type_0: libc::c_int,
) -> *mut PairsData {
    let mut d: *mut PairsData = 0 as *mut PairsData;
    let mut data: *mut uint8_t = *ptr;
    *flags = *data.offset(0 as libc::c_int as isize);
    if *data.offset(0 as libc::c_int as isize) as libc::c_int & 0x80 as libc::c_int != 0 {
        d = malloc(::core::mem::size_of::<PairsData>() as libc::c_ulong) as *mut PairsData;
        (*d).idxBits = 0 as libc::c_int as uint8_t;
        (*d).constValue[0 as libc::c_int as usize] = (if type_0 == WDL as libc::c_int {
            *data.offset(1 as libc::c_int as isize) as libc::c_int
        } else {
            0 as libc::c_int
        }) as uint8_t;
        (*d).constValue[1 as libc::c_int as usize] = 0 as libc::c_int as uint8_t;
        *ptr = data.offset(2 as libc::c_int as isize);
        let ref mut fresh13 = *size.offset(2 as libc::c_int as isize);
        *fresh13 = 0 as libc::c_int as size_t;
        let ref mut fresh14 = *size.offset(1 as libc::c_int as isize);
        *fresh14 = *fresh13;
        *size.offset(0 as libc::c_int as isize) = *fresh14;
        return d;
    }
    let mut blockSize: uint8_t = *data.offset(1 as libc::c_int as isize);
    let mut idxBits: uint8_t = *data.offset(2 as libc::c_int as isize);
    let mut realNumBlocks: uint32_t =
        read_le_u32(data.offset(4 as libc::c_int as isize) as *mut libc::c_void);
    let mut numBlocks: uint32_t =
        realNumBlocks.wrapping_add(*data.offset(3 as libc::c_int as isize) as uint32_t);
    let mut maxLen: libc::c_int = *data.offset(8 as libc::c_int as isize) as libc::c_int;
    let mut minLen: libc::c_int = *data.offset(9 as libc::c_int as isize) as libc::c_int;
    let mut h: libc::c_int = maxLen - minLen + 1 as libc::c_int;
    let mut numSyms: uint32_t = read_le_u16(
        data.offset(10 as libc::c_int as isize)
            .offset((2 as libc::c_int * h) as isize) as *mut libc::c_void,
    ) as uint32_t;
    d = malloc(
        (::core::mem::size_of::<PairsData>() as libc::c_ulong)
            .wrapping_add(
                (h as libc::c_ulong)
                    .wrapping_mul(::core::mem::size_of::<uint64_t>() as libc::c_ulong),
            )
            .wrapping_add(numSyms as libc::c_ulong),
    ) as *mut PairsData;
    (*d).blockSize = blockSize;
    (*d).idxBits = idxBits;
    (*d).offset = &mut *data.offset(10 as libc::c_int as isize) as *mut uint8_t as *mut uint16_t;
    (*d).symLen = (d as *mut uint8_t)
        .offset(::core::mem::size_of::<PairsData>() as libc::c_ulong as isize)
        .offset(
            (h as libc::c_ulong).wrapping_mul(::core::mem::size_of::<uint64_t>() as libc::c_ulong)
                as isize,
        );
    (*d).symPat =
        &mut *data.offset((12 as libc::c_int + 2 as libc::c_int * h) as isize) as *mut uint8_t;
    (*d).minLen = minLen as uint8_t;
    *ptr = &mut *data.offset(
        ((12 as libc::c_int + 2 as libc::c_int * h) as uint32_t)
            .wrapping_add(3 as libc::c_int as uint32_t * numSyms)
            .wrapping_add(numSyms & 1 as libc::c_int as uint32_t) as isize,
    ) as *mut uint8_t;
    let mut num_indices: size_t = ((tb_size as libc::c_ulonglong)
        .wrapping_add((1 as libc::c_ulonglong) << idxBits as libc::c_int)
        .wrapping_sub(1 as libc::c_int as libc::c_ulonglong)
        >> idxBits as libc::c_int) as size_t;
    *size.offset(0 as libc::c_int as isize) =
        (6 as libc::c_ulonglong).wrapping_mul(num_indices as libc::c_ulonglong) as size_t;
    *size.offset(1 as libc::c_int as isize) =
        (2 as libc::c_ulonglong).wrapping_mul(numBlocks as libc::c_ulonglong) as size_t;
    *size.offset(2 as libc::c_int as isize) = (realNumBlocks as size_t) << blockSize as libc::c_int;
    if numSyms < 4096 as libc::c_int as uint32_t {
    } else {
        __assert_fail(
            b"numSyms < TB_MAX_SYMS\0" as *const u8 as *const libc::c_char,
            b"tbprobe.c\0" as *const u8 as *const libc::c_char,
            1273 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<&[u8; 76], &[libc::c_char; 76]>(
                b"struct PairsData *setup_pairs(uint8_t **, size_t, size_t *, uint8_t *, int)\0",
            ))
            .as_ptr(),
        );
    };
    let mut tmp: [libc::c_char; 4096] = [0; 4096];
    memset(
        tmp.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        numSyms as libc::c_ulong,
    );
    let mut s: uint32_t = 0 as libc::c_int as uint32_t;
    while s < numSyms {
        if tmp[s as usize] == 0 {
            calc_symLen(d, s, tmp.as_mut_ptr());
        }
        s = s.wrapping_add(1);
        s;
    }
    *((*d).base)
        .as_mut_ptr()
        .offset((h - 1 as libc::c_int) as isize) = 0 as libc::c_int as uint64_t;
    let mut i: libc::c_int = h - 2 as libc::c_int;
    while i >= 0 as libc::c_int {
        *((*d).base).as_mut_ptr().offset(i as isize) = (*((*d).base)
            .as_mut_ptr()
            .offset((i + 1 as libc::c_int) as isize))
        .wrapping_add(read_le_u16(
            ((*d).offset).offset(i as isize) as *mut uint8_t as *mut libc::c_void
        ) as uint64_t)
        .wrapping_sub(read_le_u16(
            ((*d).offset)
                .offset(i as isize)
                .offset(1 as libc::c_int as isize) as *mut uint8_t as *mut libc::c_void,
        ) as uint64_t)
            / 2 as libc::c_int as uint64_t;
        i -= 1;
        i;
    }
    let mut i_0: libc::c_int = 0 as libc::c_int;
    while i_0 < h {
        *((*d).base).as_mut_ptr().offset(i_0 as isize) <<= 64 as libc::c_int - (minLen + i_0);
        i_0 += 1;
        i_0;
    }
    (*d).offset = ((*d).offset).offset(-((*d).minLen as libc::c_int as isize));
    return d;
}
unsafe extern "C" fn init_table(
    mut be: *mut BaseEntry,
    mut str: *const libc::c_char,
    mut type_0: libc::c_int,
) -> bool {
    let mut data: *mut uint8_t = map_tb(
        str,
        tbSuffix[type_0 as usize],
        &mut *((*be).mapping).as_mut_ptr().offset(type_0 as isize),
    ) as *mut uint8_t;
    if data.is_null() {
        return 0 as libc::c_int != 0;
    }
    if read_le_u32(data as *mut libc::c_void) != tbMagic[type_0 as usize] {
        fprintf(
            stderr,
            b"Corrupted table.\n\0" as *const u8 as *const libc::c_char,
        );
        unmap_file(data as *mut libc::c_void, (*be).mapping[type_0 as usize]);
        return 0 as libc::c_int != 0;
    }
    (*be).data[type_0 as usize] = data;
    let mut split: bool = type_0 != DTZ as libc::c_int
        && *data.offset(4 as libc::c_int as isize) as libc::c_int & 0x1 as libc::c_int != 0;
    if type_0 == DTM as libc::c_int {
        (*be).dtmLossOnly =
            *data.offset(4 as libc::c_int as isize) as libc::c_int & 0x4 as libc::c_int != 0;
    }
    data = data.offset(5 as libc::c_int as isize);
    let mut tb_size: [[size_t; 2]; 6] = [[0; 2]; 6];
    let mut num: libc::c_int = num_tables(be, type_0);
    let mut ei: *mut EncInfo = first_ei(be, type_0);
    let mut enc: libc::c_int = if !(*be).hasPawns {
        PIECE_ENC as libc::c_int
    } else if type_0 != DTM as libc::c_int {
        FILE_ENC as libc::c_int
    } else {
        RANK_ENC as libc::c_int
    };
    let mut t: libc::c_int = 0 as libc::c_int;
    while t < num {
        tb_size[t as usize][0 as libc::c_int as usize] = init_enc_info(
            &mut *ei.offset(t as isize),
            be,
            data,
            0 as libc::c_int,
            t,
            enc,
        );
        if split {
            tb_size[t as usize][1 as libc::c_int as usize] = init_enc_info(
                &mut *ei.offset((num + t) as isize),
                be,
                data,
                4 as libc::c_int,
                t,
                enc,
            );
        }
        data = data.offset(
            ((*be).num as libc::c_int
                + 1 as libc::c_int
                + ((*be).hasPawns as libc::c_int != 0
                    && (*be).c2rust_unnamed.pawns[1 as libc::c_int as usize] as libc::c_int != 0)
                    as libc::c_int) as isize,
        );
        t += 1;
        t;
    }
    data = data.offset((data as uintptr_t & 1 as libc::c_int as uintptr_t) as isize);
    let mut size: [[[size_t; 3]; 2]; 6] = [[[0; 3]; 2]; 6];
    let mut t_0: libc::c_int = 0 as libc::c_int;
    while t_0 < num {
        let mut flags: uint8_t = 0;
        let ref mut fresh15 = (*ei.offset(t_0 as isize)).precomp;
        *fresh15 = setup_pairs(
            &mut data,
            tb_size[t_0 as usize][0 as libc::c_int as usize],
            (size[t_0 as usize][0 as libc::c_int as usize]).as_mut_ptr(),
            &mut flags,
            type_0,
        );
        if type_0 == DTZ as libc::c_int {
            if !(*be).hasPawns {
                (*(be as *mut PieceEntry)).dtzFlags = flags;
            } else {
                (*(be as *mut PawnEntry)).dtzFlags[t_0 as usize] = flags;
            }
        }
        if split {
            let ref mut fresh16 = (*ei.offset((num + t_0) as isize)).precomp;
            *fresh16 = setup_pairs(
                &mut data,
                tb_size[t_0 as usize][1 as libc::c_int as usize],
                (size[t_0 as usize][1 as libc::c_int as usize]).as_mut_ptr(),
                &mut flags,
                type_0,
            );
        } else if type_0 != DTZ as libc::c_int {
            let ref mut fresh17 = (*ei.offset((num + t_0) as isize)).precomp;
            *fresh17 = 0 as *mut PairsData;
        }
        t_0 += 1;
        t_0;
    }
    if type_0 == DTM as libc::c_int && !(*be).dtmLossOnly {
        let mut map: *mut uint16_t = data as *mut uint16_t;
        let ref mut fresh18 = *if (*be).hasPawns as libc::c_int != 0 {
            &mut (*(be as *mut PawnEntry)).dtmMap
        } else {
            &mut (*(be as *mut PieceEntry)).dtmMap
        };
        *fresh18 = map;
        let mut mapIdx: *mut [[uint16_t; 2]; 2] = if (*be).hasPawns as libc::c_int != 0 {
            &mut *((*(be as *mut PawnEntry)).dtmMapIdx)
                .as_mut_ptr()
                .offset(0 as libc::c_int as isize) as *mut [[uint16_t; 2]; 2]
        } else {
            &mut (*(be as *mut PieceEntry)).dtmMapIdx
        };
        let mut t_1: libc::c_int = 0 as libc::c_int;
        while t_1 < num {
            let mut i: libc::c_int = 0 as libc::c_int;
            while i < 2 as libc::c_int {
                (*mapIdx.offset(t_1 as isize))[0 as libc::c_int as usize][i as usize] =
                    data.offset(1 as libc::c_int as isize)
                        .offset_from(map as *mut uint8_t) as libc::c_long
                        as uint16_t;
                data = data.offset(
                    (2 as libc::c_int
                        + 2 as libc::c_int * read_le_u16(data as *mut libc::c_void) as libc::c_int)
                        as isize,
                );
                i += 1;
                i;
            }
            if split {
                let mut i_0: libc::c_int = 0 as libc::c_int;
                while i_0 < 2 as libc::c_int {
                    (*mapIdx.offset(t_1 as isize))[1 as libc::c_int as usize][i_0 as usize] =
                        data.offset(1 as libc::c_int as isize)
                            .offset_from(map as *mut uint8_t)
                            as libc::c_long as uint16_t;
                    data = data.offset(
                        (2 as libc::c_int
                            + 2 as libc::c_int
                                * read_le_u16(data as *mut libc::c_void) as libc::c_int)
                            as isize,
                    );
                    i_0 += 1;
                    i_0;
                }
            }
            t_1 += 1;
            t_1;
        }
    }
    if type_0 == DTZ as libc::c_int {
        let mut map_0: *mut libc::c_void = data as *mut libc::c_void;
        let ref mut fresh19 = *if (*be).hasPawns as libc::c_int != 0 {
            &mut (*(be as *mut PawnEntry)).dtzMap
        } else {
            &mut (*(be as *mut PieceEntry)).dtzMap
        };
        *fresh19 = map_0;
        let mut mapIdx_0: *mut [uint16_t; 4] = if (*be).hasPawns as libc::c_int != 0 {
            &mut *((*(be as *mut PawnEntry)).dtzMapIdx)
                .as_mut_ptr()
                .offset(0 as libc::c_int as isize) as *mut [uint16_t; 4]
        } else {
            &mut (*(be as *mut PieceEntry)).dtzMapIdx
        };
        let mut flags_0: *mut uint8_t = if (*be).hasPawns as libc::c_int != 0 {
            &mut *((*(be as *mut PawnEntry)).dtzFlags)
                .as_mut_ptr()
                .offset(0 as libc::c_int as isize) as *mut uint8_t
        } else {
            &mut (*(be as *mut PieceEntry)).dtzFlags
        };
        let mut t_2: libc::c_int = 0 as libc::c_int;
        while t_2 < num {
            if *flags_0.offset(t_2 as isize) as libc::c_int & 2 as libc::c_int != 0 {
                if *flags_0.offset(t_2 as isize) as libc::c_int & 16 as libc::c_int == 0 {
                    let mut i_1: libc::c_int = 0 as libc::c_int;
                    while i_1 < 4 as libc::c_int {
                        (*mapIdx_0.offset(t_2 as isize))[i_1 as usize] =
                            data.offset(1 as libc::c_int as isize)
                                .offset_from(map_0 as *mut uint8_t)
                                as libc::c_long as uint16_t;
                        data = data.offset(
                            (1 as libc::c_int
                                + *data.offset(0 as libc::c_int as isize) as libc::c_int)
                                as isize,
                        );
                        i_1 += 1;
                        i_1;
                    }
                } else {
                    data =
                        data.offset((data as uintptr_t & 0x1 as libc::c_int as uintptr_t) as isize);
                    let mut i_2: libc::c_int = 0 as libc::c_int;
                    while i_2 < 4 as libc::c_int {
                        (*mapIdx_0.offset(t_2 as isize))[i_2 as usize] = (data as *mut uint16_t)
                            .offset(1 as libc::c_int as isize)
                            .offset_from(map_0 as *mut uint16_t)
                            as libc::c_long
                            as uint16_t;
                        data = data.offset(
                            (2 as libc::c_int
                                + 2 as libc::c_int
                                    * read_le_u16(data as *mut libc::c_void) as libc::c_int)
                                as isize,
                        );
                        i_2 += 1;
                        i_2;
                    }
                }
            }
            t_2 += 1;
            t_2;
        }
        data = data.offset((data as uintptr_t & 0x1 as libc::c_int as uintptr_t) as isize);
    }
    let mut t_3: libc::c_int = 0 as libc::c_int;
    while t_3 < num {
        let ref mut fresh20 = (*(*ei.offset(t_3 as isize)).precomp).indexTable;
        *fresh20 = data;
        data = data.offset(
            size[t_3 as usize][0 as libc::c_int as usize][0 as libc::c_int as usize] as isize,
        );
        if split {
            let ref mut fresh21 = (*(*ei.offset((num + t_3) as isize)).precomp).indexTable;
            *fresh21 = data;
            data = data.offset(
                size[t_3 as usize][1 as libc::c_int as usize][0 as libc::c_int as usize] as isize,
            );
        }
        t_3 += 1;
        t_3;
    }
    let mut t_4: libc::c_int = 0 as libc::c_int;
    while t_4 < num {
        let ref mut fresh22 = (*(*ei.offset(t_4 as isize)).precomp).sizeTable;
        *fresh22 = data as *mut uint16_t;
        data = data.offset(
            size[t_4 as usize][0 as libc::c_int as usize][1 as libc::c_int as usize] as isize,
        );
        if split {
            let ref mut fresh23 = (*(*ei.offset((num + t_4) as isize)).precomp).sizeTable;
            *fresh23 = data as *mut uint16_t;
            data = data.offset(
                size[t_4 as usize][1 as libc::c_int as usize][1 as libc::c_int as usize] as isize,
            );
        }
        t_4 += 1;
        t_4;
    }
    let mut t_5: libc::c_int = 0 as libc::c_int;
    while t_5 < num {
        data = ((data as uintptr_t).wrapping_add(0x3f as libc::c_int as uintptr_t)
            & !(0x3f as libc::c_int) as uintptr_t) as *mut uint8_t;
        let ref mut fresh24 = (*(*ei.offset(t_5 as isize)).precomp).data;
        *fresh24 = data;
        data = data.offset(
            size[t_5 as usize][0 as libc::c_int as usize][2 as libc::c_int as usize] as isize,
        );
        if split {
            data = ((data as uintptr_t).wrapping_add(0x3f as libc::c_int as uintptr_t)
                & !(0x3f as libc::c_int) as uintptr_t) as *mut uint8_t;
            let ref mut fresh25 = (*(*ei.offset((num + t_5) as isize)).precomp).data;
            *fresh25 = data;
            data = data.offset(
                size[t_5 as usize][1 as libc::c_int as usize][2 as libc::c_int as usize] as isize,
            );
        }
        t_5 += 1;
        t_5;
    }
    if type_0 == DTM as libc::c_int && (*be).hasPawns as libc::c_int != 0 {
        (*(be as *mut PawnEntry)).dtmSwitched = pyrrhic_calc_key_from_pieces(
            ((*ei.offset(0 as libc::c_int as isize)).pieces).as_mut_ptr(),
            (*be).num as libc::c_int,
        ) != (*be).key;
    }
    return 1 as libc::c_int != 0;
}
unsafe extern "C" fn decompress_pairs(mut d: *mut PairsData, mut idx: size_t) -> *mut uint8_t {
    if (*d).idxBits == 0 {
        return ((*d).constValue).as_mut_ptr();
    }
    let mut mainIdx: uint32_t = (idx >> (*d).idxBits as libc::c_int) as uint32_t;
    let mut litIdx: libc::c_int = (idx
        & ((1 as libc::c_int as size_t) << (*d).idxBits as libc::c_int)
            .wrapping_sub(1 as libc::c_int as size_t))
    .wrapping_sub((1 as libc::c_int as size_t) << (*d).idxBits as libc::c_int - 1 as libc::c_int)
        as libc::c_int;
    let mut block: uint32_t = 0;
    memcpy(
        &mut block as *mut uint32_t as *mut libc::c_void,
        ((*d).indexTable).offset((6 as libc::c_int as uint32_t * mainIdx) as isize)
            as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    block = from_le_u32(block);
    let mut idxOffset: uint16_t = *(((*d).indexTable)
        .offset((6 as libc::c_int as uint32_t * mainIdx) as isize)
        .offset(4 as libc::c_int as isize) as *mut uint16_t);
    litIdx += from_le_u16(idxOffset) as libc::c_int;
    if litIdx < 0 as libc::c_int {
        while litIdx < 0 as libc::c_int {
            block = block.wrapping_sub(1);
            litIdx += *((*d).sizeTable).offset(block as isize) as libc::c_int + 1 as libc::c_int;
        }
    } else {
        while litIdx > *((*d).sizeTable).offset(block as isize) as libc::c_int {
            let fresh26 = block;
            block = block.wrapping_add(1);
            litIdx -= *((*d).sizeTable).offset(fresh26 as isize) as libc::c_int + 1 as libc::c_int;
        }
    }
    let mut ptr: *mut uint32_t = ((*d).data)
        .offset(((block as size_t) << (*d).blockSize as libc::c_int) as isize)
        as *mut uint32_t;
    let mut m: libc::c_int = (*d).minLen as libc::c_int;
    let mut offset: *mut uint16_t = (*d).offset;
    let mut base: *mut uint64_t = ((*d).base).as_mut_ptr().offset(-(m as isize));
    let mut symLen: *mut uint8_t = (*d).symLen;
    let mut sym: uint32_t = 0;
    let mut bitCnt: uint32_t = 0;
    let mut code: uint64_t = from_be_u64(*(ptr as *mut uint64_t));
    ptr = ptr.offset(2 as libc::c_int as isize);
    bitCnt = 0 as libc::c_int as uint32_t;
    loop {
        let mut l: libc::c_int = m;
        while code < *base.offset(l as isize) {
            l += 1;
            l;
        }
        sym = from_le_u16(*offset.offset(l as isize)) as uint32_t;
        sym = sym.wrapping_add(
            (code.wrapping_sub(*base.offset(l as isize)) >> 64 as libc::c_int - l) as uint32_t,
        );
        if litIdx < *symLen.offset(sym as isize) as libc::c_int + 1 as libc::c_int {
            break;
        }
        litIdx -= *symLen.offset(sym as isize) as libc::c_int + 1 as libc::c_int;
        code <<= l;
        bitCnt = bitCnt.wrapping_add(l as uint32_t);
        if bitCnt >= 32 as libc::c_int as uint32_t {
            bitCnt = bitCnt.wrapping_sub(32 as libc::c_int as uint32_t);
            let fresh27 = ptr;
            ptr = ptr.offset(1);
            let mut tmp: uint32_t = from_be_u32(*fresh27);
            code |= (tmp as uint64_t) << bitCnt;
        }
    }
    let mut symPat: *mut uint8_t = (*d).symPat;
    while *symLen.offset(sym as isize) as libc::c_int != 0 as libc::c_int {
        let mut w: *mut uint8_t = symPat.offset((3 as libc::c_int as uint32_t * sym) as isize);
        let mut s1: libc::c_int = (*w.offset(1 as libc::c_int as isize) as libc::c_int
            & 0xf as libc::c_int)
            << 8 as libc::c_int
            | *w.offset(0 as libc::c_int as isize) as libc::c_int;
        if litIdx < *symLen.offset(s1 as isize) as libc::c_int + 1 as libc::c_int {
            sym = s1 as uint32_t;
        } else {
            litIdx -= *symLen.offset(s1 as isize) as libc::c_int + 1 as libc::c_int;
            sym = ((*w.offset(2 as libc::c_int as isize) as libc::c_int) << 4 as libc::c_int
                | *w.offset(1 as libc::c_int as isize) as libc::c_int >> 4 as libc::c_int)
                as uint32_t;
        }
    }
    return &mut *symPat.offset((3 as libc::c_int as uint32_t * sym) as isize) as *mut uint8_t;
}
#[inline]
unsafe extern "C" fn fill_squares(
    mut pos: *const PyrrhicPosition,
    mut pc: *mut uint8_t,
    mut flip: bool,
    mut mirror: libc::c_int,
    mut p: *mut libc::c_int,
    mut i: libc::c_int,
) -> libc::c_int {
    let mut color: libc::c_int = pyrrhic_colour_of_piece(*pc.offset(i as isize));
    if flip {
        color = (color == 0) as libc::c_int;
    }
    let mut bb: uint64_t =
        pyrrhic_pieces_by_type(pos, color, pyrrhic_type_of_piece(*pc.offset(i as isize)));
    let mut sq: libc::c_uint = 0;
    loop {
        sq = poplsb(&mut bb) as libc::c_uint;
        let fresh28 = i;
        i = i + 1;
        *p.offset(fresh28 as isize) = (sq ^ mirror as libc::c_uint) as libc::c_int;
        if !(bb != 0) {
            break;
        }
    }
    return i;
}
#[no_mangle]
pub unsafe extern "C" fn probe_table(
    mut pos: *const PyrrhicPosition,
    mut s: libc::c_int,
    mut success: *mut libc::c_int,
    type_0: libc::c_int,
) -> libc::c_int {
    let mut key: uint64_t = pyrrhic_calc_key(pos, 0 as libc::c_int);
    if type_0 == WDL as libc::c_int && key as libc::c_ulonglong == 0 as libc::c_ulonglong {
        return 0 as libc::c_int;
    }
    let mut hashIdx: libc::c_int = (key
        >> 64 as libc::c_int
            - (if (7 as libc::c_int) < 7 as libc::c_int {
                11 as libc::c_int
            } else {
                12 as libc::c_int
            })) as libc::c_int;
    while tbHash[hashIdx as usize].key != 0 && tbHash[hashIdx as usize].key != key {
        hashIdx = hashIdx + 1 as libc::c_int
            & ((1 as libc::c_int)
                << (if (7 as libc::c_int) < 7 as libc::c_int {
                    11 as libc::c_int
                } else {
                    12 as libc::c_int
                }))
                - 1 as libc::c_int;
    }
    if (tbHash[hashIdx as usize].ptr).is_null() {
        *success = 0 as libc::c_int;
        return 0 as libc::c_int;
    }
    let mut be: *mut BaseEntry = tbHash[hashIdx as usize].ptr;
    if type_0 == DTM as libc::c_int && !(*be).hasDtm
        || type_0 == DTZ as libc::c_int && !(*be).hasDtz
    {
        *success = 0 as libc::c_int;
        return 0 as libc::c_int;
    }
    if !atomic_load_explicit(
        &mut *((*be).ready).as_mut_ptr().offset(type_0 as isize),
        memory_order_acquire as libc::c_int,
    ) {
        pthread_mutex_lock(&mut tbMutex);
        if !atomic_load_explicit(
            &mut *((*be).ready).as_mut_ptr().offset(type_0 as isize),
            memory_order_relaxed as libc::c_int,
        ) {
            let mut str: [libc::c_char; 16] = [0; 16];
            prt_str(pos, str.as_mut_ptr(), ((*be).key != key) as libc::c_int);
            if !init_table(be, str.as_mut_ptr(), type_0) {
                tbHash[hashIdx as usize].ptr = 0 as *mut BaseEntry;
                *success = 0 as libc::c_int;
                pthread_mutex_unlock(&mut tbMutex);
                return 0 as libc::c_int;
            }
            atomic_store_explicit(
                &mut *((*be).ready).as_mut_ptr().offset(type_0 as isize),
                1 as libc::c_int != 0,
                memory_order_release as libc::c_int,
            );
        }
        pthread_mutex_unlock(&mut tbMutex);
    }
    let mut bside: bool = false;
    let mut flip: bool = false;
    if !(*be).symmetric {
        flip = key != (*be).key;
        bside = ((*pos).turn as libc::c_int == PYRRHIC_WHITE as libc::c_int) as libc::c_int
            == flip as libc::c_int;
        if type_0 == DTM as libc::c_int
            && (*be).hasPawns as libc::c_int != 0
            && (*(be as *mut PawnEntry)).dtmSwitched as libc::c_int != 0
        {
            flip = !flip;
            bside = !bside;
        }
    } else {
        flip = (*pos).turn as libc::c_int != PYRRHIC_WHITE as libc::c_int;
        bside = 0 as libc::c_int != 0;
    }
    let mut ei: *mut EncInfo = first_ei(be, type_0);
    let mut p: [libc::c_int; 7] = [0; 7];
    let mut idx: size_t = 0;
    let mut t: libc::c_int = 0 as libc::c_int;
    let mut flags: uint8_t = 0 as libc::c_int as uint8_t;
    if !(*be).hasPawns {
        if type_0 == DTZ as libc::c_int {
            flags = (*(be as *mut PieceEntry)).dtzFlags;
            if flags as libc::c_int & 1 as libc::c_int != bside as libc::c_int && !(*be).symmetric {
                *success = -(1 as libc::c_int);
                return 0 as libc::c_int;
            }
        }
        ei = if type_0 != DTZ as libc::c_int {
            &mut *ei.offset(bside as isize) as *mut EncInfo
        } else {
            ei
        };
        let mut i: libc::c_int = 0 as libc::c_int;
        while i < (*be).num as libc::c_int {
            i = fill_squares(
                pos,
                ((*ei).pieces).as_mut_ptr(),
                flip,
                0 as libc::c_int,
                p.as_mut_ptr(),
                i,
            );
        }
        idx = encode_piece(p.as_mut_ptr(), ei, be);
    } else {
        let mut i_0: libc::c_int = fill_squares(
            pos,
            ((*ei).pieces).as_mut_ptr(),
            flip,
            if flip as libc::c_int != 0 {
                0x38 as libc::c_int
            } else {
                0 as libc::c_int
            },
            p.as_mut_ptr(),
            0 as libc::c_int,
        );
        t = leading_pawn(
            p.as_mut_ptr(),
            be,
            if type_0 != DTM as libc::c_int {
                FILE_ENC as libc::c_int
            } else {
                RANK_ENC as libc::c_int
            },
        );
        if type_0 == DTZ as libc::c_int {
            flags = (*(be as *mut PawnEntry)).dtzFlags[t as usize];
            if flags as libc::c_int & 1 as libc::c_int != bside as libc::c_int && !(*be).symmetric {
                *success = -(1 as libc::c_int);
                return 0 as libc::c_int;
            }
        }
        ei = if type_0 == WDL as libc::c_int {
            &mut *ei.offset((t + 4 as libc::c_int * bside as libc::c_int) as isize) as *mut EncInfo
        } else if type_0 == DTM as libc::c_int {
            &mut *ei.offset((t + 6 as libc::c_int * bside as libc::c_int) as isize) as *mut EncInfo
        } else {
            &mut *ei.offset(t as isize) as *mut EncInfo
        };
        while i_0 < (*be).num as libc::c_int {
            i_0 = fill_squares(
                pos,
                ((*ei).pieces).as_mut_ptr(),
                flip,
                if flip as libc::c_int != 0 {
                    0x38 as libc::c_int
                } else {
                    0 as libc::c_int
                },
                p.as_mut_ptr(),
                i_0,
            );
        }
        idx = if type_0 != DTM as libc::c_int {
            encode_pawn_f(p.as_mut_ptr(), ei, be)
        } else {
            encode_pawn_r(p.as_mut_ptr(), ei, be)
        };
    }
    let mut w: *mut uint8_t = decompress_pairs((*ei).precomp, idx);
    if type_0 == WDL as libc::c_int {
        return *w.offset(0 as libc::c_int as isize) as libc::c_int - 2 as libc::c_int;
    }
    let mut v: libc::c_int = *w.offset(0 as libc::c_int as isize) as libc::c_int
        + ((*w.offset(1 as libc::c_int as isize) as libc::c_int & 0xf as libc::c_int)
            << 8 as libc::c_int);
    if type_0 == DTM as libc::c_int {
        if !(*be).dtmLossOnly {
            v = from_le_u16(
                (if (*be).hasPawns as libc::c_int != 0 {
                    *((*(be as *mut PawnEntry)).dtmMap).offset(
                        ((*(be as *mut PawnEntry)).dtmMapIdx[t as usize][bside as usize][s as usize]
                            as libc::c_int
                            + v) as isize,
                    ) as libc::c_int
                } else {
                    *((*(be as *mut PieceEntry)).dtmMap).offset(
                        ((*(be as *mut PieceEntry)).dtmMapIdx[bside as usize][s as usize]
                            as libc::c_int
                            + v) as isize,
                    ) as libc::c_int
                }) as uint16_t,
            ) as libc::c_int;
        }
    } else {
        if flags as libc::c_int & 2 as libc::c_int != 0 {
            let mut m: libc::c_int = WdlToMap[(s + 2 as libc::c_int) as usize];
            if flags as libc::c_int & 16 as libc::c_int == 0 {
                v = if (*be).hasPawns as libc::c_int != 0 {
                    *((*(be as *mut PawnEntry)).dtzMap as *mut uint8_t).offset(
                        ((*(be as *mut PawnEntry)).dtzMapIdx[t as usize][m as usize] as libc::c_int
                            + v) as isize,
                    ) as libc::c_int
                } else {
                    *((*(be as *mut PieceEntry)).dtzMap as *mut uint8_t).offset(
                        ((*(be as *mut PieceEntry)).dtzMapIdx[m as usize] as libc::c_int + v)
                            as isize,
                    ) as libc::c_int
                };
            } else {
                v = from_le_u16(
                    (if (*be).hasPawns as libc::c_int != 0 {
                        *((*(be as *mut PawnEntry)).dtzMap as *mut uint16_t).offset(
                            ((*(be as *mut PawnEntry)).dtzMapIdx[t as usize][m as usize]
                                as libc::c_int
                                + v) as isize,
                        ) as libc::c_int
                    } else {
                        *((*(be as *mut PieceEntry)).dtzMap as *mut uint16_t).offset(
                            ((*(be as *mut PieceEntry)).dtzMapIdx[m as usize] as libc::c_int + v)
                                as isize,
                        ) as libc::c_int
                    }) as uint16_t,
                ) as libc::c_int;
            }
        }
        if flags as libc::c_int & PAFlags[(s + 2 as libc::c_int) as usize] as libc::c_int == 0
            || s & 1 as libc::c_int != 0
        {
            v *= 2 as libc::c_int;
        }
    }
    return v;
}
unsafe extern "C" fn probe_wdl_table(
    mut pos: *const PyrrhicPosition,
    mut success: *mut libc::c_int,
) -> libc::c_int {
    return probe_table(pos, 0 as libc::c_int, success, WDL as libc::c_int);
}
unsafe extern "C" fn probe_dtz_table(
    mut pos: *const PyrrhicPosition,
    mut wdl: libc::c_int,
    mut success: *mut libc::c_int,
) -> libc::c_int {
    return probe_table(pos, wdl, success, DTZ as libc::c_int);
}
unsafe extern "C" fn probe_ab(
    mut pos: *const PyrrhicPosition,
    mut alpha: libc::c_int,
    mut beta: libc::c_int,
    mut success: *mut libc::c_int,
) -> libc::c_int {
    if (*pos).ep as libc::c_int == 0 as libc::c_int {
    } else {
        __assert_fail(
            b"pos->ep == 0\0" as *const u8 as *const libc::c_char,
            b"tbprobe.c\0" as *const u8 as *const libc::c_char,
            1665 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<&[u8; 55], &[libc::c_char; 55]>(
                b"int probe_ab(const PyrrhicPosition *, int, int, int *)\0",
            ))
            .as_ptr(),
        );
    };
    let mut moves0: [PyrrhicMove; 64] = [0; 64];
    let mut m: *mut PyrrhicMove = moves0.as_mut_ptr();
    let mut end: *mut PyrrhicMove = pyrrhic_gen_captures(pos, m);
    while m < end {
        let mut pos1: PyrrhicPosition = PyrrhicPosition {
            white: 0,
            black: 0,
            kings: 0,
            queens: 0,
            rooks: 0,
            bishops: 0,
            knights: 0,
            pawns: 0,
            rule50: 0,
            ep: 0,
            turn: false,
        };
        let mut move_0: PyrrhicMove = *m;
        if pyrrhic_is_capture(pos, move_0) {
            if pyrrhic_do_move(&mut pos1, pos, move_0) {
                let mut v: libc::c_int = -probe_ab(&mut pos1, -beta, -alpha, success);
                if *success == 0 as libc::c_int {
                    return 0 as libc::c_int;
                }
                if v > alpha {
                    if v >= beta {
                        return v;
                    }
                    alpha = v;
                }
            }
        }
        m = m.offset(1);
        m;
    }
    let mut v_0: libc::c_int = probe_wdl_table(pos, success);
    return if alpha >= v_0 { alpha } else { v_0 };
}
unsafe extern "C" fn probe_wdl(
    mut pos: *mut PyrrhicPosition,
    mut success: *mut libc::c_int,
) -> libc::c_int {
    *success = 1 as libc::c_int;
    let mut moves0: [PyrrhicMove; 64] = [0; 64];
    let mut m: *mut PyrrhicMove = moves0.as_mut_ptr();
    let mut end: *mut PyrrhicMove = pyrrhic_gen_captures(pos, m);
    let mut bestCap: libc::c_int = -(3 as libc::c_int);
    let mut bestEp: libc::c_int = -(3 as libc::c_int);
    while m < end {
        let mut pos1: PyrrhicPosition = PyrrhicPosition {
            white: 0,
            black: 0,
            kings: 0,
            queens: 0,
            rooks: 0,
            bishops: 0,
            knights: 0,
            pawns: 0,
            rule50: 0,
            ep: 0,
            turn: false,
        };
        let mut move_0: PyrrhicMove = *m;
        if pyrrhic_is_capture(pos, move_0) {
            if pyrrhic_do_move(&mut pos1, pos, move_0) {
                let mut v: libc::c_int =
                    -probe_ab(&mut pos1, -(2 as libc::c_int), -bestCap, success);
                if *success == 0 as libc::c_int {
                    return 0 as libc::c_int;
                }
                if v > bestCap {
                    if v == 2 as libc::c_int {
                        *success = 2 as libc::c_int;
                        return 2 as libc::c_int;
                    }
                    if !pyrrhic_is_en_passant(pos, move_0) {
                        bestCap = v;
                    } else if v > bestEp {
                        bestEp = v;
                    }
                }
            }
        }
        m = m.offset(1);
        m;
    }
    let mut v_0: libc::c_int = probe_wdl_table(pos, success);
    if *success == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if bestEp > bestCap {
        if bestEp > v_0 {
            *success = 2 as libc::c_int;
            return bestEp;
        }
        bestCap = bestEp;
    }
    if bestCap >= v_0 {
        *success = 1 as libc::c_int + (bestCap > 0 as libc::c_int) as libc::c_int;
        return bestCap;
    }
    if bestEp > -(3 as libc::c_int) && v_0 == 0 as libc::c_int {
        let mut moves: [PyrrhicMove; 256] = [0; 256];
        let mut end2: *mut PyrrhicMove = pyrrhic_gen_moves(pos, moves.as_mut_ptr());
        m = moves.as_mut_ptr();
        while m < end2 {
            if !pyrrhic_is_en_passant(pos, *m) && pyrrhic_legal_move(pos, *m) as libc::c_int != 0 {
                break;
            }
            m = m.offset(1);
            m;
        }
        if m == end2 && !pyrrhic_is_check(pos) {
            *success = 2 as libc::c_int;
            return bestEp;
        }
    }
    return v_0;
}
static mut WdlToDtz: [libc::c_int; 5] = [
    -(1 as libc::c_int),
    -(101 as libc::c_int),
    0 as libc::c_int,
    101 as libc::c_int,
    1 as libc::c_int,
];
unsafe extern "C" fn probe_dtz(
    mut pos: *mut PyrrhicPosition,
    mut success: *mut libc::c_int,
) -> libc::c_int {
    let mut wdl: libc::c_int = probe_wdl(pos, success);
    if *success == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if wdl == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    if *success == 2 as libc::c_int {
        return WdlToDtz[(wdl + 2 as libc::c_int) as usize];
    }
    let mut moves: [PyrrhicMove; 256] = [0; 256];
    let mut m: *mut PyrrhicMove = moves.as_mut_ptr();
    let mut end: *mut PyrrhicMove = 0 as *mut PyrrhicMove;
    let mut pos1: PyrrhicPosition = PyrrhicPosition {
        white: 0,
        black: 0,
        kings: 0,
        queens: 0,
        rooks: 0,
        bishops: 0,
        knights: 0,
        pawns: 0,
        rule50: 0,
        ep: 0,
        turn: false,
    };
    if wdl > 0 as libc::c_int {
        end = pyrrhic_gen_legal(pos, moves.as_mut_ptr());
        m = moves.as_mut_ptr();
        while m < end {
            let mut move_0: PyrrhicMove = *m;
            if !(!pyrrhic_is_pawn_move(pos, move_0)
                || pyrrhic_is_capture(pos, move_0) as libc::c_int != 0)
            {
                if pyrrhic_do_move(&mut pos1, pos, move_0) {
                    let mut v: libc::c_int = -probe_wdl(&mut pos1, success);
                    if *success == 0 as libc::c_int {
                        return 0 as libc::c_int;
                    }
                    if v == wdl {
                        if wdl < 3 as libc::c_int {
                        } else {
                            __assert_fail(
                                b"wdl < 3\0" as *const u8 as *const libc::c_char,
                                b"tbprobe.c\0" as *const u8 as *const libc::c_char,
                                1852 as libc::c_int as libc::c_uint,
                                (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
                                    b"int probe_dtz(PyrrhicPosition *, int *)\0",
                                ))
                                .as_ptr(),
                            );
                        };
                        return WdlToDtz[(wdl + 2 as libc::c_int) as usize];
                    }
                }
            }
            m = m.offset(1);
            m;
        }
    }
    let mut dtz: libc::c_int = probe_dtz_table(pos, wdl, success);
    if *success >= 0 as libc::c_int {
        return WdlToDtz[(wdl + 2 as libc::c_int) as usize]
            + (if wdl > 0 as libc::c_int { dtz } else { -dtz });
    }
    let mut best: libc::c_int = 0;
    if wdl > 0 as libc::c_int {
        best = 2147483647 as libc::c_int;
    } else {
        best = WdlToDtz[(wdl + 2 as libc::c_int) as usize];
        end = pyrrhic_gen_moves(pos, m);
    }
    if !end.is_null() {
    } else {
        __assert_fail(
            b"end != NULL\0" as *const u8 as *const libc::c_char,
            b"tbprobe.c\0" as *const u8 as *const libc::c_char,
            1879 as libc::c_int as libc::c_uint,
            (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
                b"int probe_dtz(PyrrhicPosition *, int *)\0",
            ))
            .as_ptr(),
        );
    };
    m = moves.as_mut_ptr();
    while m < end {
        let mut move_1: PyrrhicMove = *m;
        if !(pyrrhic_is_capture(pos, move_1) as libc::c_int != 0
            || pyrrhic_is_pawn_move(pos, move_1) as libc::c_int != 0)
        {
            if pyrrhic_do_move(&mut pos1, pos, move_1) {
                let mut v_0: libc::c_int = -probe_dtz(&mut pos1, success);
                if v_0 == 1 as libc::c_int && pyrrhic_is_mate(&mut pos1) as libc::c_int != 0 {
                    best = 1 as libc::c_int;
                } else if wdl > 0 as libc::c_int {
                    if v_0 > 0 as libc::c_int && (v_0 + 1 as libc::c_int) < best {
                        best = v_0 + 1 as libc::c_int;
                    }
                } else if (v_0 - 1 as libc::c_int) < best {
                    best = v_0 - 1 as libc::c_int;
                }
                if *success == 0 as libc::c_int {
                    return 0 as libc::c_int;
                }
            }
        }
        m = m.offset(1);
        m;
    }
    return best;
}
#[no_mangle]
pub unsafe extern "C" fn root_probe_dtz(
    mut pos: *const PyrrhicPosition,
    mut hasRepeated: bool,
    mut useRule50: bool,
    mut rm: *mut TbRootMoves,
) -> libc::c_int {
    let mut v: libc::c_int = 0;
    let mut success: libc::c_int = 0;
    let mut cnt50: libc::c_int = (*pos).rule50 as libc::c_int;
    let mut bound: libc::c_int = if useRule50 as libc::c_int != 0 {
        0x40000 as libc::c_int - 100 as libc::c_int
    } else {
        1 as libc::c_int
    };
    let mut rootMoves: [PyrrhicMove; 256] = [0; 256];
    let mut end: *mut PyrrhicMove = pyrrhic_gen_legal(pos, rootMoves.as_mut_ptr());
    (*rm).size = end.offset_from(rootMoves.as_mut_ptr()) as libc::c_long as libc::c_uint;
    let mut pos1: PyrrhicPosition = PyrrhicPosition {
        white: 0,
        black: 0,
        kings: 0,
        queens: 0,
        rooks: 0,
        bishops: 0,
        knights: 0,
        pawns: 0,
        rule50: 0,
        ep: 0,
        turn: false,
    };
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < (*rm).size {
        let mut m: *mut TbRootMove =
            &mut *((*rm).moves).as_mut_ptr().offset(i as isize) as *mut TbRootMove;
        (*m).move_0 = rootMoves[i as usize];
        pyrrhic_do_move(&mut pos1, pos, (*m).move_0);
        if pos1.rule50 as libc::c_int == 0 as libc::c_int {
            v = -probe_wdl(&mut pos1, &mut success);
            if v < 3 as libc::c_int {
            } else {
                __assert_fail(
                    b"v < 3\0" as *const u8 as *const libc::c_char,
                    b"tbprobe.c\0" as *const u8 as *const libc::c_char,
                    1935 as libc::c_int as libc::c_uint,
                    (*::core::mem::transmute::<
                        &[u8; 80],
                        &[libc::c_char; 80],
                    >(
                        b"int root_probe_dtz(const PyrrhicPosition *, _Bool, _Bool, struct TbRootMoves *)\0",
                    ))
                        .as_ptr(),
                );
            };
            v = WdlToDtz[(v + 2 as libc::c_int) as usize];
        } else {
            v = -probe_dtz(&mut pos1, &mut success);
            if v > 0 as libc::c_int {
                v += 1;
                v;
            } else if v < 0 as libc::c_int {
                v -= 1;
                v;
            }
        }
        if v == 2 as libc::c_int && pyrrhic_is_mate(&mut pos1) as libc::c_int != 0 {
            v = 1 as libc::c_int;
        }
        if success == 0 {
            return 0 as libc::c_int;
        }
        let mut r: libc::c_int = if v > 0 as libc::c_int {
            if v + cnt50 <= 99 as libc::c_int && !hasRepeated {
                0x40000 as libc::c_int
            } else {
                0x40000 as libc::c_int - (v + cnt50)
            }
        } else if v < 0 as libc::c_int {
            if -v * 2 as libc::c_int + cnt50 < 100 as libc::c_int {
                -(0x40000 as libc::c_int)
            } else {
                -(0x40000 as libc::c_int) + (-v + cnt50)
            }
        } else {
            0 as libc::c_int
        };
        (*m).tbRank = r;
        (*m).tbScore = if r >= bound {
            32000 as libc::c_int - 255 as libc::c_int - 1 as libc::c_int
        } else if r > 0 as libc::c_int {
            (if 3 as libc::c_int > r - (0x40000 as libc::c_int - 200 as libc::c_int) {
                3 as libc::c_int
            } else {
                r - (0x40000 as libc::c_int - 200 as libc::c_int)
            }) * 100 as libc::c_int
                / 200 as libc::c_int
        } else if r == 0 as libc::c_int {
            0 as libc::c_int
        } else if r > -bound {
            (if -(3 as libc::c_int) < r + (0x40000 as libc::c_int - 200 as libc::c_int) {
                -(3 as libc::c_int)
            } else {
                r + (0x40000 as libc::c_int - 200 as libc::c_int)
            }) * 100 as libc::c_int
                / 200 as libc::c_int
        } else {
            -(32000 as libc::c_int) + 255 as libc::c_int + 1 as libc::c_int
        };
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn root_probe_wdl(
    mut pos: *const PyrrhicPosition,
    mut useRule50: bool,
    mut rm: *mut TbRootMoves,
) -> libc::c_int {
    static mut WdlToRank: [libc::c_int; 5] = [
        -(0x40000 as libc::c_int),
        -(0x40000 as libc::c_int) + 101 as libc::c_int,
        0 as libc::c_int,
        0x40000 as libc::c_int - 101 as libc::c_int,
        0x40000 as libc::c_int,
    ];
    static mut WdlToValue: [libc::c_int; 5] = [
        -(32000 as libc::c_int) + 255 as libc::c_int + 1 as libc::c_int,
        0 as libc::c_int - 2 as libc::c_int,
        0 as libc::c_int,
        0 as libc::c_int + 2 as libc::c_int,
        32000 as libc::c_int - 255 as libc::c_int - 1 as libc::c_int,
    ];
    let mut v: libc::c_int = 0;
    let mut success: libc::c_int = 0;
    let mut moves: [PyrrhicMove; 256] = [0; 256];
    let mut end: *mut PyrrhicMove = pyrrhic_gen_legal(pos, moves.as_mut_ptr());
    (*rm).size = end.offset_from(moves.as_mut_ptr()) as libc::c_long as libc::c_uint;
    let mut pos1: PyrrhicPosition = PyrrhicPosition {
        white: 0,
        black: 0,
        kings: 0,
        queens: 0,
        rooks: 0,
        bishops: 0,
        knights: 0,
        pawns: 0,
        rule50: 0,
        ep: 0,
        turn: false,
    };
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while i < (*rm).size {
        let mut m: *mut TbRootMove =
            &mut *((*rm).moves).as_mut_ptr().offset(i as isize) as *mut TbRootMove;
        (*m).move_0 = moves[i as usize];
        pyrrhic_do_move(&mut pos1, pos, (*m).move_0);
        v = -probe_wdl(&mut pos1, &mut success);
        if success == 0 {
            return 0 as libc::c_int;
        }
        if !useRule50 {
            v = if v > 0 as libc::c_int {
                2 as libc::c_int
            } else if v < 0 as libc::c_int {
                -(2 as libc::c_int)
            } else {
                0 as libc::c_int
            };
        }
        (*m).tbRank = WdlToRank[(v + 2 as libc::c_int) as usize];
        (*m).tbScore = WdlToValue[(v + 2 as libc::c_int) as usize];
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
static mut wdl_to_dtz: [libc::c_int; 5] = [
    -(1 as libc::c_int),
    -(101 as libc::c_int),
    0 as libc::c_int,
    101 as libc::c_int,
    1 as libc::c_int,
];
unsafe extern "C" fn probe_root(
    mut pos: *mut PyrrhicPosition,
    mut score: *mut libc::c_int,
    mut results: *mut libc::c_uint,
) -> uint16_t {
    let mut success: libc::c_int = 0;
    let mut dtz: libc::c_int = probe_dtz(pos, &mut success);
    if success == 0 {
        return 0 as libc::c_int as uint16_t;
    }
    let mut scores: [int16_t; 256] = [0; 256];
    let mut moves0: [uint16_t; 256] = [0; 256];
    let mut moves: *mut uint16_t = moves0.as_mut_ptr();
    let mut end: *mut uint16_t = pyrrhic_gen_moves(pos, moves);
    let mut len: size_t = end.offset_from(moves) as libc::c_long as size_t;
    let mut num_draw: size_t = 0 as libc::c_int as size_t;
    let mut j: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    while (i as size_t) < len {
        let mut pos1: PyrrhicPosition = PyrrhicPosition {
            white: 0,
            black: 0,
            kings: 0,
            queens: 0,
            rooks: 0,
            bishops: 0,
            knights: 0,
            pawns: 0,
            rule50: 0,
            ep: 0,
            turn: false,
        };
        if !pyrrhic_do_move(&mut pos1, pos, *moves.offset(i as isize)) {
            scores[i as usize] = 0x7fff as libc::c_int as int16_t;
        } else {
            let mut v: libc::c_int = 0 as libc::c_int;
            if dtz > 0 as libc::c_int && pyrrhic_is_mate(&mut pos1) as libc::c_int != 0 {
                v = 1 as libc::c_int;
            } else if pos1.rule50 as libc::c_int != 0 as libc::c_int {
                v = -probe_dtz(&mut pos1, &mut success);
                if v > 0 as libc::c_int {
                    v += 1;
                    v;
                } else if v < 0 as libc::c_int {
                    v -= 1;
                    v;
                }
            } else {
                v = -probe_wdl(&mut pos1, &mut success);
                v = wdl_to_dtz[(v + 2 as libc::c_int) as usize];
            }
            num_draw = num_draw.wrapping_add((v == 0 as libc::c_int) as libc::c_int as size_t);
            if success == 0 {
                return 0 as libc::c_int as uint16_t;
            }
            scores[i as usize] = v as int16_t;
            if !results.is_null() {
                let mut res: libc::c_uint = 0 as libc::c_int as libc::c_uint;
                res = res & !(0xf as libc::c_int) as libc::c_uint
                    | dtz_to_wdl((*pos).rule50 as libc::c_int, v) << 0 as libc::c_int
                        & 0xf as libc::c_int as libc::c_uint;
                res = res & !(0xfc00 as libc::c_int) as libc::c_uint
                    | pyrrhic_move_from(*moves.offset(i as isize)) << 10 as libc::c_int
                        & 0xfc00 as libc::c_int as libc::c_uint;
                res = res & !(0x3f0 as libc::c_int) as libc::c_uint
                    | pyrrhic_move_to(*moves.offset(i as isize)) << 4 as libc::c_int
                        & 0x3f0 as libc::c_int as libc::c_uint;
                res = res & !(0x70000 as libc::c_int) as libc::c_uint
                    | pyrrhic_move_promotes(*moves.offset(i as isize)) << 16 as libc::c_int
                        & 0x70000 as libc::c_int as libc::c_uint;
                res = res & !(0x80000 as libc::c_int) as libc::c_uint
                    | ((pyrrhic_is_en_passant(pos, *moves.offset(i as isize)) as libc::c_int)
                        << 19 as libc::c_int
                        & 0x80000 as libc::c_int) as libc::c_uint;
                res = res & !(0xfff00000 as libc::c_uint)
                    | ((if v < 0 as libc::c_int { -v } else { v }) << 20 as libc::c_int)
                        as libc::c_uint
                        & 0xfff00000 as libc::c_uint;
                let fresh29 = j;
                j = j.wrapping_add(1);
                *results.offset(fresh29 as isize) = res;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    if !results.is_null() {
        let fresh30 = j;
        j = j.wrapping_add(1);
        *results.offset(fresh30 as isize) = 0xffffffff as libc::c_uint;
    }
    if !score.is_null() {
        *score = dtz;
    }
    if dtz > 0 as libc::c_int {
        let mut best: libc::c_int = 0xffff as libc::c_int;
        let mut best_move: uint16_t = 0 as libc::c_int as uint16_t;
        let mut i_0: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        while (i_0 as size_t) < len {
            let mut v_0: libc::c_int = scores[i_0 as usize] as libc::c_int;
            if !(v_0 == 0x7fff as libc::c_int) {
                if v_0 > 0 as libc::c_int && v_0 < best {
                    best = v_0;
                    best_move = *moves.offset(i_0 as isize);
                }
            }
            i_0 = i_0.wrapping_add(1);
            i_0;
        }
        return (if best == 0xffff as libc::c_int {
            0 as libc::c_int
        } else {
            best_move as libc::c_int
        }) as uint16_t;
    } else if dtz < 0 as libc::c_int {
        let mut best_0: libc::c_int = 0 as libc::c_int;
        let mut best_move_0: uint16_t = 0 as libc::c_int as uint16_t;
        let mut i_1: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        while (i_1 as size_t) < len {
            let mut v_1: libc::c_int = scores[i_1 as usize] as libc::c_int;
            if !(v_1 == 0x7fff as libc::c_int) {
                if v_1 < best_0 {
                    best_0 = v_1;
                    best_move_0 = *moves.offset(i_1 as isize);
                }
            }
            i_1 = i_1.wrapping_add(1);
            i_1;
        }
        return (if best_0 == 0 as libc::c_int {
            0xfffe as libc::c_int
        } else {
            best_move_0 as libc::c_int
        }) as uint16_t;
    } else {
        if num_draw == 0 as libc::c_int as size_t {
            return 0xffff as libc::c_int as uint16_t;
        }
        let mut count: size_t =
            (pyrrhic_calc_key(pos, !(*pos).turn as libc::c_int)).wrapping_rem(num_draw);
        let mut i_2: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        while (i_2 as size_t) < len {
            let mut v_2: libc::c_int = scores[i_2 as usize] as libc::c_int;
            if !(v_2 == 0x7fff as libc::c_int) {
                if v_2 == 0 as libc::c_int {
                    if count == 0 as libc::c_int as size_t {
                        return *moves.offset(i_2 as isize);
                    }
                    count = count.wrapping_sub(1);
                    count;
                }
            }
            i_2 = i_2.wrapping_add(1);
            i_2;
        }
        return 0 as libc::c_int as uint16_t;
    };
}
