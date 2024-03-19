use std::{ptr::addr_of_mut, sync::atomic::{AtomicBool, Ordering}};

use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn __assert_fail(
        __assertion: *const i8,
        __file: *const i8,
        __line: u32,
        __function: *const i8,
    ) -> !;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const i8, _: ...) -> i32;
    fn printf(_: *const i8, _: ...) -> i32;
    fn snprintf(_: *mut i8, _: u64, _: *const i8, _: ...) -> i32;
    fn perror(__s: *const i8);
    fn malloc(_: u64) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn exit(_: i32) -> !;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: u64) -> *mut libc::c_void;
    fn memset(_: *mut libc::c_void, _: i32, _: u64) -> *mut libc::c_void;
    fn strcpy(_: *mut i8, _: *const i8) -> *mut i8;
    fn strcat(_: *mut i8, _: *const i8) -> *mut i8;
    fn strcmp(_: *const i8, _: *const i8) -> i32;
    fn strlen(_: *const i8) -> u64;
    fn open(__file: *const i8, __oflag: i32, _: ...) -> i32;
    fn pthread_mutex_unlock(__mutex: *mut pthread_mutex_t) -> i32;
    fn pthread_mutex_lock(__mutex: *mut pthread_mutex_t) -> i32;
    fn pthread_mutex_destroy(__mutex: *mut pthread_mutex_t) -> i32;
    fn pthread_mutex_init(
        __mutex: *mut pthread_mutex_t,
        __mutexattr: *const pthread_mutexattr_t,
    ) -> i32;
    fn close(__fd: i32) -> i32;
    fn mmap(
        __addr: *mut libc::c_void,
        __len: u64,
        __prot: i32,
        __flags: i32,
        __fd: i32,
        __offset: i64,
    ) -> *mut libc::c_void;
    fn munmap(__addr: *mut libc::c_void, __len: u64) -> i32;
    fn fstat(__fd: i32, __buf: *mut stat) -> i32;
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: i32,
    pub _IO_read_ptr: *mut i8,
    pub _IO_read_end: *mut i8,
    pub _IO_read_base: *mut i8,
    pub _IO_write_base: *mut i8,
    pub _IO_write_ptr: *mut i8,
    pub _IO_write_end: *mut i8,
    pub _IO_buf_base: *mut i8,
    pub _IO_buf_end: *mut i8,
    pub _IO_save_base: *mut i8,
    pub _IO_backup_base: *mut i8,
    pub _IO_save_end: *mut i8,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: i32,
    pub _flags2: i32,
    pub _old_offset: i64,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [i8; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: i64,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: u64,
    pub _mode: i32,
    pub _unused2: [i8; 20],
}
pub type FILE = _IO_FILE;
pub const memory_order_release: u32 = 2;
pub const memory_order_acquire: u32 = 1;
pub const memory_order_relaxed: u32 = 0;
pub const PYRRHIC_PRIME_BPAWN: u64 = 11695583624105689831;
pub const PYRRHIC_BPAWN: u32 = 9;
pub const PYRRHIC_PRIME_BKNIGHT: u64 = 13469005675588064321;
pub const PYRRHIC_BKNIGHT: u32 = 10;
pub const PYRRHIC_PRIME_BBISHOP: u64 = 15394650811035483107;
pub const PYRRHIC_BBISHOP: u32 = 11;
pub const PYRRHIC_PRIME_BROOK: u64 = 18264461213049635989;
pub const PYRRHIC_BROOK: u32 = 12;
pub const PYRRHIC_PRIME_BQUEEN: u64 = 15484752644942473553;
pub const PYRRHIC_BQUEEN: u32 = 13;
pub const PYRRHIC_PRIME_WPAWN: u64 = 17008651141875982339;
pub const PYRRHIC_WPAWN: u32 = 1;
pub const PYRRHIC_PRIME_WKNIGHT: u64 = 15202887380319082783;
pub const PYRRHIC_WKNIGHT: u32 = 2;
pub const PYRRHIC_PRIME_WBISHOP: u64 = 12311744257139811149;
pub const PYRRHIC_WBISHOP: u32 = 3;
pub const PYRRHIC_PRIME_WROOK: u64 = 10979190538029446137;
pub const PYRRHIC_WROOK: u32 = 4;
pub const PYRRHIC_PRIME_WQUEEN: u64 = 11811845319353239651;
pub const PYRRHIC_WQUEEN: u32 = 5;

#[repr(C)]
pub struct BaseEntry {
    pub key: u64,
    pub data: [*mut u8; 3],
    pub mapping: [u64; 3],
    pub ready: [AtomicBool; 3],
    pub num: u8,
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
    pub pawns: [u8; 2],
}

#[repr(C)]
pub struct PieceEntry {
    pub be: BaseEntry,
    pub ei: [EncInfo; 5],
    pub dtmMap: *mut u16,
    pub dtmMapIdx: [[u16; 2]; 2],
    pub dtzMap: *mut libc::c_void,
    pub dtzMapIdx: [u16; 4],
    pub dtzFlags: u8,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct EncInfo {
    pub precomp: *mut PairsData,
    pub factor: [u64; 7],
    pub pieces: [u8; 7],
    pub norm: [u8; 7],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PairsData {
    pub indexTable: *mut u8,
    pub sizeTable: *mut u16,
    pub data: *mut u8,
    pub offset: *mut u16,
    pub symLen: *mut u8,
    pub symPat: *mut u8,
    pub blockSize: u8,
    pub idxBits: u8,
    pub minLen: u8,
    pub constValue: [u8; 2],
    pub base: [u64; 1],
}

#[repr(C)]
pub struct PawnEntry {
    pub be: BaseEntry,
    pub ei: [EncInfo; 24],
    pub dtmMap: *mut u16,
    pub dtmMapIdx: [[[u16; 2]; 2]; 6],
    pub dtzMap: *mut libc::c_void,
    pub dtzMapIdx: [[u16; 4]; 4],
    pub dtzFlags: [u8; 4],
    pub dtmSwitched: bool,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TbHashEntry {
    pub key: u64,
    pub ptr: *mut BaseEntry,
}
pub const DTZ: u32 = 2;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: i32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atimensec: u64,
    pub st_mtime: i64,
    pub st_mtimensec: u64,
    pub st_ctime: i64,
    pub st_ctimensec: u64,
    pub __glibc_reserved: [i64; 3],
}
pub const DTM: u32 = 1;
pub const PYRRHIC_PAWN: u32 = 1;
pub const PYRRHIC_KING: u32 = 6;
pub const WDL: u32 = 0;
pub const PYRRHIC_QUEEN: u32 = 5;
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutexattr_t {
    pub __size: [i8; 4],
    pub __align: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [i8; 40],
    pub __align: i64,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __pthread_mutex_s {
    pub __lock: i32,
    pub __count: u32,
    pub __owner: i32,
    pub __nusers: u32,
    pub __kind: i32,
    pub __spins: i16,
    pub __elision: i16,
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
    pub white: u64,
    pub black: u64,
    pub kings: u64,
    pub queens: u64,
    pub rooks: u64,
    pub bishops: u64,
    pub knights: u64,
    pub pawns: u64,
    pub rule50: u8,
    pub ep: u8,
    pub turn: bool,
}
pub const RANK_ENC: u32 = 2;
pub const PIECE_ENC: u32 = 0;
pub const FILE_ENC: u32 = 1;
pub const PYRRHIC_WHITE: u32 = 1;
pub const PYRRHIC_ROOK: u32 = 4;
pub const PYRRHIC_BISHOP: u32 = 3;
pub const PYRRHIC_KNIGHT: u32 = 2;
pub const PYRRHIC_BLACK: u32 = 0;
pub const PYRRHIC_PRIME_NONE: u64 = 0;
pub const PYRRHIC_PRIME_BKING: u64 = 0;
pub const PYRRHIC_PRIME_WKING: u64 = 0;
pub type PyrrhicMove = u16;
pub const PYRRHIC_PROMOSQS: u64 = 18374686479671623935;
pub const PYRRHIC_PROMOTES_BISHOP: u32 = 3;
pub const PYRRHIC_PROMOTES_ROOK: u32 = 2;
pub const PYRRHIC_PROMOTES_KNIGHT: u32 = 4;
pub const PYRRHIC_PROMOTES_QUEEN: u32 = 1;
pub const PYRRHIC_PROMOTES_NONE: u32 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TbRootMove {
    pub move_0: PyrrhicMove,
    pub pv: [PyrrhicMove; 256],
    pub pvSize: u32,
    pub tbScore: i32,
    pub tbRank: i32,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct TbRootMoves {
    pub size: u32,
    pub moves: [TbRootMove; 256],
}
pub const PYRRHIC_BKING: u32 = 14;
pub const PYRRHIC_WKING: u32 = 6;
#[no_mangle]
pub unsafe extern "C" fn atomic_init(mut var: *mut AtomicBool, mut val: bool) {
    *var = AtomicBool::new(val)
}
#[no_mangle]
pub unsafe extern "C" fn atomic_load_explicit(mut var: *mut AtomicBool, mut ordering: i32) -> bool {
    let ordering = match ordering {
        0 => Ordering::Relaxed,
        1 => Ordering::Acquire,
        2 => Ordering::Release,
        _ => unreachable!(),
    };

    (*var).load(ordering)
}
#[no_mangle]
pub unsafe extern "C" fn atomic_store_explicit(
    mut var: *mut AtomicBool,
    mut val: bool,
    mut ordering: i32,
) {
    let ordering = match ordering {
        0 => Ordering::Relaxed,
        1 => Ordering::Acquire,
        2 => Ordering::Release,
        _ => unreachable!(),
    };
    (*var).store(val, ordering);
}
pub fn poplsb(mut x: &mut u64) -> u64 {
    let lsb = x.trailing_zeros();
    *x &= x.wrapping_sub(1);
    lsb as u64
}

use cozy_chess::*;
pub fn pawnAttacks(c: u64, sq: u64) -> u64 {
    let attacks = get_pawn_attacks(
        Square::index(sq as usize),
        if c == 0 { Color::Black } else { Color::White },
    );
    attacks.0
}
pub fn knightAttacks(sq: u64) -> u64 {
    get_knight_moves(Square::index(sq as usize)).0
}
pub fn popcount(x: u64) -> u64 {
    x.count_ones() as u64
}
pub fn bishopAttacks(sq: u64, occ: u64) -> u64 {
    get_bishop_moves(Square::index(sq as usize), BitBoard(occ)).0
}
pub fn getlsb(x: u64) -> u64 {
    x.trailing_zeros() as u64
}
pub fn rookAttacks(sq: u64, occ: u64) -> u64 {
    get_rook_moves(Square::index(sq as usize), BitBoard(occ)).0
}
pub fn kingAttacks(sq: u64) -> u64 {
    get_king_moves(Square::index(sq as usize)).0
}
pub fn queenAttacks(sq: u64, occ: u64) -> u64 {
    bishopAttacks(sq, occ) | rookAttacks(sq, occ)
}

#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: u32) -> u32 {
    (__bsx & 0xff000000 as u32) >> 24 as i32
        | (__bsx & 0xff0000 as u32) >> 8 as i32
        | (__bsx & 0xff00 as u32) << 8 as i32
        | (__bsx & 0xff as u32) << 24 as i32
}
#[inline]
unsafe extern "C" fn __bswap_64(mut __bsx: u64) -> u64 {
    (__bsx as u64 & 0xff00000000000000 as u64) >> 56 as i32
        | (__bsx as u64 & 0xff000000000000 as u64) >> 40 as i32
        | (__bsx as u64 & 0xff0000000000 as u64) >> 24 as i32
        | (__bsx as u64 & 0xff00000000 as u64) >> 8 as i32
        | (__bsx as u64 & 0xff000000 as u64) << 8 as i32
        | (__bsx as u64 & 0xff0000 as u64) << 24 as i32
        | (__bsx as u64 & 0xff00 as u64) << 40 as i32
        | (__bsx as u64 & 0xff as u64) << 56 as i32
}
unsafe extern "C" fn from_le_u32(mut x: u32) -> u32 {
    x
}
unsafe extern "C" fn from_le_u16(mut x: u16) -> u16 {
    x
}
unsafe extern "C" fn from_be_u64(mut x: u64) -> u64 {
    __bswap_64(x)
}
unsafe extern "C" fn from_be_u32(mut x: u32) -> u32 {
    __bswap_32(x)
}
#[inline]
unsafe extern "C" fn read_le_u32(mut p: *mut libc::c_void) -> u32 {
    let le_u32 = (p as *mut u32).read_unaligned();
    from_le_u32(le_u32)
}
#[inline]
unsafe extern "C" fn read_le_u16(mut p: *mut libc::c_void) -> u16 {
    let le_u16 = (p as *mut u16).read_unaligned();
    from_le_u16(le_u16)
}
unsafe extern "C" fn file_size(mut fd: i32) -> u64 {
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
        0 as i32 as u64
    } else {
        buf.st_size as u64
    }
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
static mut initialized: i32 = 0 as i32;
static mut numPaths: i32 = 0 as i32;
static mut pathString: *mut i8 = 0 as *const i8 as *mut i8;
static mut paths: *mut *mut i8 = 0 as *const *mut i8 as *mut *mut i8;
unsafe extern "C" fn open_tb(mut str: *const i8, mut suffix: *const i8) -> i32 {
    let mut i: i32 = 0;
    let mut fd: i32 = 0;
    let mut file: *mut i8 = std::ptr::null_mut::<i8>();
    i = 0 as i32;
    while i < numPaths {
        file = malloc(
            (strlen(*paths.offset(i as isize)))
                .wrapping_add(strlen(str))
                .wrapping_add(strlen(suffix))
                .wrapping_add(2 as i32 as u64),
        ) as *mut i8;
        strcpy(file, *paths.offset(i as isize));
        strcat(file, b"/\0" as *const u8 as *const i8);
        strcat(file, str);
        strcat(file, suffix);
        fd = open(file, 0 as i32);
        free(file as *mut libc::c_void);
        if fd != -(1 as i32) {
            return fd;
        }
        i += 1;
    }
    -(1 as i32)
}
unsafe extern "C" fn close_tb(mut fd: i32) {
    close(fd);
}
unsafe extern "C" fn map_file(mut fd: i32, mut mapping: *mut u64) -> *mut libc::c_void {
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
        perror(b"fstat\0" as *const u8 as *const i8);
        close_tb(fd);
        return std::ptr::null_mut::<libc::c_void>();
    }
    *mapping = statbuf.st_size as u64;
    let mut data: *mut libc::c_void = mmap(
        std::ptr::null_mut::<libc::c_void>(),
        statbuf.st_size as u64,
        0x1 as i32,
        0x1 as i32,
        fd,
        0 as i32 as i64,
    );
    if data == -(1 as i32) as *mut libc::c_void {
        perror(b"mmap\0" as *const u8 as *const i8);
        return std::ptr::null_mut::<libc::c_void>();
    }
    data
}
unsafe extern "C" fn unmap_file(mut data: *mut libc::c_void, mut size: u64) {
    if data.is_null() {
        return;
    }
    if munmap(data, size) < 0 as i32 {
        perror(b"munmap\0" as *const u8 as *const i8);
    }
}
#[no_mangle]
pub static mut TB_MaxCardinality: i32 = 0 as i32;
#[no_mangle]
pub static mut TB_MaxCardinalityDTM: i32 = 0 as i32;
#[no_mangle]
pub static mut TB_LARGEST: i32 = 0 as i32;
#[no_mangle]
pub static mut TB_NUM_WDL: i32 = 0 as i32;
#[no_mangle]
pub static mut TB_NUM_DTM: i32 = 0 as i32;
#[no_mangle]
pub static mut TB_NUM_DTZ: i32 = 0 as i32;
static mut tbSuffix: [*const i8; 3] = [
    b".rtbw\0" as *const u8 as *const i8,
    b".rtbm\0" as *const u8 as *const i8,
    b".rtbz\0" as *const u8 as *const i8,
];
static mut tbMagic: [u32; 3] = [
    0x5d23e871 as i32 as u32,
    0x88ac504b as u32,
    0xa50c66d7 as u32,
];
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_move_from(mut move_0: PyrrhicMove) -> u32 {
    (move_0 as i32 >> 6 as i32 & 0x3f as i32) as u32
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_move_to(mut move_0: PyrrhicMove) -> u32 {
    (move_0 as i32 >> 0 as i32 & 0x3f as i32) as u32
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_move_promotes(mut move_0: PyrrhicMove) -> u32 {
    (move_0 as i32 >> 12 as i32 & 0x7 as i32) as u32
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_colour_of_piece(mut piece: u8) -> i32 {
    (piece as i32 >> 3 as i32 == 0) as i32
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_type_of_piece(mut piece: u8) -> i32 {
    piece as i32 & 0x7 as i32
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_test_bit(mut bb: u64, mut sq: i32) -> bool {
    bb >> sq & 0x1 as i32 as u64 != 0
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_enable_bit(mut b: *mut u64, mut sq: i32) {
    *b = *b as u64 | (1 as u64) << sq;
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_disable_bit(mut b: *mut u64, mut sq: i32) {
    *b = *b as u64 & !((1 as u64) << sq);
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_promo_square(mut sq: i32) -> bool {
    PYRRHIC_PROMOSQS as u64 >> sq & 0x1 as i32 as u64 != 0
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_pawn_start_square(mut colour: i32, mut sq: i32) -> bool {
    sq >> 3 as i32 == (if colour != 0 { 1 as i32 } else { 6 as i32 })
}
#[no_mangle]
pub static mut pyrrhic_piece_to_char: [i8; 16] =
    unsafe { *::core::mem::transmute::<&[u8; 16], &[i8; 16]>(b" PNBRQK  pnbrqk\0") };
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_pieces_by_type(
    mut pos: *const PyrrhicPosition,
    mut colour: i32,
    mut piece: i32,
) -> u64 {
    if PYRRHIC_PAWN as i32 <= piece && piece <= PYRRHIC_KING as i32 {
    } else {
        __assert_fail(
            b"PYRRHIC_PAWN <= piece && piece <= PYRRHIC_KING\0" as *const u8 as *const i8,
            b"./tbchess.c\0" as *const u8 as *const i8,
            94 as i32 as u32,
            (*::core::mem::transmute::<&[u8; 67], &[i8; 67]>(
                b"uint64_t pyrrhic_pieces_by_type(const PyrrhicPosition *, int, int)\0",
            ))
            .as_ptr(),
        );
    };
    if colour == PYRRHIC_WHITE as i32 || colour == PYRRHIC_BLACK as i32 {
    } else {
        __assert_fail(
            b"colour == PYRRHIC_WHITE || colour == PYRRHIC_BLACK\0" as *const u8 as *const i8,
            b"./tbchess.c\0" as *const u8 as *const i8,
            95 as i32 as u32,
            (*::core::mem::transmute::<&[u8; 67], &[i8; 67]>(
                b"uint64_t pyrrhic_pieces_by_type(const PyrrhicPosition *, int, int)\0",
            ))
            .as_ptr(),
        );
    };
    let mut side: u64 = if colour == PYRRHIC_WHITE as i32 {
        (*pos).white
    } else {
        (*pos).black
    };
    match piece {
        1 => (*pos).pawns & side,
        2 => (*pos).knights & side,
        3 => (*pos).bishops & side,
        4 => (*pos).rooks & side,
        5 => (*pos).queens & side,
        6 => (*pos).kings & side,
        _ => {
            if 0 as i32 != 0 {
            } else {
                __assert_fail(
                    b"0\0" as *const u8 as *const i8,
                    b"./tbchess.c\0" as *const u8 as *const i8,
                    106 as i32 as u32,
                    (*::core::mem::transmute::<&[u8; 67], &[i8; 67]>(
                        b"uint64_t pyrrhic_pieces_by_type(const PyrrhicPosition *, int, int)\0",
                    ))
                    .as_ptr(),
                );
            };
            0 as i32 as u64
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_char_to_piece_type(mut c: i8) -> i32 {
    let mut i: i32 = PYRRHIC_PAWN as i32;
    while i <= PYRRHIC_KING as i32 {
        if c as i32 == pyrrhic_piece_to_char[i as usize] as i32 {
            return i;
        }
        i += 1;
    }
    0 as i32
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_calc_key(mut pos: *const PyrrhicPosition, mut mirror: i32) -> u64 {
    let mut white: u64 = if mirror != 0 {
        (*pos).black
    } else {
        (*pos).white
    };
    let mut black: u64 = if mirror != 0 {
        (*pos).white
    } else {
        (*pos).black
    };
    (popcount(white & (*pos).queens))
        .wrapping_mul(PYRRHIC_PRIME_WQUEEN as u64)
        .wrapping_add((popcount(white & (*pos).rooks)).wrapping_mul(PYRRHIC_PRIME_WROOK as u64))
        .wrapping_add((popcount(white & (*pos).bishops)).wrapping_mul(PYRRHIC_PRIME_WBISHOP as u64))
        .wrapping_add((popcount(white & (*pos).knights)).wrapping_mul(PYRRHIC_PRIME_WKNIGHT as u64))
        .wrapping_add((popcount(white & (*pos).pawns)).wrapping_mul(PYRRHIC_PRIME_WPAWN as u64))
        .wrapping_add((popcount(black & (*pos).queens)).wrapping_mul(PYRRHIC_PRIME_BQUEEN as u64))
        .wrapping_add((popcount(black & (*pos).rooks)).wrapping_mul(PYRRHIC_PRIME_BROOK as u64))
        .wrapping_add((popcount(black & (*pos).bishops)).wrapping_mul(PYRRHIC_PRIME_BBISHOP as u64))
        .wrapping_add((popcount(black & (*pos).knights)).wrapping_mul(PYRRHIC_PRIME_BKNIGHT as u64))
        .wrapping_add((popcount(black & (*pos).pawns)).wrapping_mul(PYRRHIC_PRIME_BPAWN as u64))
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_calc_key_from_pcs(mut pieces: *mut i32, mut mirror: i32) -> u64 {
    (*pieces
        .offset((PYRRHIC_WQUEEN as i32 ^ (if mirror != 0 { 8 as i32 } else { 0 as i32 })) as isize)
        as u64)
        .wrapping_mul(PYRRHIC_PRIME_WQUEEN as u64)
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_WROOK as i32 ^ (if mirror != 0 { 8 as i32 } else { 0 as i32 })) as isize,
            ) as u64)
                .wrapping_mul(PYRRHIC_PRIME_WROOK as u64),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_WBISHOP as i32 ^ (if mirror != 0 { 8 as i32 } else { 0 as i32 })) as isize,
            ) as u64)
                .wrapping_mul(PYRRHIC_PRIME_WBISHOP as u64),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_WKNIGHT as i32 ^ (if mirror != 0 { 8 as i32 } else { 0 as i32 })) as isize,
            ) as u64)
                .wrapping_mul(PYRRHIC_PRIME_WKNIGHT as u64),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_WPAWN as i32 ^ (if mirror != 0 { 8 as i32 } else { 0 as i32 })) as isize,
            ) as u64)
                .wrapping_mul(PYRRHIC_PRIME_WPAWN as u64),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_BQUEEN as i32 ^ (if mirror != 0 { 8 as i32 } else { 0 as i32 })) as isize,
            ) as u64)
                .wrapping_mul(PYRRHIC_PRIME_BQUEEN as u64),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_BROOK as i32 ^ (if mirror != 0 { 8 as i32 } else { 0 as i32 })) as isize,
            ) as u64)
                .wrapping_mul(PYRRHIC_PRIME_BROOK as u64),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_BBISHOP as i32 ^ (if mirror != 0 { 8 as i32 } else { 0 as i32 })) as isize,
            ) as u64)
                .wrapping_mul(PYRRHIC_PRIME_BBISHOP as u64),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_BKNIGHT as i32 ^ (if mirror != 0 { 8 as i32 } else { 0 as i32 })) as isize,
            ) as u64)
                .wrapping_mul(PYRRHIC_PRIME_BKNIGHT as u64),
        )
        .wrapping_add(
            (*pieces.offset(
                (PYRRHIC_BPAWN as i32 ^ (if mirror != 0 { 8 as i32 } else { 0 as i32 })) as isize,
            ) as u64)
                .wrapping_mul(PYRRHIC_PRIME_BPAWN as u64),
        )
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_calc_key_from_pieces(mut pieces: *mut u8, mut length: i32) -> u64 {
    static mut PyrrhicPrimes: [u64; 16] = [
        PYRRHIC_PRIME_NONE as i32 as u64,
        PYRRHIC_PRIME_WPAWN as u64,
        PYRRHIC_PRIME_WKNIGHT as u64,
        PYRRHIC_PRIME_WBISHOP as u64,
        PYRRHIC_PRIME_WROOK as u64,
        PYRRHIC_PRIME_WQUEEN as u64,
        PYRRHIC_PRIME_WKING as i32 as u64,
        PYRRHIC_PRIME_NONE as i32 as u64,
        PYRRHIC_PRIME_NONE as i32 as u64,
        PYRRHIC_PRIME_BPAWN as u64,
        PYRRHIC_PRIME_BKNIGHT as u64,
        PYRRHIC_PRIME_BBISHOP as u64,
        PYRRHIC_PRIME_BROOK as u64,
        PYRRHIC_PRIME_BQUEEN as u64,
        PYRRHIC_PRIME_BKING as i32 as u64,
        PYRRHIC_PRIME_NONE as i32 as u64,
    ];
    let mut key: u64 = 0 as i32 as u64;
    let mut i: i32 = 0 as i32;
    while i < length {
        key = key.wrapping_add(PyrrhicPrimes[*pieces.offset(i as isize) as usize]);
        i += 1;
    }
    key
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_do_bb_move(mut bb: u64, mut from: u32, mut to: u32) -> u64 {
    ((bb >> from & 0x1 as i32 as u64) << to) as u64
        | bb as u64 & (!((1 as u64) << from) & !((1 as u64) << to))
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_make_move(
    mut promote: u32,
    mut from: u32,
    mut to: u32,
) -> PyrrhicMove {
    ((promote & 0x7 as i32 as u32) << 12 as i32
        | (from & 0x3f as i32 as u32) << 6 as i32
        | to & 0x3f as i32 as u32) as PyrrhicMove
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_add_move(
    mut moves: *mut PyrrhicMove,
    mut promotes: i32,
    mut from: u32,
    mut to: u32,
) -> *mut PyrrhicMove {
    if promotes == 0 {
        let fresh0 = moves;
        moves = moves.offset(1);
        *fresh0 = pyrrhic_make_move(PYRRHIC_PROMOTES_NONE as i32 as u32, from, to);
    } else {
        let fresh1 = moves;
        moves = moves.offset(1);
        *fresh1 = pyrrhic_make_move(PYRRHIC_PROMOTES_QUEEN as i32 as u32, from, to);
        let fresh2 = moves;
        moves = moves.offset(1);
        *fresh2 = pyrrhic_make_move(PYRRHIC_PROMOTES_KNIGHT as i32 as u32, from, to);
        let fresh3 = moves;
        moves = moves.offset(1);
        *fresh3 = pyrrhic_make_move(PYRRHIC_PROMOTES_ROOK as i32 as u32, from, to);
        let fresh4 = moves;
        moves = moves.offset(1);
        *fresh4 = pyrrhic_make_move(PYRRHIC_PROMOTES_BISHOP as i32 as u32, from, to);
    }
    moves
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_gen_captures(
    mut pos: *const PyrrhicPosition,
    mut moves: *mut PyrrhicMove,
) -> *mut PyrrhicMove {
    let mut us: u64 = if (*pos).turn as i32 != 0 {
        (*pos).white
    } else {
        (*pos).black
    };
    let mut them: u64 = if (*pos).turn as i32 != 0 {
        (*pos).black
    } else {
        (*pos).white
    };
    let mut b: u64 = 0;
    let mut att: u64 = 0;
    b = us & (*pos).kings;
    while b != 0 {
        att = kingAttacks(getlsb(b)) & them;
        while att != 0 {
            moves = pyrrhic_add_move(moves, 0 as i32, getlsb(b) as u32, getlsb(att) as u32);
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & ((*pos).rooks | (*pos).queens);
    while b != 0 {
        att = rookAttacks(getlsb(b), us | them) & them;
        while att != 0 {
            moves = pyrrhic_add_move(moves, 0 as i32, getlsb(b) as u32, getlsb(att) as u32);
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & ((*pos).bishops | (*pos).queens);
    while b != 0 {
        att = bishopAttacks(getlsb(b), us | them) & them;
        while att != 0 {
            moves = pyrrhic_add_move(moves, 0 as i32, getlsb(b) as u32, getlsb(att) as u32);
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & (*pos).knights;
    while b != 0 {
        att = knightAttacks(getlsb(b)) & them;
        while att != 0 {
            moves = pyrrhic_add_move(moves, 0 as i32, getlsb(b) as u32, getlsb(att) as u32);
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & (*pos).pawns;
    while b != 0 {
        if (*pos).ep as i32 != 0
            && pyrrhic_test_bit(
                pawnAttacks(!(*pos).turn as i32 as u64, getlsb(b)),
                (*pos).ep as i32,
            ) as i32
                != 0
        {
            moves = pyrrhic_add_move(moves, 0 as i32, getlsb(b) as u32, (*pos).ep as u32);
        }
        att = pawnAttacks(!(*pos).turn as i32 as u64, getlsb(b)) & them;
        while att != 0 {
            moves = pyrrhic_add_move(
                moves,
                pyrrhic_promo_square(getlsb(att) as i32) as i32,
                getlsb(b) as u32,
                getlsb(att) as u32,
            );
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    moves
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_gen_moves(
    mut pos: *const PyrrhicPosition,
    mut moves: *mut PyrrhicMove,
) -> *mut PyrrhicMove {
    let Forward: u32 = (if (*pos).turn as i32 == PYRRHIC_WHITE as i32 {
        8 as i32
    } else {
        -(8 as i32)
    }) as u32;
    let mut us: u64 = if (*pos).turn as i32 != 0 {
        (*pos).white
    } else {
        (*pos).black
    };
    let mut them: u64 = if (*pos).turn as i32 != 0 {
        (*pos).black
    } else {
        (*pos).white
    };
    let mut b: u64 = 0;
    let mut att: u64 = 0;
    b = us & (*pos).kings;
    while b != 0 {
        att = kingAttacks(getlsb(b)) & !us;
        while att != 0 {
            moves = pyrrhic_add_move(moves, 0 as i32, getlsb(b) as u32, getlsb(att) as u32);
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & ((*pos).rooks | (*pos).queens);
    while b != 0 {
        att = rookAttacks(getlsb(b), us | them) & !us;
        while att != 0 {
            moves = pyrrhic_add_move(moves, 0 as i32, getlsb(b) as u32, getlsb(att) as u32);
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & ((*pos).bishops | (*pos).queens);
    while b != 0 {
        att = bishopAttacks(getlsb(b), us | them) & !us;
        while att != 0 {
            moves = pyrrhic_add_move(moves, 0 as i32, getlsb(b) as u32, getlsb(att) as u32);
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & (*pos).knights;
    while b != 0 {
        att = knightAttacks(getlsb(b)) & !us;
        while att != 0 {
            moves = pyrrhic_add_move(moves, 0 as i32, getlsb(b) as u32, getlsb(att) as u32);
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    b = us & (*pos).pawns;
    while b != 0 {
        let mut from: u32 = getlsb(b) as u32;
        if (*pos).ep as i32 != 0
            && pyrrhic_test_bit(
                pawnAttacks(!(*pos).turn as i32 as u64, from as u64),
                (*pos).ep as i32,
            ) as i32
                != 0
        {
            moves = pyrrhic_add_move(moves, 0 as i32, from, (*pos).ep as u32);
        }
        if !pyrrhic_test_bit(us | them, from.wrapping_add(Forward) as i32) {
            moves = pyrrhic_add_move(
                moves,
                pyrrhic_promo_square(from.wrapping_add(Forward) as i32) as i32,
                from,
                from.wrapping_add(Forward),
            );
        }
        if pyrrhic_pawn_start_square((*pos).turn as i32, from as i32) as i32 != 0
            && !pyrrhic_test_bit(us | them, from.wrapping_add(Forward) as i32)
            && !pyrrhic_test_bit(
                us | them,
                from.wrapping_add((2 as i32 as u32).wrapping_mul(Forward)) as i32,
            )
        {
            moves = pyrrhic_add_move(
                moves,
                0 as i32,
                from,
                from.wrapping_add((2 as i32 as u32).wrapping_mul(Forward)),
            );
        }
        att = pawnAttacks(!(*pos).turn as i32 as u64, from as u64) & them;
        while att != 0 {
            moves = pyrrhic_add_move(
                moves,
                pyrrhic_promo_square(getlsb(att) as i32) as i32,
                from,
                getlsb(att) as u32,
            );
            poplsb(&mut att);
        }
        poplsb(&mut b);
    }
    moves
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
    }
    results
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_is_pawn_move(
    mut pos: *const PyrrhicPosition,
    mut move_0: PyrrhicMove,
) -> bool {
    let mut us: u64 = if (*pos).turn as i32 != 0 {
        (*pos).white
    } else {
        (*pos).black
    };
    pyrrhic_test_bit(us & (*pos).pawns, pyrrhic_move_from(move_0) as i32)
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_is_en_passant(
    mut pos: *const PyrrhicPosition,
    mut move_0: PyrrhicMove,
) -> bool {
    pyrrhic_is_pawn_move(pos, move_0) as i32 != 0
        && pyrrhic_move_to(move_0) == (*pos).ep as u32
        && (*pos).ep as i32 != 0
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_is_capture(
    mut pos: *const PyrrhicPosition,
    mut move_0: PyrrhicMove,
) -> bool {
    let mut them: u64 = if (*pos).turn as i32 != 0 {
        (*pos).black
    } else {
        (*pos).white
    };
    pyrrhic_test_bit(them, pyrrhic_move_to(move_0) as i32) as i32 != 0
        || pyrrhic_is_en_passant(pos, move_0) as i32 != 0
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_is_legal(mut pos: *const PyrrhicPosition) -> bool {
    let mut us: u64 = if (*pos).turn as i32 != 0 {
        (*pos).black
    } else {
        (*pos).white
    };
    let mut them: u64 = if (*pos).turn as i32 != 0 {
        (*pos).white
    } else {
        (*pos).black
    };
    let mut sq: u32 = getlsb((*pos).kings & us) as u32;
    kingAttacks(sq as u64) & (*pos).kings & them == 0
        && rookAttacks(sq as u64, us | them) & ((*pos).rooks | (*pos).queens) & them == 0
        && bishopAttacks(sq as u64, us | them) & ((*pos).bishops | (*pos).queens) & them == 0
        && knightAttacks(sq as u64) & (*pos).knights & them == 0
        && pawnAttacks((*pos).turn as i32 as u64, sq as u64) & (*pos).pawns & them == 0
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_is_check(mut pos: *const PyrrhicPosition) -> bool {
    let mut us: u64 = if (*pos).turn as i32 != 0 {
        (*pos).white
    } else {
        (*pos).black
    };
    let mut them: u64 = if (*pos).turn as i32 != 0 {
        (*pos).black
    } else {
        (*pos).white
    };
    let mut sq: u32 = getlsb((*pos).kings & us) as u32;
    rookAttacks(sq as u64, us | them) & (((*pos).rooks | (*pos).queens) & them) != 0
        || bishopAttacks(sq as u64, us | them) & (((*pos).bishops | (*pos).queens) & them) != 0
        || knightAttacks(sq as u64) & ((*pos).knights & them) != 0
        || pawnAttacks(!(*pos).turn as i32 as u64, sq as u64) & ((*pos).pawns & them) != 0
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_is_mate(mut pos: *const PyrrhicPosition) -> bool {
    if !pyrrhic_is_check(pos) {
        return 0 as i32 != 0;
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
            return 0 as i32 != 0;
        }
        moves = moves.offset(1);
    }
    1 as i32 != 0
}
#[no_mangle]
pub unsafe extern "C" fn pyrrhic_do_move(
    mut pos: *mut PyrrhicPosition,
    mut pos0: *const PyrrhicPosition,
    mut move_0: PyrrhicMove,
) -> bool {
    let mut from: u32 = pyrrhic_move_from(move_0);
    let mut to: u32 = pyrrhic_move_to(move_0);
    let mut promotes: u32 = pyrrhic_move_promotes(move_0);
    (*pos).turn = !(*pos0).turn;
    (*pos).white = pyrrhic_do_bb_move((*pos0).white, from, to);
    (*pos).black = pyrrhic_do_bb_move((*pos0).black, from, to);
    (*pos).kings = pyrrhic_do_bb_move((*pos0).kings, from, to);
    (*pos).queens = pyrrhic_do_bb_move((*pos0).queens, from, to);
    (*pos).rooks = pyrrhic_do_bb_move((*pos0).rooks, from, to);
    (*pos).bishops = pyrrhic_do_bb_move((*pos0).bishops, from, to);
    (*pos).knights = pyrrhic_do_bb_move((*pos0).knights, from, to);
    (*pos).pawns = pyrrhic_do_bb_move((*pos0).pawns, from, to);
    (*pos).ep = 0 as i32 as u8;
    if promotes != PYRRHIC_PROMOTES_NONE as i32 as u32 {
        pyrrhic_disable_bit(&mut (*pos).pawns, to as i32);
        match promotes {
            1 => {
                pyrrhic_enable_bit(&mut (*pos).queens, to as i32);
            }
            2 => {
                pyrrhic_enable_bit(&mut (*pos).rooks, to as i32);
            }
            3 => {
                pyrrhic_enable_bit(&mut (*pos).bishops, to as i32);
            }
            4 => {
                pyrrhic_enable_bit(&mut (*pos).knights, to as i32);
            }
            _ => {}
        }
        (*pos).rule50 = 0 as i32 as u8;
    } else if pyrrhic_test_bit((*pos0).pawns, from as i32) {
        (*pos).rule50 = 0 as i32 as u8;
        if from ^ to == 16 as i32 as u32
            && (*pos0).turn as i32 == PYRRHIC_WHITE as i32
            && pawnAttacks(
                (PYRRHIC_WHITE as i32 == 0) as i32 as u64,
                from.wrapping_add(8 as i32 as u32) as u64,
            ) & (*pos0).pawns
                & (*pos0).black
                != 0
        {
            (*pos).ep = from.wrapping_add(8 as i32 as u32) as u8;
        }
        if from ^ to == 16 as i32 as u32
            && (*pos0).turn as i32 == PYRRHIC_BLACK as i32
            && pawnAttacks(
                (PYRRHIC_BLACK as i32 == 0) as i32 as u64,
                from.wrapping_sub(8 as i32 as u32) as u64,
            ) & (*pos0).pawns
                & (*pos0).white
                != 0
        {
            (*pos).ep = from.wrapping_sub(8 as i32 as u32) as u8;
        } else if to == (*pos0).ep as u32 {
            pyrrhic_disable_bit(
                &mut (*pos).white,
                (if (*pos0).turn as i32 != 0 {
                    to.wrapping_sub(8 as i32 as u32)
                } else {
                    to.wrapping_add(8 as i32 as u32)
                }) as i32,
            );
            pyrrhic_disable_bit(
                &mut (*pos).black,
                (if (*pos0).turn as i32 != 0 {
                    to.wrapping_sub(8 as i32 as u32)
                } else {
                    to.wrapping_add(8 as i32 as u32)
                }) as i32,
            );
            pyrrhic_disable_bit(
                &mut (*pos).pawns,
                (if (*pos0).turn as i32 != 0 {
                    to.wrapping_sub(8 as i32 as u32)
                } else {
                    to.wrapping_add(8 as i32 as u32)
                }) as i32,
            );
        }
    } else if pyrrhic_test_bit((*pos0).white | (*pos0).black, to as i32) {
        (*pos).rule50 = 0 as i32 as u8;
    } else {
        (*pos).rule50 = ((*pos0).rule50 as i32 + 1 as i32) as u8;
    }
    pyrrhic_is_legal(pos)
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
    pyrrhic_do_move(&mut pos1, pos, move_0)
}
static mut tbNumPiece: i32 = 0;
static mut tbNumPawn: i32 = 0;
static mut numWdl: i32 = 0;
static mut numDtm: i32 = 0;
static mut numDtz: i32 = 0;
static mut pieceEntry: *mut PieceEntry = 0 as *const PieceEntry as *mut PieceEntry;
static mut pawnEntry: *mut PawnEntry = 0 as *const PawnEntry as *mut PawnEntry;
static mut tbHash: [TbHashEntry; 4096] = [TbHashEntry {
    key: 0,
    ptr: 0 as *const BaseEntry as *mut BaseEntry,
}; 4096];
unsafe extern "C" fn dtz_to_wdl(mut cnt50: i32, mut dtz: i32) -> u32 {
    let mut wdl: i32 = 0 as i32;
    if dtz > 0 as i32 {
        wdl = if dtz + cnt50 <= 100 as i32 {
            2 as i32
        } else {
            1 as i32
        };
    } else if dtz < 0 as i32 {
        wdl = if -dtz + cnt50 <= 100 as i32 {
            -(2 as i32)
        } else {
            -(1 as i32)
        };
    }
    (wdl + 2 as i32) as u32
}
#[no_mangle]
pub unsafe extern "C" fn tb_probe_wdl(
    mut white: u64,
    mut black: u64,
    mut kings: u64,
    mut queens: u64,
    mut rooks: u64,
    mut bishops: u64,
    mut knights: u64,
    mut pawns: u64,
    mut ep: u32,
    mut turn: bool,
) -> u32 {
    let mut pos: PyrrhicPosition = {
        PyrrhicPosition {
            white,
            black,
            kings,
            queens,
            rooks,
            bishops,
            knights,
            pawns,
            rule50: 0 as i32 as u8,
            ep: ep as u8,
            turn,
        }
    };
    let mut success: i32 = 0;
    let mut v: i32 = probe_wdl(&mut pos, &mut success);
    if success == 0 as i32 {
        return 0xffffffff as u32;
    }
    (v + 2 as i32) as u32
}
#[no_mangle]
pub unsafe extern "C" fn tb_probe_root(
    mut white: u64,
    mut black: u64,
    mut kings: u64,
    mut queens: u64,
    mut rooks: u64,
    mut bishops: u64,
    mut knights: u64,
    mut pawns: u64,
    mut rule50: u32,
    mut ep: u32,
    mut turn: bool,
    mut results: *mut u32,
) -> u32 {
    let mut pos: PyrrhicPosition = {
        PyrrhicPosition {
            white,
            black,
            kings,
            queens,
            rooks,
            bishops,
            knights,
            pawns,
            rule50: rule50 as u8,
            ep: ep as u8,
            turn,
        }
    };
    let mut dtz: i32 = 0;
    let mut move_0: PyrrhicMove = probe_root(&mut pos, &mut dtz, results);
    if move_0 as i32 == 0 as i32 {
        return 0xffffffff as u32;
    }
    if move_0 as i32 == 0xfffe as i32 {
        return (0 as i32 & !(0xf as i32) | (4 as i32) << 0 as i32 & 0xf as i32) as u32;
    }
    if move_0 as i32 == 0xffff as i32 {
        return (0 as i32 & !(0xf as i32) | (2 as i32) << 0 as i32 & 0xf as i32) as u32;
    }
    let mut res: u32 = 0 as i32 as u32;
    res =
        res & !(0xf as i32) as u32 | dtz_to_wdl(rule50 as i32, dtz) << 0 as i32 & 0xf as i32 as u32;
    res = res & !(0xfff00000 as u32)
        | ((if dtz < 0 as i32 { -dtz } else { dtz }) << 20 as i32) as u32 & 0xfff00000 as u32;
    res = res & !(0xfc00 as i32) as u32
        | pyrrhic_move_from(move_0) << 10 as i32 & 0xfc00 as i32 as u32;
    res = res & !(0x3f0 as i32) as u32 | pyrrhic_move_to(move_0) << 4 as i32 & 0x3f0 as i32 as u32;
    res = res & !(0x70000 as i32) as u32
        | pyrrhic_move_promotes(move_0) << 16 as i32 & 0x70000 as i32 as u32;
    res = res & !(0x80000 as i32) as u32
        | ((pyrrhic_is_en_passant(&mut pos, move_0) as i32) << 19 as i32 & 0x80000 as i32) as u32;
    res
}
#[no_mangle]
pub unsafe extern "C" fn tb_probe_root_dtz(
    mut white: u64,
    mut black: u64,
    mut kings: u64,
    mut queens: u64,
    mut rooks: u64,
    mut bishops: u64,
    mut knights: u64,
    mut pawns: u64,
    mut rule50: u32,
    mut ep: u32,
    mut turn: bool,
    mut hasRepeated: bool,
    mut useRule50: bool,
    mut results: *mut TbRootMoves,
) -> i32 {
    let mut pos: PyrrhicPosition = {
        PyrrhicPosition {
            white,
            black,
            kings,
            queens,
            rooks,
            bishops,
            knights,
            pawns,
            rule50: rule50 as u8,
            ep: ep as u8,
            turn,
        }
    };
    root_probe_dtz(&mut pos, hasRepeated, useRule50, results)
}
#[no_mangle]
pub unsafe extern "C" fn tb_probe_root_wdl(
    mut white: u64,
    mut black: u64,
    mut kings: u64,
    mut queens: u64,
    mut rooks: u64,
    mut bishops: u64,
    mut knights: u64,
    mut pawns: u64,
    mut rule50: u32,
    mut ep: u32,
    mut turn: bool,
    mut useRule50: bool,
    mut results: *mut TbRootMoves,
) -> i32 {
    let mut pos: PyrrhicPosition = {
        PyrrhicPosition {
            white,
            black,
            kings,
            queens,
            rooks,
            bishops,
            knights,
            pawns,
            rule50: rule50 as u8,
            ep: ep as u8,
            turn,
        }
    };
    root_probe_wdl(&mut pos, useRule50, results)
}
unsafe extern "C" fn prt_str(mut pos: *const PyrrhicPosition, mut str: *mut i8, mut flip: i32) {
    let mut color: i32 = if flip != 0 {
        PYRRHIC_BLACK as i32
    } else {
        PYRRHIC_WHITE as i32
    };
    let mut pt: i32 = PYRRHIC_KING as i32;
    while pt >= PYRRHIC_PAWN as i32 {
        let mut i: i32 = popcount(pyrrhic_pieces_by_type(pos, color, pt)) as i32;
        while i > 0 as i32 {
            let fresh6 = str;
            str = str.offset(1);
            *fresh6 = pyrrhic_piece_to_char[pt as usize];
            i -= 1;
        }
        pt -= 1;
    }
    let fresh7 = str;
    str = str.offset(1);
    *fresh7 = 'v' as i32 as i8;
    let mut pt_0: i32 = PYRRHIC_KING as i32;
    while pt_0 >= PYRRHIC_PAWN as i32 {
        let mut i_0: i32 = popcount(pyrrhic_pieces_by_type(pos, color ^ 1 as i32, pt_0)) as i32;
        while i_0 > 0 as i32 {
            let fresh8 = str;
            str = str.offset(1);
            *fresh8 = pyrrhic_piece_to_char[pt_0 as usize];
            i_0 -= 1;
        }
        pt_0 -= 1;
    }
    let fresh9 = str;
    str = str.offset(1);
    *fresh9 = 0 as i32 as i8;
}
unsafe extern "C" fn test_tb(mut str: *const i8, mut suffix: *const i8) -> i32 {
    let mut fd: i32 = open_tb(str, suffix);
    if fd != -(1 as i32) {
        let mut size: u64 = file_size(fd);
        close_tb(fd);
        if size & 63 as i32 as u64 != 16 as i32 as u64 {
            fprintf(
                stderr,
                b"Incomplete tablebase file %s.%s\n\0" as *const u8 as *const i8,
                str,
                suffix,
            );
            printf(
                b"info string Incomplete tablebase file %s.%s\n\0" as *const u8 as *const i8,
                str,
                suffix,
            );
            fd = -(1 as i32);
        }
    }
    (fd != -(1 as i32)) as i32
}
unsafe extern "C" fn map_tb(
    mut name: *const i8,
    mut suffix: *const i8,
    mut mapping: *mut u64,
) -> *mut libc::c_void {
    let mut fd: i32 = open_tb(name, suffix);
    if fd == -(1 as i32) {
        return std::ptr::null_mut::<libc::c_void>();
    }
    let mut data: *mut libc::c_void = map_file(fd, mapping);
    if data.is_null() {
        fprintf(
            stderr,
            b"Could not map %s%s into memory.\n\0" as *const u8 as *const i8,
            name,
            suffix,
        );
        exit(1 as i32);
    }
    close_tb(fd);
    data
}
unsafe extern "C" fn add_to_hash(mut ptr: *mut BaseEntry, mut key: u64) {
    let mut idx: i32 = 0;
    idx = (key
        >> (64 as i32
            - (if (7 as i32) < 7 as i32 {
                11 as i32
            } else {
                12 as i32
            }))) as i32;
    while !(tbHash[idx as usize].ptr).is_null() {
        idx = (idx + 1 as i32)
            & (((1 as i32)
                << (if (7 as i32) < 7 as i32 {
                    11 as i32
                } else {
                    12 as i32
                }))
                - 1 as i32);
    }
    tbHash[idx as usize].key = key;
    tbHash[idx as usize].ptr = ptr;
}
unsafe extern "C" fn init_tb(mut str: *mut i8) {
    if test_tb(str, tbSuffix[WDL as i32 as usize]) == 0 {
        return;
    }
    let mut pcs: [i32; 16] = [0; 16];
    let mut i: i32 = 0 as i32;
    while i < 16 as i32 {
        pcs[i as usize] = 0 as i32;
        i += 1;
    }
    let mut color: i32 = 0 as i32;
    let mut s: *mut i8 = str;
    while *s != 0 {
        if *s as i32 == 'v' as i32 {
            color = 8 as i32;
        } else {
            let mut piece_type: i32 = pyrrhic_char_to_piece_type(*s);
            if piece_type != 0 {
                if piece_type | color < 16 as i32 {
                } else {
                    __assert_fail(
                        b"(piece_type | color) < 16\0" as *const u8 as *const i8,
                        b"tbprobe.c\0" as *const u8 as *const i8,
                        550 as i32 as u32,
                        (*::core::mem::transmute::<&[u8; 21], &[i8; 21]>(
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
    }
    let mut key: u64 = pyrrhic_calc_key_from_pcs(pcs.as_mut_ptr(), 0 as i32);
    let mut key2: u64 = pyrrhic_calc_key_from_pcs(pcs.as_mut_ptr(), 1 as i32);
    let mut hasPawns: bool =
        pcs[PYRRHIC_WPAWN as i32 as usize] != 0 || pcs[PYRRHIC_BPAWN as i32 as usize] != 0;
    let mut be: *mut BaseEntry = if hasPawns as i32 != 0 {
        let fresh10 = tbNumPawn;
        tbNumPawn += 1;
        &mut (*pawnEntry.offset(fresh10 as isize)).be
    } else {
        let fresh11 = tbNumPiece;
        tbNumPiece += 1;
        &mut (*pieceEntry.offset(fresh11 as isize)).be
    };
    (*be).hasPawns = hasPawns;
    (*be).key = key;
    (*be).symmetric = key == key2;
    (*be).num = 0 as i32 as u8;
    let mut i_0: i32 = 0 as i32;
    while i_0 < 16 as i32 {
        (*be).num = ((*be).num as i32 + pcs[i_0 as usize]) as u8;
        i_0 += 1;
    }
    numWdl += 1;
    (*be).hasDtm = test_tb(str, tbSuffix[DTM as i32 as usize]) != 0;
    numDtm += (*be).hasDtm as i32;
    (*be).hasDtz = test_tb(str, tbSuffix[DTZ as i32 as usize]) != 0;
    numDtz += (*be).hasDtz as i32;
    if (*be).num as i32 > TB_MaxCardinality {
        TB_MaxCardinality = (*be).num as i32;
    }
    if (*be).hasDtm && (*be).num as i32 > TB_MaxCardinalityDTM {
        TB_MaxCardinalityDTM = (*be).num as i32;
    }
    let mut type_0: i32 = 0 as i32;
    while type_0 < 3 as i32 {
        atomic_init(
            &mut *((*be).ready).as_mut_ptr().offset(type_0 as isize),
            0 as i32 != 0,
        );
        type_0 += 1;
    }
    if !(*be).hasPawns {
        let mut j: i32 = 0 as i32;
        let mut i_1: i32 = 0 as i32;
        while i_1 < 16 as i32 {
            if pcs[i_1 as usize] == 1 as i32 {
                j += 1;
            }
            i_1 += 1;
        }
        (*be).c2rust_unnamed.kk_enc = j == 2 as i32;
    } else {
        (*be).c2rust_unnamed.pawns[0 as i32 as usize] = pcs[PYRRHIC_WPAWN as i32 as usize] as u8;
        (*be).c2rust_unnamed.pawns[1 as i32 as usize] = pcs[PYRRHIC_BPAWN as i32 as usize] as u8;
        if pcs[PYRRHIC_BPAWN as i32 as usize] != 0
            && (pcs[PYRRHIC_WPAWN as i32 as usize] == 0
                || pcs[PYRRHIC_WPAWN as i32 as usize] > pcs[PYRRHIC_BPAWN as i32 as usize])
        {
            let mut tmp: i32 = (*be).c2rust_unnamed.pawns[0 as i32 as usize] as i32;
            (*be).c2rust_unnamed.pawns[0 as i32 as usize] =
                (*be).c2rust_unnamed.pawns[1 as i32 as usize];
            (*be).c2rust_unnamed.pawns[1 as i32 as usize] = tmp as u8;
        }
    }
    add_to_hash(be, key);
    if key != key2 {
        add_to_hash(be, key2);
    }
}
#[no_mangle]
pub unsafe extern "C" fn num_tables(mut be: *mut BaseEntry, type_0: i32) -> i32 {
    if (*be).hasPawns as i32 != 0 {
        if type_0 == DTM as i32 {
            6 as i32
        } else {
            4 as i32
        }
    } else {
        1 as i32
    }
}
#[no_mangle]
pub unsafe extern "C" fn first_ei(mut be: *mut BaseEntry, type_0: i32) -> *mut EncInfo {
    if (*be).hasPawns as i32 != 0 {
        &mut *((*(be as *mut PawnEntry)).ei).as_mut_ptr().offset(
            (if type_0 == WDL as i32 {
                0 as i32
            } else if type_0 == DTM as i32 {
                8 as i32
            } else {
                20 as i32
            }) as isize,
        ) as *mut EncInfo
    } else {
        &mut *((*(be as *mut PieceEntry)).ei).as_mut_ptr().offset(
            (if type_0 == WDL as i32 {
                0 as i32
            } else if type_0 == DTM as i32 {
                2 as i32
            } else {
                4 as i32
            }) as isize,
        ) as *mut EncInfo
    }
}
unsafe extern "C" fn free_tb_entry(mut be: *mut BaseEntry) {
    let mut type_0: i32 = 0 as i32;
    while type_0 < 3 as i32 {
        if atomic_load_explicit(
            &mut *((*be).ready).as_mut_ptr().offset(type_0 as isize),
            memory_order_relaxed as i32,
        ) {
            unmap_file(
                (*be).data[type_0 as usize] as *mut libc::c_void,
                (*be).mapping[type_0 as usize],
            );
            let mut num: i32 = num_tables(be, type_0);
            let mut ei: *mut EncInfo = first_ei(be, type_0);
            let mut t: i32 = 0 as i32;
            while t < num {
                free((*ei.offset(t as isize)).precomp as *mut libc::c_void);
                if type_0 != DTZ as i32 {
                    free((*ei.offset((num + t) as isize)).precomp as *mut libc::c_void);
                }
                t += 1;
            }
            atomic_store_explicit(
                &mut *((*be).ready).as_mut_ptr().offset(type_0 as isize),
                0 as i32 != 0,
                memory_order_relaxed as i32,
            );
        }
        type_0 += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn tb_init(mut path: *const i8) -> bool {
    if initialized == 0 {
        init_indices();
        initialized = 1 as i32;
    }
    TB_LARGEST = 0 as i32;
    TB_NUM_WDL = 0 as i32;
    TB_NUM_DTZ = 0 as i32;
    TB_NUM_DTM = 0 as i32;
    if !pathString.is_null() {
        free(pathString as *mut libc::c_void);
        free(paths as *mut libc::c_void);
        let mut i: i32 = 0 as i32;
        while i < tbNumPiece {
            free_tb_entry(&mut *pieceEntry.offset(i as isize) as *mut PieceEntry as *mut BaseEntry);
            i += 1;
        }
        let mut i_0: i32 = 0 as i32;
        while i_0 < tbNumPawn {
            free_tb_entry(&mut *pawnEntry.offset(i_0 as isize) as *mut PawnEntry as *mut BaseEntry);
            i_0 += 1;
        }
        pthread_mutex_destroy(addr_of_mut!(tbMutex));
        pathString = std::ptr::null_mut::<i8>();
        numDtz = 0 as i32;
        numDtm = numDtz;
        numWdl = numDtm;
    }
    let mut p: *const i8 = path;
    if strlen(p) == 0 as i32 as u64 || strcmp(p, b"<empty>\0" as *const u8 as *const i8) == 0 {
        return 1 as i32 != 0;
    }
    pathString = malloc((strlen(p)).wrapping_add(1 as i32 as u64)) as *mut i8;
    strcpy(pathString, p);
    numPaths = 0 as i32;
    let mut i_1: i32 = 0 as i32;
    loop {
        if *pathString.offset(i_1 as isize) as i32 != ':' as i32 {
            numPaths += 1;
        }
        while *pathString.offset(i_1 as isize) as i32 != 0
            && *pathString.offset(i_1 as isize) as i32 != ':' as i32
        {
            i_1 += 1;
        }
        if *pathString.offset(i_1 as isize) == 0 {
            break;
        }
        *pathString.offset(i_1 as isize) = 0 as i32 as i8;
        i_1 += 1;
    }
    paths = malloc((numPaths as u64).wrapping_mul(::core::mem::size_of::<*mut i8>() as u64))
        as *mut *mut i8;
    let mut i_2: i32 = 0 as i32;
    let mut j: i32 = 0 as i32;
    while i_2 < numPaths {
        while *pathString.offset(j as isize) == 0 {
            j += 1;
        }
        let fresh12 = &mut (*paths.offset(i_2 as isize));
        *fresh12 = &mut *pathString.offset(j as isize) as *mut i8;
        while *pathString.offset(j as isize) != 0 {
            j += 1;
        }
        i_2 += 1;
    }
    pthread_mutex_init(addr_of_mut!(tbMutex), std::ptr::null::<pthread_mutexattr_t>());
    tbNumPawn = 0 as i32;
    tbNumPiece = tbNumPawn;
    TB_MaxCardinalityDTM = 0 as i32;
    TB_MaxCardinality = TB_MaxCardinalityDTM;
    if pieceEntry.is_null() {
        pieceEntry = malloc(
            ((if (7 as i32) < 7 as i32 {
                254 as i32
            } else {
                650 as i32
            }) as u64)
                .wrapping_mul(::core::mem::size_of::<PieceEntry>() as u64),
        ) as *mut PieceEntry;
        pawnEntry = malloc(
            ((if (7 as i32) < 7 as i32 {
                256 as i32
            } else {
                861 as i32
            }) as u64)
                .wrapping_mul(::core::mem::size_of::<PawnEntry>() as u64),
        ) as *mut PawnEntry;
        if pieceEntry.is_null() || pawnEntry.is_null() {
            fprintf(stderr, b"Out of memory.\n\0" as *const u8 as *const i8);
            exit(1 as i32);
        }
    }
    let mut i_3: i32 = 0 as i32;
    while i_3
        < (1 as i32)
            << (if (7 as i32) < 7 as i32 {
                11 as i32
            } else {
                12 as i32
            })
    {
        tbHash[i_3 as usize].key = 0 as i32 as u64;
        tbHash[i_3 as usize].ptr = std::ptr::null_mut::<BaseEntry>();
        i_3 += 1;
    }
    let mut str: [i8; 16] = [0; 16];
    let mut i_4: i32 = 0;
    let mut j_0: i32 = 0;
    let mut k: i32 = 0;
    let mut l: i32 = 0;
    let mut m: i32 = 0;
    i_4 = 0 as i32;
    while i_4 < 5 as i32 {
        snprintf(
            str.as_mut_ptr(),
            16 as i32 as u64,
            b"K%cvK\0" as *const u8 as *const i8,
            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - i_4) as usize] as i32,
        );
        init_tb(str.as_mut_ptr());
        i_4 += 1;
    }
    i_4 = 0 as i32;
    while i_4 < 5 as i32 {
        j_0 = i_4;
        while j_0 < 5 as i32 {
            snprintf(
                str.as_mut_ptr(),
                16 as i32 as u64,
                b"K%cvK%c\0" as *const u8 as *const i8,
                pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - i_4) as usize] as i32,
                pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - j_0) as usize] as i32,
            );
            init_tb(str.as_mut_ptr());
            j_0 += 1;
        }
        i_4 += 1;
    }
    i_4 = 0 as i32;
    while i_4 < 5 as i32 {
        j_0 = i_4;
        while j_0 < 5 as i32 {
            snprintf(
                str.as_mut_ptr(),
                16 as i32 as u64,
                b"K%c%cvK\0" as *const u8 as *const i8,
                pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - i_4) as usize] as i32,
                pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - j_0) as usize] as i32,
            );
            init_tb(str.as_mut_ptr());
            j_0 += 1;
        }
        i_4 += 1;
    }
    i_4 = 0 as i32;
    while i_4 < 5 as i32 {
        j_0 = i_4;
        while j_0 < 5 as i32 {
            k = 0 as i32;
            while k < 5 as i32 {
                snprintf(
                    str.as_mut_ptr(),
                    16 as i32 as u64,
                    b"K%c%cvK%c\0" as *const u8 as *const i8,
                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - i_4) as usize] as i32,
                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - j_0) as usize] as i32,
                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - k) as usize] as i32,
                );
                init_tb(str.as_mut_ptr());
                k += 1;
            }
            j_0 += 1;
        }
        i_4 += 1;
    }
    i_4 = 0 as i32;
    while i_4 < 5 as i32 {
        j_0 = i_4;
        while j_0 < 5 as i32 {
            k = j_0;
            while k < 5 as i32 {
                snprintf(
                    str.as_mut_ptr(),
                    16 as i32 as u64,
                    b"K%c%c%cvK\0" as *const u8 as *const i8,
                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - i_4) as usize] as i32,
                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - j_0) as usize] as i32,
                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - k) as usize] as i32,
                );
                init_tb(str.as_mut_ptr());
                k += 1;
            }
            j_0 += 1;
        }
        i_4 += 1;
    }
    if !((::core::mem::size_of::<u64>() as u64) < 8 as i32 as u64 || (7 as i32) < 6 as i32) {
        i_4 = 0 as i32;
        while i_4 < 5 as i32 {
            j_0 = i_4;
            while j_0 < 5 as i32 {
                k = i_4;
                while k < 5 as i32 {
                    l = if i_4 == k { j_0 } else { k };
                    while l < 5 as i32 {
                        snprintf(
                            str.as_mut_ptr(),
                            16 as i32 as u64,
                            b"K%c%cvK%c%c\0" as *const u8 as *const i8,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - i_4) as usize] as i32,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - j_0) as usize] as i32,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - k) as usize] as i32,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - l) as usize] as i32,
                        );
                        init_tb(str.as_mut_ptr());
                        l += 1;
                    }
                    k += 1;
                }
                j_0 += 1;
            }
            i_4 += 1;
        }
        i_4 = 0 as i32;
        while i_4 < 5 as i32 {
            j_0 = i_4;
            while j_0 < 5 as i32 {
                k = j_0;
                while k < 5 as i32 {
                    l = 0 as i32;
                    while l < 5 as i32 {
                        snprintf(
                            str.as_mut_ptr(),
                            16 as i32 as u64,
                            b"K%c%c%cvK%c\0" as *const u8 as *const i8,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - i_4) as usize] as i32,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - j_0) as usize] as i32,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - k) as usize] as i32,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - l) as usize] as i32,
                        );
                        init_tb(str.as_mut_ptr());
                        l += 1;
                    }
                    k += 1;
                }
                j_0 += 1;
            }
            i_4 += 1;
        }
        i_4 = 0 as i32;
        while i_4 < 5 as i32 {
            j_0 = i_4;
            while j_0 < 5 as i32 {
                k = j_0;
                while k < 5 as i32 {
                    l = k;
                    while l < 5 as i32 {
                        snprintf(
                            str.as_mut_ptr(),
                            16 as i32 as u64,
                            b"K%c%c%c%cvK\0" as *const u8 as *const i8,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - i_4) as usize] as i32,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - j_0) as usize] as i32,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - k) as usize] as i32,
                            pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - l) as usize] as i32,
                        );
                        init_tb(str.as_mut_ptr());
                        l += 1;
                    }
                    k += 1;
                }
                j_0 += 1;
            }
            i_4 += 1;
        }
        if (7 as i32) >= 7 as i32 {
            i_4 = 0 as i32;
            while i_4 < 5 as i32 {
                j_0 = i_4;
                while j_0 < 5 as i32 {
                    k = j_0;
                    while k < 5 as i32 {
                        l = k;
                        while l < 5 as i32 {
                            m = l;
                            while m < 5 as i32 {
                                snprintf(
                                    str.as_mut_ptr(),
                                    16 as i32 as u64,
                                    b"K%c%c%c%c%cvK\0" as *const u8 as *const i8,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - i_4) as usize]
                                        as i32,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - j_0) as usize]
                                        as i32,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - k) as usize]
                                        as i32,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - l) as usize]
                                        as i32,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - m) as usize]
                                        as i32,
                                );
                                init_tb(str.as_mut_ptr());
                                m += 1;
                            }
                            l += 1;
                        }
                        k += 1;
                    }
                    j_0 += 1;
                }
                i_4 += 1;
            }
            i_4 = 0 as i32;
            while i_4 < 5 as i32 {
                j_0 = i_4;
                while j_0 < 5 as i32 {
                    k = j_0;
                    while k < 5 as i32 {
                        l = k;
                        while l < 5 as i32 {
                            m = 0 as i32;
                            while m < 5 as i32 {
                                snprintf(
                                    str.as_mut_ptr(),
                                    16 as i32 as u64,
                                    b"K%c%c%c%cvK%c\0" as *const u8 as *const i8,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - i_4) as usize]
                                        as i32,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - j_0) as usize]
                                        as i32,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - k) as usize]
                                        as i32,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - l) as usize]
                                        as i32,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - m) as usize]
                                        as i32,
                                );
                                init_tb(str.as_mut_ptr());
                                m += 1;
                            }
                            l += 1;
                        }
                        k += 1;
                    }
                    j_0 += 1;
                }
                i_4 += 1;
            }
            i_4 = 0 as i32;
            while i_4 < 5 as i32 {
                j_0 = i_4;
                while j_0 < 5 as i32 {
                    k = j_0;
                    while k < 5 as i32 {
                        l = 0 as i32;
                        while l < 5 as i32 {
                            m = l;
                            while m < 5 as i32 {
                                snprintf(
                                    str.as_mut_ptr(),
                                    16 as i32 as u64,
                                    b"K%c%c%cvK%c%c\0" as *const u8 as *const i8,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - i_4) as usize]
                                        as i32,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - j_0) as usize]
                                        as i32,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - k) as usize]
                                        as i32,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - l) as usize]
                                        as i32,
                                    pyrrhic_piece_to_char[(PYRRHIC_QUEEN as i32 - m) as usize]
                                        as i32,
                                );
                                init_tb(str.as_mut_ptr());
                                m += 1;
                            }
                            l += 1;
                        }
                        k += 1;
                    }
                    j_0 += 1;
                }
                i_4 += 1;
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
    1 as i32 != 0
}
#[no_mangle]
pub unsafe extern "C" fn tb_free() {
    tb_init(b"\0" as *const u8 as *const i8);
    free(pieceEntry as *mut libc::c_void);
    free(pawnEntry as *mut libc::c_void);
}
static mut OffDiag: [i8; 64] = [
    0 as i32 as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    1 as i32 as i8,
    0 as i32 as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    0 as i32 as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    0 as i32 as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    0 as i32 as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    0 as i32 as i8,
    -(1 as i32) as i8,
    -(1 as i32) as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    0 as i32 as i8,
    -(1 as i32) as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    1 as i32 as i8,
    0 as i32 as i8,
];
static mut Triangle: [u8; 64] = [
    6 as i32 as u8,
    0 as i32 as u8,
    1 as i32 as u8,
    2 as i32 as u8,
    2 as i32 as u8,
    1 as i32 as u8,
    0 as i32 as u8,
    6 as i32 as u8,
    0 as i32 as u8,
    7 as i32 as u8,
    3 as i32 as u8,
    4 as i32 as u8,
    4 as i32 as u8,
    3 as i32 as u8,
    7 as i32 as u8,
    0 as i32 as u8,
    1 as i32 as u8,
    3 as i32 as u8,
    8 as i32 as u8,
    5 as i32 as u8,
    5 as i32 as u8,
    8 as i32 as u8,
    3 as i32 as u8,
    1 as i32 as u8,
    2 as i32 as u8,
    4 as i32 as u8,
    5 as i32 as u8,
    9 as i32 as u8,
    9 as i32 as u8,
    5 as i32 as u8,
    4 as i32 as u8,
    2 as i32 as u8,
    2 as i32 as u8,
    4 as i32 as u8,
    5 as i32 as u8,
    9 as i32 as u8,
    9 as i32 as u8,
    5 as i32 as u8,
    4 as i32 as u8,
    2 as i32 as u8,
    1 as i32 as u8,
    3 as i32 as u8,
    8 as i32 as u8,
    5 as i32 as u8,
    5 as i32 as u8,
    8 as i32 as u8,
    3 as i32 as u8,
    1 as i32 as u8,
    0 as i32 as u8,
    7 as i32 as u8,
    3 as i32 as u8,
    4 as i32 as u8,
    4 as i32 as u8,
    3 as i32 as u8,
    7 as i32 as u8,
    0 as i32 as u8,
    6 as i32 as u8,
    0 as i32 as u8,
    1 as i32 as u8,
    2 as i32 as u8,
    2 as i32 as u8,
    1 as i32 as u8,
    0 as i32 as u8,
    6 as i32 as u8,
];
static mut FlipDiag: [u8; 64] = [
    0 as i32 as u8,
    8 as i32 as u8,
    16 as i32 as u8,
    24 as i32 as u8,
    32 as i32 as u8,
    40 as i32 as u8,
    48 as i32 as u8,
    56 as i32 as u8,
    1 as i32 as u8,
    9 as i32 as u8,
    17 as i32 as u8,
    25 as i32 as u8,
    33 as i32 as u8,
    41 as i32 as u8,
    49 as i32 as u8,
    57 as i32 as u8,
    2 as i32 as u8,
    10 as i32 as u8,
    18 as i32 as u8,
    26 as i32 as u8,
    34 as i32 as u8,
    42 as i32 as u8,
    50 as i32 as u8,
    58 as i32 as u8,
    3 as i32 as u8,
    11 as i32 as u8,
    19 as i32 as u8,
    27 as i32 as u8,
    35 as i32 as u8,
    43 as i32 as u8,
    51 as i32 as u8,
    59 as i32 as u8,
    4 as i32 as u8,
    12 as i32 as u8,
    20 as i32 as u8,
    28 as i32 as u8,
    36 as i32 as u8,
    44 as i32 as u8,
    52 as i32 as u8,
    60 as i32 as u8,
    5 as i32 as u8,
    13 as i32 as u8,
    21 as i32 as u8,
    29 as i32 as u8,
    37 as i32 as u8,
    45 as i32 as u8,
    53 as i32 as u8,
    61 as i32 as u8,
    6 as i32 as u8,
    14 as i32 as u8,
    22 as i32 as u8,
    30 as i32 as u8,
    38 as i32 as u8,
    46 as i32 as u8,
    54 as i32 as u8,
    62 as i32 as u8,
    7 as i32 as u8,
    15 as i32 as u8,
    23 as i32 as u8,
    31 as i32 as u8,
    39 as i32 as u8,
    47 as i32 as u8,
    55 as i32 as u8,
    63 as i32 as u8,
];
static mut Lower: [u8; 64] = [
    28 as i32 as u8,
    0 as i32 as u8,
    1 as i32 as u8,
    2 as i32 as u8,
    3 as i32 as u8,
    4 as i32 as u8,
    5 as i32 as u8,
    6 as i32 as u8,
    0 as i32 as u8,
    29 as i32 as u8,
    7 as i32 as u8,
    8 as i32 as u8,
    9 as i32 as u8,
    10 as i32 as u8,
    11 as i32 as u8,
    12 as i32 as u8,
    1 as i32 as u8,
    7 as i32 as u8,
    30 as i32 as u8,
    13 as i32 as u8,
    14 as i32 as u8,
    15 as i32 as u8,
    16 as i32 as u8,
    17 as i32 as u8,
    2 as i32 as u8,
    8 as i32 as u8,
    13 as i32 as u8,
    31 as i32 as u8,
    18 as i32 as u8,
    19 as i32 as u8,
    20 as i32 as u8,
    21 as i32 as u8,
    3 as i32 as u8,
    9 as i32 as u8,
    14 as i32 as u8,
    18 as i32 as u8,
    32 as i32 as u8,
    22 as i32 as u8,
    23 as i32 as u8,
    24 as i32 as u8,
    4 as i32 as u8,
    10 as i32 as u8,
    15 as i32 as u8,
    19 as i32 as u8,
    22 as i32 as u8,
    33 as i32 as u8,
    25 as i32 as u8,
    26 as i32 as u8,
    5 as i32 as u8,
    11 as i32 as u8,
    16 as i32 as u8,
    20 as i32 as u8,
    23 as i32 as u8,
    25 as i32 as u8,
    34 as i32 as u8,
    27 as i32 as u8,
    6 as i32 as u8,
    12 as i32 as u8,
    17 as i32 as u8,
    21 as i32 as u8,
    24 as i32 as u8,
    26 as i32 as u8,
    27 as i32 as u8,
    35 as i32 as u8,
];
static mut Diag: [u8; 64] = [
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    8 as i32 as u8,
    0 as i32 as u8,
    1 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    9 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    2 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    10 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    3 as i32 as u8,
    11 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    12 as i32 as u8,
    4 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    13 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    5 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    14 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    6 as i32 as u8,
    0 as i32 as u8,
    15 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    7 as i32 as u8,
];
static mut Flap: [[u8; 64]; 2] = [
    [
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        6 as i32 as u8,
        12 as i32 as u8,
        18 as i32 as u8,
        18 as i32 as u8,
        12 as i32 as u8,
        6 as i32 as u8,
        0 as i32 as u8,
        1 as i32 as u8,
        7 as i32 as u8,
        13 as i32 as u8,
        19 as i32 as u8,
        19 as i32 as u8,
        13 as i32 as u8,
        7 as i32 as u8,
        1 as i32 as u8,
        2 as i32 as u8,
        8 as i32 as u8,
        14 as i32 as u8,
        20 as i32 as u8,
        20 as i32 as u8,
        14 as i32 as u8,
        8 as i32 as u8,
        2 as i32 as u8,
        3 as i32 as u8,
        9 as i32 as u8,
        15 as i32 as u8,
        21 as i32 as u8,
        21 as i32 as u8,
        15 as i32 as u8,
        9 as i32 as u8,
        3 as i32 as u8,
        4 as i32 as u8,
        10 as i32 as u8,
        16 as i32 as u8,
        22 as i32 as u8,
        22 as i32 as u8,
        16 as i32 as u8,
        10 as i32 as u8,
        4 as i32 as u8,
        5 as i32 as u8,
        11 as i32 as u8,
        17 as i32 as u8,
        23 as i32 as u8,
        23 as i32 as u8,
        17 as i32 as u8,
        11 as i32 as u8,
        5 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
    ],
    [
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        1 as i32 as u8,
        2 as i32 as u8,
        3 as i32 as u8,
        3 as i32 as u8,
        2 as i32 as u8,
        1 as i32 as u8,
        0 as i32 as u8,
        4 as i32 as u8,
        5 as i32 as u8,
        6 as i32 as u8,
        7 as i32 as u8,
        7 as i32 as u8,
        6 as i32 as u8,
        5 as i32 as u8,
        4 as i32 as u8,
        8 as i32 as u8,
        9 as i32 as u8,
        10 as i32 as u8,
        11 as i32 as u8,
        11 as i32 as u8,
        10 as i32 as u8,
        9 as i32 as u8,
        8 as i32 as u8,
        12 as i32 as u8,
        13 as i32 as u8,
        14 as i32 as u8,
        15 as i32 as u8,
        15 as i32 as u8,
        14 as i32 as u8,
        13 as i32 as u8,
        12 as i32 as u8,
        16 as i32 as u8,
        17 as i32 as u8,
        18 as i32 as u8,
        19 as i32 as u8,
        19 as i32 as u8,
        18 as i32 as u8,
        17 as i32 as u8,
        16 as i32 as u8,
        20 as i32 as u8,
        21 as i32 as u8,
        22 as i32 as u8,
        23 as i32 as u8,
        23 as i32 as u8,
        22 as i32 as u8,
        21 as i32 as u8,
        20 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
    ],
];
static mut PawnTwist: [[u8; 64]; 2] = [
    [
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        47 as i32 as u8,
        35 as i32 as u8,
        23 as i32 as u8,
        11 as i32 as u8,
        10 as i32 as u8,
        22 as i32 as u8,
        34 as i32 as u8,
        46 as i32 as u8,
        45 as i32 as u8,
        33 as i32 as u8,
        21 as i32 as u8,
        9 as i32 as u8,
        8 as i32 as u8,
        20 as i32 as u8,
        32 as i32 as u8,
        44 as i32 as u8,
        43 as i32 as u8,
        31 as i32 as u8,
        19 as i32 as u8,
        7 as i32 as u8,
        6 as i32 as u8,
        18 as i32 as u8,
        30 as i32 as u8,
        42 as i32 as u8,
        41 as i32 as u8,
        29 as i32 as u8,
        17 as i32 as u8,
        5 as i32 as u8,
        4 as i32 as u8,
        16 as i32 as u8,
        28 as i32 as u8,
        40 as i32 as u8,
        39 as i32 as u8,
        27 as i32 as u8,
        15 as i32 as u8,
        3 as i32 as u8,
        2 as i32 as u8,
        14 as i32 as u8,
        26 as i32 as u8,
        38 as i32 as u8,
        37 as i32 as u8,
        25 as i32 as u8,
        13 as i32 as u8,
        1 as i32 as u8,
        0 as i32 as u8,
        12 as i32 as u8,
        24 as i32 as u8,
        36 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
    ],
    [
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        47 as i32 as u8,
        45 as i32 as u8,
        43 as i32 as u8,
        41 as i32 as u8,
        40 as i32 as u8,
        42 as i32 as u8,
        44 as i32 as u8,
        46 as i32 as u8,
        39 as i32 as u8,
        37 as i32 as u8,
        35 as i32 as u8,
        33 as i32 as u8,
        32 as i32 as u8,
        34 as i32 as u8,
        36 as i32 as u8,
        38 as i32 as u8,
        31 as i32 as u8,
        29 as i32 as u8,
        27 as i32 as u8,
        25 as i32 as u8,
        24 as i32 as u8,
        26 as i32 as u8,
        28 as i32 as u8,
        30 as i32 as u8,
        23 as i32 as u8,
        21 as i32 as u8,
        19 as i32 as u8,
        17 as i32 as u8,
        16 as i32 as u8,
        18 as i32 as u8,
        20 as i32 as u8,
        22 as i32 as u8,
        15 as i32 as u8,
        13 as i32 as u8,
        11 as i32 as u8,
        9 as i32 as u8,
        8 as i32 as u8,
        10 as i32 as u8,
        12 as i32 as u8,
        14 as i32 as u8,
        7 as i32 as u8,
        5 as i32 as u8,
        3 as i32 as u8,
        1 as i32 as u8,
        0 as i32 as u8,
        2 as i32 as u8,
        4 as i32 as u8,
        6 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
        0 as i32 as u8,
    ],
];
static mut KKIdx: [[i16; 64]; 10] = [
    [
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        0 as i32 as i16,
        1 as i32 as i16,
        2 as i32 as i16,
        3 as i32 as i16,
        4 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        5 as i32 as i16,
        6 as i32 as i16,
        7 as i32 as i16,
        8 as i32 as i16,
        9 as i32 as i16,
        10 as i32 as i16,
        11 as i32 as i16,
        12 as i32 as i16,
        13 as i32 as i16,
        14 as i32 as i16,
        15 as i32 as i16,
        16 as i32 as i16,
        17 as i32 as i16,
        18 as i32 as i16,
        19 as i32 as i16,
        20 as i32 as i16,
        21 as i32 as i16,
        22 as i32 as i16,
        23 as i32 as i16,
        24 as i32 as i16,
        25 as i32 as i16,
        26 as i32 as i16,
        27 as i32 as i16,
        28 as i32 as i16,
        29 as i32 as i16,
        30 as i32 as i16,
        31 as i32 as i16,
        32 as i32 as i16,
        33 as i32 as i16,
        34 as i32 as i16,
        35 as i32 as i16,
        36 as i32 as i16,
        37 as i32 as i16,
        38 as i32 as i16,
        39 as i32 as i16,
        40 as i32 as i16,
        41 as i32 as i16,
        42 as i32 as i16,
        43 as i32 as i16,
        44 as i32 as i16,
        45 as i32 as i16,
        46 as i32 as i16,
        47 as i32 as i16,
        48 as i32 as i16,
        49 as i32 as i16,
        50 as i32 as i16,
        51 as i32 as i16,
        52 as i32 as i16,
        53 as i32 as i16,
        54 as i32 as i16,
        55 as i32 as i16,
        56 as i32 as i16,
        57 as i32 as i16,
    ],
    [
        58 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        59 as i32 as i16,
        60 as i32 as i16,
        61 as i32 as i16,
        62 as i32 as i16,
        63 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        64 as i32 as i16,
        65 as i32 as i16,
        66 as i32 as i16,
        67 as i32 as i16,
        68 as i32 as i16,
        69 as i32 as i16,
        70 as i32 as i16,
        71 as i32 as i16,
        72 as i32 as i16,
        73 as i32 as i16,
        74 as i32 as i16,
        75 as i32 as i16,
        76 as i32 as i16,
        77 as i32 as i16,
        78 as i32 as i16,
        79 as i32 as i16,
        80 as i32 as i16,
        81 as i32 as i16,
        82 as i32 as i16,
        83 as i32 as i16,
        84 as i32 as i16,
        85 as i32 as i16,
        86 as i32 as i16,
        87 as i32 as i16,
        88 as i32 as i16,
        89 as i32 as i16,
        90 as i32 as i16,
        91 as i32 as i16,
        92 as i32 as i16,
        93 as i32 as i16,
        94 as i32 as i16,
        95 as i32 as i16,
        96 as i32 as i16,
        97 as i32 as i16,
        98 as i32 as i16,
        99 as i32 as i16,
        100 as i32 as i16,
        101 as i32 as i16,
        102 as i32 as i16,
        103 as i32 as i16,
        104 as i32 as i16,
        105 as i32 as i16,
        106 as i32 as i16,
        107 as i32 as i16,
        108 as i32 as i16,
        109 as i32 as i16,
        110 as i32 as i16,
        111 as i32 as i16,
        112 as i32 as i16,
        113 as i32 as i16,
        114 as i32 as i16,
        115 as i32 as i16,
    ],
    [
        116 as i32 as i16,
        117 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        118 as i32 as i16,
        119 as i32 as i16,
        120 as i32 as i16,
        121 as i32 as i16,
        122 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        123 as i32 as i16,
        124 as i32 as i16,
        125 as i32 as i16,
        126 as i32 as i16,
        127 as i32 as i16,
        128 as i32 as i16,
        129 as i32 as i16,
        130 as i32 as i16,
        131 as i32 as i16,
        132 as i32 as i16,
        133 as i32 as i16,
        134 as i32 as i16,
        135 as i32 as i16,
        136 as i32 as i16,
        137 as i32 as i16,
        138 as i32 as i16,
        139 as i32 as i16,
        140 as i32 as i16,
        141 as i32 as i16,
        142 as i32 as i16,
        143 as i32 as i16,
        144 as i32 as i16,
        145 as i32 as i16,
        146 as i32 as i16,
        147 as i32 as i16,
        148 as i32 as i16,
        149 as i32 as i16,
        150 as i32 as i16,
        151 as i32 as i16,
        152 as i32 as i16,
        153 as i32 as i16,
        154 as i32 as i16,
        155 as i32 as i16,
        156 as i32 as i16,
        157 as i32 as i16,
        158 as i32 as i16,
        159 as i32 as i16,
        160 as i32 as i16,
        161 as i32 as i16,
        162 as i32 as i16,
        163 as i32 as i16,
        164 as i32 as i16,
        165 as i32 as i16,
        166 as i32 as i16,
        167 as i32 as i16,
        168 as i32 as i16,
        169 as i32 as i16,
        170 as i32 as i16,
        171 as i32 as i16,
        172 as i32 as i16,
        173 as i32 as i16,
    ],
    [
        174 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        175 as i32 as i16,
        176 as i32 as i16,
        177 as i32 as i16,
        178 as i32 as i16,
        179 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        180 as i32 as i16,
        181 as i32 as i16,
        182 as i32 as i16,
        183 as i32 as i16,
        184 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        185 as i32 as i16,
        186 as i32 as i16,
        187 as i32 as i16,
        188 as i32 as i16,
        189 as i32 as i16,
        190 as i32 as i16,
        191 as i32 as i16,
        192 as i32 as i16,
        193 as i32 as i16,
        194 as i32 as i16,
        195 as i32 as i16,
        196 as i32 as i16,
        197 as i32 as i16,
        198 as i32 as i16,
        199 as i32 as i16,
        200 as i32 as i16,
        201 as i32 as i16,
        202 as i32 as i16,
        203 as i32 as i16,
        204 as i32 as i16,
        205 as i32 as i16,
        206 as i32 as i16,
        207 as i32 as i16,
        208 as i32 as i16,
        209 as i32 as i16,
        210 as i32 as i16,
        211 as i32 as i16,
        212 as i32 as i16,
        213 as i32 as i16,
        214 as i32 as i16,
        215 as i32 as i16,
        216 as i32 as i16,
        217 as i32 as i16,
        218 as i32 as i16,
        219 as i32 as i16,
        220 as i32 as i16,
        221 as i32 as i16,
        222 as i32 as i16,
        223 as i32 as i16,
        224 as i32 as i16,
        225 as i32 as i16,
        226 as i32 as i16,
        227 as i32 as i16,
        228 as i32 as i16,
    ],
    [
        229 as i32 as i16,
        230 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        231 as i32 as i16,
        232 as i32 as i16,
        233 as i32 as i16,
        234 as i32 as i16,
        235 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        236 as i32 as i16,
        237 as i32 as i16,
        238 as i32 as i16,
        239 as i32 as i16,
        240 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        241 as i32 as i16,
        242 as i32 as i16,
        243 as i32 as i16,
        244 as i32 as i16,
        245 as i32 as i16,
        246 as i32 as i16,
        247 as i32 as i16,
        248 as i32 as i16,
        249 as i32 as i16,
        250 as i32 as i16,
        251 as i32 as i16,
        252 as i32 as i16,
        253 as i32 as i16,
        254 as i32 as i16,
        255 as i32 as i16,
        256 as i32 as i16,
        257 as i32 as i16,
        258 as i32 as i16,
        259 as i32 as i16,
        260 as i32 as i16,
        261 as i32 as i16,
        262 as i32 as i16,
        263 as i32 as i16,
        264 as i32 as i16,
        265 as i32 as i16,
        266 as i32 as i16,
        267 as i32 as i16,
        268 as i32 as i16,
        269 as i32 as i16,
        270 as i32 as i16,
        271 as i32 as i16,
        272 as i32 as i16,
        273 as i32 as i16,
        274 as i32 as i16,
        275 as i32 as i16,
        276 as i32 as i16,
        277 as i32 as i16,
        278 as i32 as i16,
        279 as i32 as i16,
        280 as i32 as i16,
        281 as i32 as i16,
        282 as i32 as i16,
        283 as i32 as i16,
    ],
    [
        284 as i32 as i16,
        285 as i32 as i16,
        286 as i32 as i16,
        287 as i32 as i16,
        288 as i32 as i16,
        289 as i32 as i16,
        290 as i32 as i16,
        291 as i32 as i16,
        292 as i32 as i16,
        293 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        294 as i32 as i16,
        295 as i32 as i16,
        296 as i32 as i16,
        297 as i32 as i16,
        298 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        299 as i32 as i16,
        300 as i32 as i16,
        301 as i32 as i16,
        302 as i32 as i16,
        303 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        304 as i32 as i16,
        305 as i32 as i16,
        306 as i32 as i16,
        307 as i32 as i16,
        308 as i32 as i16,
        309 as i32 as i16,
        310 as i32 as i16,
        311 as i32 as i16,
        312 as i32 as i16,
        313 as i32 as i16,
        314 as i32 as i16,
        315 as i32 as i16,
        316 as i32 as i16,
        317 as i32 as i16,
        318 as i32 as i16,
        319 as i32 as i16,
        320 as i32 as i16,
        321 as i32 as i16,
        322 as i32 as i16,
        323 as i32 as i16,
        324 as i32 as i16,
        325 as i32 as i16,
        326 as i32 as i16,
        327 as i32 as i16,
        328 as i32 as i16,
        329 as i32 as i16,
        330 as i32 as i16,
        331 as i32 as i16,
        332 as i32 as i16,
        333 as i32 as i16,
        334 as i32 as i16,
        335 as i32 as i16,
        336 as i32 as i16,
        337 as i32 as i16,
        338 as i32 as i16,
    ],
    [
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        339 as i32 as i16,
        340 as i32 as i16,
        341 as i32 as i16,
        342 as i32 as i16,
        343 as i32 as i16,
        344 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        345 as i32 as i16,
        346 as i32 as i16,
        347 as i32 as i16,
        348 as i32 as i16,
        349 as i32 as i16,
        350 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        441 as i32 as i16,
        351 as i32 as i16,
        352 as i32 as i16,
        353 as i32 as i16,
        354 as i32 as i16,
        355 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        442 as i32 as i16,
        356 as i32 as i16,
        357 as i32 as i16,
        358 as i32 as i16,
        359 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        443 as i32 as i16,
        360 as i32 as i16,
        361 as i32 as i16,
        362 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        444 as i32 as i16,
        363 as i32 as i16,
        364 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        445 as i32 as i16,
        365 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        446 as i32 as i16,
    ],
    [
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        366 as i32 as i16,
        367 as i32 as i16,
        368 as i32 as i16,
        369 as i32 as i16,
        370 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        371 as i32 as i16,
        372 as i32 as i16,
        373 as i32 as i16,
        374 as i32 as i16,
        375 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        376 as i32 as i16,
        377 as i32 as i16,
        378 as i32 as i16,
        379 as i32 as i16,
        380 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        447 as i32 as i16,
        381 as i32 as i16,
        382 as i32 as i16,
        383 as i32 as i16,
        384 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        448 as i32 as i16,
        385 as i32 as i16,
        386 as i32 as i16,
        387 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        449 as i32 as i16,
        388 as i32 as i16,
        389 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        450 as i32 as i16,
        390 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        451 as i32 as i16,
    ],
    [
        452 as i32 as i16,
        391 as i32 as i16,
        392 as i32 as i16,
        393 as i32 as i16,
        394 as i32 as i16,
        395 as i32 as i16,
        396 as i32 as i16,
        397 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        398 as i32 as i16,
        399 as i32 as i16,
        400 as i32 as i16,
        401 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        402 as i32 as i16,
        403 as i32 as i16,
        404 as i32 as i16,
        405 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        406 as i32 as i16,
        407 as i32 as i16,
        408 as i32 as i16,
        409 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        453 as i32 as i16,
        410 as i32 as i16,
        411 as i32 as i16,
        412 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        454 as i32 as i16,
        413 as i32 as i16,
        414 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        455 as i32 as i16,
        415 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        456 as i32 as i16,
    ],
    [
        457 as i32 as i16,
        416 as i32 as i16,
        417 as i32 as i16,
        418 as i32 as i16,
        419 as i32 as i16,
        420 as i32 as i16,
        421 as i32 as i16,
        422 as i32 as i16,
        -(1 as i32) as i16,
        458 as i32 as i16,
        423 as i32 as i16,
        424 as i32 as i16,
        425 as i32 as i16,
        426 as i32 as i16,
        427 as i32 as i16,
        428 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        429 as i32 as i16,
        430 as i32 as i16,
        431 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        432 as i32 as i16,
        433 as i32 as i16,
        434 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        435 as i32 as i16,
        436 as i32 as i16,
        437 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        459 as i32 as i16,
        438 as i32 as i16,
        439 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        460 as i32 as i16,
        440 as i32 as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        -(1 as i32) as i16,
        461 as i32 as i16,
    ],
];
static mut FileToFile: [u8; 8] = [
    0 as i32 as u8,
    1 as i32 as u8,
    2 as i32 as u8,
    3 as i32 as u8,
    3 as i32 as u8,
    2 as i32 as u8,
    1 as i32 as u8,
    0 as i32 as u8,
];
static mut WdlToMap: [i32; 5] = [1 as i32, 3 as i32, 0 as i32, 2 as i32, 0 as i32];
static mut PAFlags: [u8; 5] = [
    8 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    0 as i32 as u8,
    4 as i32 as u8,
];
static mut Binomial: [[u64; 64]; 7] = [[0; 64]; 7];
static mut PawnIdx: [[[u64; 24]; 6]; 2] = [[[0; 24]; 6]; 2];
static mut PawnFactorFile: [[u64; 4]; 6] = [[0; 4]; 6];
static mut PawnFactorRank: [[u64; 6]; 6] = [[0; 6]; 6];
unsafe extern "C" fn init_indices() {
    let mut i: i32 = 0;
    let mut j: i32 = 0;
    let mut k: i32 = 0;
    i = 0 as i32;
    while i < 7 as i32 {
        j = 0 as i32;
        while j < 64 as i32 {
            let mut f: u64 = 1 as i32 as u64;
            let mut l: u64 = 1 as i32 as u64;
            k = 0 as i32;
            while k < i {
                f *= (j - k) as u64;
                l *= (k + 1 as i32) as u64;
                k += 1;
            }
            Binomial[i as usize][j as usize] = f / l;
            j += 1;
        }
        i += 1;
    }
    i = 0 as i32;
    while i < 6 as i32 {
        let mut s: u64 = 0 as i32 as u64;
        j = 0 as i32;
        while j < 24 as i32 {
            PawnIdx[0 as i32 as usize][i as usize][j as usize] = s;
            s = s.wrapping_add(
                Binomial[i as usize][PawnTwist[0 as i32 as usize]
                    [((1 as i32 + j % 6 as i32) * 8 as i32 + j / 6 as i32) as usize]
                    as usize],
            );
            if (j + 1 as i32) % 6 as i32 == 0 as i32 {
                PawnFactorFile[i as usize][(j / 6 as i32) as usize] = s;
                s = 0 as i32 as u64;
            }
            j += 1;
        }
        i += 1;
    }
    i = 0 as i32;
    while i < 6 as i32 {
        let mut s_0: u64 = 0 as i32 as u64;
        j = 0 as i32;
        while j < 24 as i32 {
            PawnIdx[1 as i32 as usize][i as usize][j as usize] = s_0;
            s_0 = s_0.wrapping_add(
                Binomial[i as usize][PawnTwist[1 as i32 as usize]
                    [((1 as i32 + j / 4 as i32) * 8 as i32 + j % 4 as i32) as usize]
                    as usize],
            );
            if (j + 1 as i32) % 4 as i32 == 0 as i32 {
                PawnFactorRank[i as usize][(j / 4 as i32) as usize] = s_0;
                s_0 = 0 as i32 as u64;
            }
            j += 1;
        }
        i += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn leading_pawn(mut p: *mut i32, mut be: *mut BaseEntry, enc: i32) -> i32 {
    let mut i: i32 = 1 as i32;
    while i < (*be).c2rust_unnamed.pawns[0 as i32 as usize] as i32 {
        if Flap[(enc - 1 as i32) as usize][*p.offset(0 as i32 as isize) as usize] as i32
            > Flap[(enc - 1 as i32) as usize][*p.offset(i as isize) as usize] as i32
        {
            let mut tmp: i32 = *p.offset(0 as i32 as isize);
            *p.offset(0 as i32 as isize) = *p.offset(i as isize);
            *p.offset(i as isize) = tmp;
        }
        i += 1;
    }
    if enc == FILE_ENC as i32 {
        FileToFile[(*p.offset(0 as i32 as isize) & 7 as i32) as usize] as i32
    } else {
        (*p.offset(0 as i32 as isize) - 8 as i32) >> 3 as i32
    }
}
#[no_mangle]
pub unsafe extern "C" fn encode(
    mut p: *mut i32,
    mut ei: *mut EncInfo,
    mut be: *mut BaseEntry,
    enc: i32,
) -> u64 {
    let mut n: i32 = (*be).num as i32;
    let mut idx: u64 = 0;
    let mut k: i32 = 0;
    if *p.offset(0 as i32 as isize) & 0x4 as i32 != 0 {
        let mut i: i32 = 0 as i32;
        while i < n {
            *p.offset(i as isize) ^= 0x7 as i32;
            i += 1;
        }
    }
    if enc == PIECE_ENC as i32 {
        if *p.offset(0 as i32 as isize) & 0x20 as i32 != 0 {
            let mut i_0: i32 = 0 as i32;
            while i_0 < n {
                *p.offset(i_0 as isize) ^= 0x38 as i32;
                i_0 += 1;
            }
        }
        let mut i_1: i32 = 0 as i32;
        while i_1 < n {
            if OffDiag[*p.offset(i_1 as isize) as usize] != 0 {
                if OffDiag[*p.offset(i_1 as isize) as usize] as i32 > 0 as i32
                    && i_1
                        < (if (*be).c2rust_unnamed.kk_enc as i32 != 0 {
                            2 as i32
                        } else {
                            3 as i32
                        })
                {
                    let mut j: i32 = 0 as i32;
                    while j < n {
                        *p.offset(j as isize) = FlipDiag[*p.offset(j as isize) as usize] as i32;
                        j += 1;
                    }
                }
                break;
            } else {
                i_1 += 1;
            }
        }
        if (*be).c2rust_unnamed.kk_enc {
            idx = KKIdx[Triangle[*p.offset(0 as i32 as isize) as usize] as usize]
                [*p.offset(1 as i32 as isize) as usize] as u64;
            k = 2 as i32;
        } else {
            let mut s1: i32 = (*p.offset(1 as i32 as isize) > *p.offset(0 as i32 as isize)) as i32;
            let mut s2: i32 = (*p.offset(2 as i32 as isize) > *p.offset(0 as i32 as isize)) as i32
                + (*p.offset(2 as i32 as isize) > *p.offset(1 as i32 as isize)) as i32;
            if OffDiag[*p.offset(0 as i32 as isize) as usize] != 0 {
                idx =
                    (Triangle[*p.offset(0 as i32 as isize) as usize] as i32 * 63 as i32 * 62 as i32
                        + (*p.offset(1 as i32 as isize) - s1) * 62 as i32
                        + (*p.offset(2 as i32 as isize) - s2)) as u64;
            } else if OffDiag[*p.offset(1 as i32 as isize) as usize] != 0 {
                idx = (6 as i32 * 63 as i32 * 62 as i32
                    + Diag[*p.offset(0 as i32 as isize) as usize] as i32 * 28 as i32 * 62 as i32
                    + Lower[*p.offset(1 as i32 as isize) as usize] as i32 * 62 as i32
                    + *p.offset(2 as i32 as isize)
                    - s2) as u64;
            } else if OffDiag[*p.offset(2 as i32 as isize) as usize] != 0 {
                idx = (6 as i32 * 63 as i32 * 62 as i32
                    + 4 as i32 * 28 as i32 * 62 as i32
                    + Diag[*p.offset(0 as i32 as isize) as usize] as i32 * 7 as i32 * 28 as i32
                    + (Diag[*p.offset(1 as i32 as isize) as usize] as i32 - s1) * 28 as i32
                    + Lower[*p.offset(2 as i32 as isize) as usize] as i32)
                    as u64;
            } else {
                idx = (6 as i32 * 63 as i32 * 62 as i32
                    + 4 as i32 * 28 as i32 * 62 as i32
                    + 4 as i32 * 7 as i32 * 28 as i32
                    + Diag[*p.offset(0 as i32 as isize) as usize] as i32 * 7 as i32 * 6 as i32
                    + (Diag[*p.offset(1 as i32 as isize) as usize] as i32 - s1) * 6 as i32
                    + (Diag[*p.offset(2 as i32 as isize) as usize] as i32 - s2))
                    as u64;
            }
            k = 3 as i32;
        }
        idx *= (*ei).factor[0 as i32 as usize];
    } else {
        let mut i_2: i32 = 1 as i32;
        while i_2 < (*be).c2rust_unnamed.pawns[0 as i32 as usize] as i32 {
            let mut j_0: i32 = i_2 + 1 as i32;
            while j_0 < (*be).c2rust_unnamed.pawns[0 as i32 as usize] as i32 {
                if (PawnTwist[(enc - 1 as i32) as usize][*p.offset(i_2 as isize) as usize] as i32)
                    < PawnTwist[(enc - 1 as i32) as usize][*p.offset(j_0 as isize) as usize] as i32
                {
                    let mut tmp: i32 = *p.offset(i_2 as isize);
                    *p.offset(i_2 as isize) = *p.offset(j_0 as isize);
                    *p.offset(j_0 as isize) = tmp;
                }
                j_0 += 1;
            }
            i_2 += 1;
        }
        k = (*be).c2rust_unnamed.pawns[0 as i32 as usize] as i32;
        idx = PawnIdx[(enc - 1 as i32) as usize][(k - 1 as i32) as usize]
            [Flap[(enc - 1 as i32) as usize][*p.offset(0 as i32 as isize) as usize] as usize];
        let mut i_3: i32 = 1 as i32;
        while i_3 < k {
            idx = idx.wrapping_add(
                Binomial[(k - i_3) as usize][PawnTwist[(enc - 1 as i32) as usize]
                    [*p.offset(i_3 as isize) as usize]
                    as usize],
            );
            i_3 += 1;
        }
        idx *= (*ei).factor[0 as i32 as usize];
        if (*be).c2rust_unnamed.pawns[1 as i32 as usize] != 0 {
            let mut t: i32 = k + (*be).c2rust_unnamed.pawns[1 as i32 as usize] as i32;
            let mut i_4: i32 = k;
            while i_4 < t {
                let mut j_1: i32 = i_4 + 1 as i32;
                while j_1 < t {
                    if *p.offset(i_4 as isize) > *p.offset(j_1 as isize) {
                        let mut tmp_0: i32 = *p.offset(i_4 as isize);
                        *p.offset(i_4 as isize) = *p.offset(j_1 as isize);
                        *p.offset(j_1 as isize) = tmp_0;
                    }
                    j_1 += 1;
                }
                i_4 += 1;
            }
            let mut s: u64 = 0 as i32 as u64;
            let mut i_5: i32 = k;
            while i_5 < t {
                let mut sq: i32 = *p.offset(i_5 as isize);
                let mut skips: i32 = 0 as i32;
                let mut j_2: i32 = 0 as i32;
                while j_2 < k {
                    skips += (sq > *p.offset(j_2 as isize)) as i32;
                    j_2 += 1;
                }
                s = s.wrapping_add(
                    Binomial[(i_5 - k + 1 as i32) as usize][(sq - skips - 8 as i32) as usize],
                );
                i_5 += 1;
            }
            idx = idx.wrapping_add(s * (*ei).factor[k as usize]);
            k = t;
        }
    }
    while k < n {
        let mut t_0: i32 = k + (*ei).norm[k as usize] as i32;
        let mut i_6: i32 = k;
        while i_6 < t_0 {
            let mut j_3: i32 = i_6 + 1 as i32;
            while j_3 < t_0 {
                if *p.offset(i_6 as isize) > *p.offset(j_3 as isize) {
                    let mut tmp_1: i32 = *p.offset(i_6 as isize);
                    *p.offset(i_6 as isize) = *p.offset(j_3 as isize);
                    *p.offset(j_3 as isize) = tmp_1;
                }
                j_3 += 1;
            }
            i_6 += 1;
        }
        let mut s_0: u64 = 0 as i32 as u64;
        let mut i_7: i32 = k;
        while i_7 < t_0 {
            let mut sq_0: i32 = *p.offset(i_7 as isize);
            let mut skips_0: i32 = 0 as i32;
            let mut j_4: i32 = 0 as i32;
            while j_4 < k {
                skips_0 += (sq_0 > *p.offset(j_4 as isize)) as i32;
                j_4 += 1;
            }
            s_0 = s_0
                .wrapping_add(Binomial[(i_7 - k + 1 as i32) as usize][(sq_0 - skips_0) as usize]);
            i_7 += 1;
        }
        idx = idx.wrapping_add(s_0 * (*ei).factor[k as usize]);
        k = t_0;
    }
    idx
}
unsafe extern "C" fn encode_piece(
    mut p: *mut i32,
    mut ei: *mut EncInfo,
    mut be: *mut BaseEntry,
) -> u64 {
    encode(p, ei, be, PIECE_ENC as i32)
}
unsafe extern "C" fn encode_pawn_f(
    mut p: *mut i32,
    mut ei: *mut EncInfo,
    mut be: *mut BaseEntry,
) -> u64 {
    encode(p, ei, be, FILE_ENC as i32)
}
unsafe extern "C" fn encode_pawn_r(
    mut p: *mut i32,
    mut ei: *mut EncInfo,
    mut be: *mut BaseEntry,
) -> u64 {
    encode(p, ei, be, RANK_ENC as i32)
}
unsafe extern "C" fn subfactor(mut k: u64, mut n: u64) -> u64 {
    let mut f: u64 = n;
    let mut l: u64 = 1 as i32 as u64;
    let mut i: u64 = 1 as i32 as u64;
    while i < k {
        f *= n.wrapping_sub(i);
        l *= i.wrapping_add(1 as i32 as u64);
        i = i.wrapping_add(1);
    }
    f / l
}
unsafe extern "C" fn init_enc_info(
    mut ei: *mut EncInfo,
    mut be: *mut BaseEntry,
    mut tb: *mut u8,
    mut shift: i32,
    mut t: i32,
    enc: i32,
) -> u64 {
    let mut morePawns: bool =
        enc != PIECE_ENC as i32 && (*be).c2rust_unnamed.pawns[1 as i32 as usize] as i32 > 0 as i32;
    let mut i: i32 = 0 as i32;
    while i < (*be).num as i32 {
        (*ei).pieces[i as usize] = (*tb.offset((i + 1 as i32 + morePawns as i32) as isize) as i32
            >> shift
            & 0xf as i32) as u8;
        (*ei).norm[i as usize] = 0 as i32 as u8;
        i += 1;
    }
    let mut order: i32 = *tb.offset(0 as i32 as isize) as i32 >> shift & 0xf as i32;
    let mut order2: i32 = if morePawns as i32 != 0 {
        *tb.offset(1 as i32 as isize) as i32 >> shift & 0xf as i32
    } else {
        0xf as i32
    };
    (*ei).norm[0 as i32 as usize] = (if enc != PIECE_ENC as i32 {
        (*be).c2rust_unnamed.pawns[0 as i32 as usize] as i32
    } else if (*be).c2rust_unnamed.kk_enc as i32 != 0 {
        2 as i32
    } else {
        3 as i32
    }) as u8;
    let mut k: i32 = (*ei).norm[0 as i32 as usize] as i32;
    if morePawns {
        (*ei).norm[k as usize] = (*be).c2rust_unnamed.pawns[1 as i32 as usize];
        k += (*ei).norm[k as usize] as i32;
    }
    let mut i_0: i32 = k;
    while i_0 < (*be).num as i32 {
        let mut j: i32 = i_0;
        while j < (*be).num as i32
            && (*ei).pieces[j as usize] as i32 == (*ei).pieces[i_0 as usize] as i32
        {
            (*ei).norm[i_0 as usize] = ((*ei).norm[i_0 as usize]).wrapping_add(1);
            (*ei).norm[i_0 as usize];
            j += 1;
        }
        i_0 += (*ei).norm[i_0 as usize] as i32;
    }
    let mut n: i32 = 64 as i32 - k;
    let mut f: u64 = 1 as i32 as u64;
    let mut i_1: i32 = 0 as i32;
    while k < (*be).num as i32 || i_1 == order || i_1 == order2 {
        if i_1 == order {
            (*ei).factor[0 as i32 as usize] = f;
            f *= if enc == FILE_ENC as i32 {
                PawnFactorFile[((*ei).norm[0 as i32 as usize] as i32 - 1 as i32) as usize]
                    [t as usize]
            } else if enc == RANK_ENC as i32 {
                PawnFactorRank[((*ei).norm[0 as i32 as usize] as i32 - 1 as i32) as usize]
                    [t as usize]
            } else {
                (if (*be).c2rust_unnamed.kk_enc as i32 != 0 {
                    462 as i32
                } else {
                    31332 as i32
                }) as u64
            };
        } else if i_1 == order2 {
            (*ei).factor[(*ei).norm[0 as i32 as usize] as usize] = f;
            f *= subfactor(
                (*ei).norm[(*ei).norm[0 as i32 as usize] as usize] as u64,
                (48 as i32 - (*ei).norm[0 as i32 as usize] as i32) as u64,
            );
        } else {
            (*ei).factor[k as usize] = f;
            f *= subfactor((*ei).norm[k as usize] as u64, n as u64);
            n -= (*ei).norm[k as usize] as i32;
            k += (*ei).norm[k as usize] as i32;
        }
        i_1 += 1;
    }
    f
}
unsafe extern "C" fn calc_symLen(mut d: *mut PairsData, mut s: u32, mut tmp: *mut i8) {
    let mut w: *mut u8 = ((*d).symPat).offset((3 as i32 as u32 * s) as isize);
    let mut s2: u32 = ((*w.offset(2 as i32 as isize) as i32) << 4 as i32
        | *w.offset(1 as i32 as isize) as i32 >> 4 as i32) as u32;
    if s2 == 0xfff as i32 as u32 {
        *((*d).symLen).offset(s as isize) = 0 as i32 as u8;
    } else {
        let mut s1: u32 = ((*w.offset(1 as i32 as isize) as i32 & 0xf as i32) << 8 as i32
            | *w.offset(0 as i32 as isize) as i32) as u32;
        if *tmp.offset(s1 as isize) == 0 {
            calc_symLen(d, s1, tmp);
        }
        if *tmp.offset(s2 as isize) == 0 {
            calc_symLen(d, s2, tmp);
        }
        *((*d).symLen).offset(s as isize) = (*((*d).symLen).offset(s1 as isize) as i32
            + *((*d).symLen).offset(s2 as isize) as i32
            + 1 as i32) as u8;
    }
    *tmp.offset(s as isize) = 1 as i32 as i8;
}
unsafe extern "C" fn setup_pairs(
    mut ptr: *mut *mut u8,
    mut tb_size: u64,
    mut size: *mut u64,
    mut flags: *mut u8,
    mut type_0: i32,
) -> *mut PairsData {
    let mut d: *mut PairsData = std::ptr::null_mut::<PairsData>();
    let mut data: *mut u8 = *ptr;
    *flags = *data.offset(0 as i32 as isize);
    if *data.offset(0 as i32 as isize) as i32 & 0x80 as i32 != 0 {
        d = malloc(::core::mem::size_of::<PairsData>() as u64) as *mut PairsData;
        (*d).idxBits = 0 as i32 as u8;
        (*d).constValue[0 as i32 as usize] = (if type_0 == WDL as i32 {
            *data.offset(1 as i32 as isize) as i32
        } else {
            0 as i32
        }) as u8;
        (*d).constValue[1 as i32 as usize] = 0 as i32 as u8;
        *ptr = data.offset(2 as i32 as isize);
        let fresh13 = &mut (*size.offset(2 as i32 as isize));
        *fresh13 = 0 as i32 as u64;
        let fresh14 = &mut (*size.offset(1 as i32 as isize));
        *fresh14 = *fresh13;
        *size.offset(0 as i32 as isize) = *fresh14;
        return d;
    }
    let mut blockSize: u8 = *data.offset(1 as i32 as isize);
    let mut idxBits: u8 = *data.offset(2 as i32 as isize);
    let mut realNumBlocks: u32 = read_le_u32(data.offset(4 as i32 as isize) as *mut libc::c_void);
    let mut numBlocks: u32 = realNumBlocks.wrapping_add(*data.offset(3 as i32 as isize) as u32);
    let mut maxLen: i32 = *data.offset(8 as i32 as isize) as i32;
    let mut minLen: i32 = *data.offset(9 as i32 as isize) as i32;
    let mut h: i32 = maxLen - minLen + 1 as i32;
    let mut numSyms: u32 = read_le_u16(
        data.offset(10 as i32 as isize)
            .offset((2 as i32 * h) as isize) as *mut libc::c_void,
    ) as u32;
    d = malloc(
        (::core::mem::size_of::<PairsData>() as u64)
            .wrapping_add((h as u64).wrapping_mul(::core::mem::size_of::<u64>() as u64))
            .wrapping_add(numSyms as u64),
    ) as *mut PairsData;
    (*d).blockSize = blockSize;
    (*d).idxBits = idxBits;
    (*d).offset = &mut *data.offset(10 as i32 as isize) as *mut u8 as *mut u16;
    (*d).symLen = (d as *mut u8)
        .offset(::core::mem::size_of::<PairsData>() as u64 as isize)
        .offset((h as u64).wrapping_mul(::core::mem::size_of::<u64>() as u64) as isize);
    (*d).symPat = &mut *data.offset((12 as i32 + 2 as i32 * h) as isize) as *mut u8;
    (*d).minLen = minLen as u8;
    *ptr = &mut *data.offset(
        ((12 as i32 + 2 as i32 * h) as u32)
            .wrapping_add(3 as i32 as u32 * numSyms)
            .wrapping_add(numSyms & 1 as i32 as u32) as isize,
    ) as *mut u8;
    let mut num_indices: u64 = ((tb_size as u64)
        .wrapping_add((1 as u64) << idxBits as i32)
        .wrapping_sub(1 as i32 as u64)
        >> idxBits as i32) as u64;
    *size.offset(0 as i32 as isize) = (6 as u64).wrapping_mul(num_indices as u64) as u64;
    *size.offset(1 as i32 as isize) = (2 as u64).wrapping_mul(numBlocks as u64) as u64;
    *size.offset(2 as i32 as isize) = (realNumBlocks as u64) << blockSize as i32;
    if numSyms < 4096 as i32 as u32 {
    } else {
        __assert_fail(
            b"numSyms < TB_MAX_SYMS\0" as *const u8 as *const i8,
            b"tbprobe.c\0" as *const u8 as *const i8,
            1273 as i32 as u32,
            (*::core::mem::transmute::<&[u8; 76], &[i8; 76]>(
                b"struct PairsData *setup_pairs(uint8_t **, size_t, size_t *, uint8_t *, int)\0",
            ))
            .as_ptr(),
        );
    };
    let mut tmp: [i8; 4096] = [0; 4096];
    memset(
        tmp.as_mut_ptr() as *mut libc::c_void,
        0 as i32,
        numSyms as u64,
    );
    let mut s: u32 = 0 as i32 as u32;
    while s < numSyms {
        if tmp[s as usize] == 0 {
            calc_symLen(d, s, tmp.as_mut_ptr());
        }
        s = s.wrapping_add(1);
    }
    *((*d).base).as_mut_ptr().offset((h - 1 as i32) as isize) = 0 as i32 as u64;
    let mut i: i32 = h - 2 as i32;
    while i >= 0 as i32 {
        *((*d).base).as_mut_ptr().offset(i as isize) =
            (*((*d).base).as_mut_ptr().offset((i + 1 as i32) as isize))
                .wrapping_add(read_le_u16(
                    ((*d).offset).offset(i as isize) as *mut u8 as *mut libc::c_void
                ) as u64)
                .wrapping_sub(read_le_u16(
                    ((*d).offset).offset(i as isize).offset(1 as i32 as isize) as *mut u8
                        as *mut libc::c_void,
                ) as u64)
                / 2 as i32 as u64;
        i -= 1;
    }
    let mut i_0: i32 = 0 as i32;
    while i_0 < h {
        *((*d).base).as_mut_ptr().offset(i_0 as isize) <<= 64 as i32 - (minLen + i_0);
        i_0 += 1;
    }
    (*d).offset = ((*d).offset).offset(-((*d).minLen as i32 as isize));
    d
}
unsafe extern "C" fn init_table(
    mut be: *mut BaseEntry,
    mut str: *const i8,
    mut type_0: i32,
) -> bool {
    let mut data: *mut u8 = map_tb(
        str,
        tbSuffix[type_0 as usize],
        &mut *((*be).mapping).as_mut_ptr().offset(type_0 as isize),
    ) as *mut u8;
    if data.is_null() {
        return 0 as i32 != 0;
    }
    if read_le_u32(data as *mut libc::c_void) != tbMagic[type_0 as usize] {
        fprintf(stderr, b"Corrupted table.\n\0" as *const u8 as *const i8);
        unmap_file(data as *mut libc::c_void, (*be).mapping[type_0 as usize]);
        return 0 as i32 != 0;
    }
    (*be).data[type_0 as usize] = data;
    let mut split: bool =
        type_0 != DTZ as i32 && *data.offset(4 as i32 as isize) as i32 & 0x1 as i32 != 0;
    if type_0 == DTM as i32 {
        (*be).dtmLossOnly = *data.offset(4 as i32 as isize) as i32 & 0x4 as i32 != 0;
    }
    data = data.offset(5 as i32 as isize);
    let mut tb_size: [[u64; 2]; 6] = [[0; 2]; 6];
    let mut num: i32 = num_tables(be, type_0);
    let mut ei: *mut EncInfo = first_ei(be, type_0);
    let mut enc: i32 = if !(*be).hasPawns {
        PIECE_ENC as i32
    } else if type_0 != DTM as i32 {
        FILE_ENC as i32
    } else {
        RANK_ENC as i32
    };
    let mut t: i32 = 0 as i32;
    while t < num {
        tb_size[t as usize][0 as i32 as usize] =
            init_enc_info(&mut *ei.offset(t as isize), be, data, 0 as i32, t, enc);
        if split {
            tb_size[t as usize][1 as i32 as usize] = init_enc_info(
                &mut *ei.offset((num + t) as isize),
                be,
                data,
                4 as i32,
                t,
                enc,
            );
        }
        data = data.offset(
            ((*be).num as i32
                + 1 as i32
                + ((*be).hasPawns as i32 != 0
                    && (*be).c2rust_unnamed.pawns[1 as i32 as usize] as i32 != 0)
                    as i32) as isize,
        );
        t += 1;
    }
    data = data.offset((data as u64 & 1 as i32 as u64) as isize);
    let mut size: [[[u64; 3]; 2]; 6] = [[[0; 3]; 2]; 6];
    let mut t_0: i32 = 0 as i32;
    while t_0 < num {
        let mut flags: u8 = 0;
        let fresh15 = &mut (*ei.offset(t_0 as isize)).precomp;
        *fresh15 = setup_pairs(
            &mut data,
            tb_size[t_0 as usize][0 as i32 as usize],
            (size[t_0 as usize][0 as i32 as usize]).as_mut_ptr(),
            &mut flags,
            type_0,
        );
        if type_0 == DTZ as i32 {
            if !(*be).hasPawns {
                (*(be as *mut PieceEntry)).dtzFlags = flags;
            } else {
                (*(be as *mut PawnEntry)).dtzFlags[t_0 as usize] = flags;
            }
        }
        if split {
            let fresh16 = &mut (*ei.offset((num + t_0) as isize)).precomp;
            *fresh16 = setup_pairs(
                &mut data,
                tb_size[t_0 as usize][1 as i32 as usize],
                (size[t_0 as usize][1 as i32 as usize]).as_mut_ptr(),
                &mut flags,
                type_0,
            );
        } else if type_0 != DTZ as i32 {
            let fresh17 = &mut (*ei.offset((num + t_0) as isize)).precomp;
            *fresh17 = std::ptr::null_mut::<PairsData>();
        }
        t_0 += 1;
    }
    if type_0 == DTM as i32 && !(*be).dtmLossOnly {
        let mut map: *mut u16 = data as *mut u16;
        let fresh18 = &mut (*if (*be).hasPawns as i32 != 0 {
            &mut (*(be as *mut PawnEntry)).dtmMap
        } else {
            &mut (*(be as *mut PieceEntry)).dtmMap
        });
        *fresh18 = map;
        let mut mapIdx: *mut [[u16; 2]; 2] = if (*be).hasPawns as i32 != 0 {
            &mut *((*(be as *mut PawnEntry)).dtmMapIdx)
                .as_mut_ptr()
                .offset(0 as i32 as isize) as *mut [[u16; 2]; 2]
        } else {
            &mut (*(be as *mut PieceEntry)).dtmMapIdx
        };
        let mut t_1: i32 = 0 as i32;
        while t_1 < num {
            let mut i: i32 = 0 as i32;
            while i < 2 as i32 {
                (*mapIdx.offset(t_1 as isize))[0 as i32 as usize][i as usize] =
                    data.offset(1 as i32 as isize).offset_from(map as *mut u8) as i64 as u16;
                data = data.offset(
                    (2 as i32 + 2 as i32 * read_le_u16(data as *mut libc::c_void) as i32) as isize,
                );
                i += 1;
            }
            if split {
                let mut i_0: i32 = 0 as i32;
                while i_0 < 2 as i32 {
                    (*mapIdx.offset(t_1 as isize))[1 as i32 as usize][i_0 as usize] =
                        data.offset(1 as i32 as isize).offset_from(map as *mut u8) as i64 as u16;
                    data = data.offset(
                        (2 as i32 + 2 as i32 * read_le_u16(data as *mut libc::c_void) as i32)
                            as isize,
                    );
                    i_0 += 1;
                }
            }
            t_1 += 1;
        }
    }
    if type_0 == DTZ as i32 {
        let mut map_0: *mut libc::c_void = data as *mut libc::c_void;
        let fresh19 = &mut (*if (*be).hasPawns as i32 != 0 {
            &mut (*(be as *mut PawnEntry)).dtzMap
        } else {
            &mut (*(be as *mut PieceEntry)).dtzMap
        });
        *fresh19 = map_0;
        let mut mapIdx_0: *mut [u16; 4] = if (*be).hasPawns as i32 != 0 {
            &mut *((*(be as *mut PawnEntry)).dtzMapIdx)
                .as_mut_ptr()
                .offset(0 as i32 as isize) as *mut [u16; 4]
        } else {
            &mut (*(be as *mut PieceEntry)).dtzMapIdx
        };
        let mut flags_0: *mut u8 = if (*be).hasPawns as i32 != 0 {
            &mut *((*(be as *mut PawnEntry)).dtzFlags)
                .as_mut_ptr()
                .offset(0 as i32 as isize) as *mut u8
        } else {
            &mut (*(be as *mut PieceEntry)).dtzFlags
        };
        let mut t_2: i32 = 0 as i32;
        while t_2 < num {
            if *flags_0.offset(t_2 as isize) as i32 & 2 as i32 != 0 {
                if *flags_0.offset(t_2 as isize) as i32 & 16 as i32 == 0 {
                    let mut i_1: i32 = 0 as i32;
                    while i_1 < 4 as i32 {
                        (*mapIdx_0.offset(t_2 as isize))[i_1 as usize] =
                            data.offset(1 as i32 as isize).offset_from(map_0 as *mut u8) as i64
                                as u16;
                        data = data
                            .offset((1 as i32 + *data.offset(0 as i32 as isize) as i32) as isize);
                        i_1 += 1;
                    }
                } else {
                    data = data.offset((data as u64 & 0x1 as i32 as u64) as isize);
                    let mut i_2: i32 = 0 as i32;
                    while i_2 < 4 as i32 {
                        (*mapIdx_0.offset(t_2 as isize))[i_2 as usize] = (data as *mut u16)
                            .offset(1 as i32 as isize)
                            .offset_from(map_0 as *mut u16)
                            as i64
                            as u16;
                        data = data.offset(
                            (2 as i32 + 2 as i32 * read_le_u16(data as *mut libc::c_void) as i32)
                                as isize,
                        );
                        i_2 += 1;
                    }
                }
            }
            t_2 += 1;
        }
        data = data.offset((data as u64 & 0x1 as i32 as u64) as isize);
    }
    let mut t_3: i32 = 0 as i32;
    while t_3 < num {
        let fresh20 = &mut (*(*ei.offset(t_3 as isize)).precomp).indexTable;
        *fresh20 = data;
        data = data.offset(size[t_3 as usize][0 as i32 as usize][0 as i32 as usize] as isize);
        if split {
            let fresh21 = &mut (*(*ei.offset((num + t_3) as isize)).precomp).indexTable;
            *fresh21 = data;
            data = data.offset(size[t_3 as usize][1 as i32 as usize][0 as i32 as usize] as isize);
        }
        t_3 += 1;
    }
    let mut t_4: i32 = 0 as i32;
    while t_4 < num {
        let fresh22 = &mut (*(*ei.offset(t_4 as isize)).precomp).sizeTable;
        *fresh22 = data as *mut u16;
        data = data.offset(size[t_4 as usize][0 as i32 as usize][1 as i32 as usize] as isize);
        if split {
            let fresh23 = &mut (*(*ei.offset((num + t_4) as isize)).precomp).sizeTable;
            *fresh23 = data as *mut u16;
            data = data.offset(size[t_4 as usize][1 as i32 as usize][1 as i32 as usize] as isize);
        }
        t_4 += 1;
    }
    let mut t_5: i32 = 0 as i32;
    while t_5 < num {
        data = ((data as u64).wrapping_add(0x3f as i32 as u64) & !(0x3f as i32) as u64) as *mut u8;
        let fresh24 = &mut (*(*ei.offset(t_5 as isize)).precomp).data;
        *fresh24 = data;
        data = data.offset(size[t_5 as usize][0 as i32 as usize][2 as i32 as usize] as isize);
        if split {
            data =
                ((data as u64).wrapping_add(0x3f as i32 as u64) & !(0x3f as i32) as u64) as *mut u8;
            let fresh25 = &mut (*(*ei.offset((num + t_5) as isize)).precomp).data;
            *fresh25 = data;
            data = data.offset(size[t_5 as usize][1 as i32 as usize][2 as i32 as usize] as isize);
        }
        t_5 += 1;
    }
    if type_0 == DTM as i32 && (*be).hasPawns as i32 != 0 {
        (*(be as *mut PawnEntry)).dtmSwitched = pyrrhic_calc_key_from_pieces(
            ((*ei.offset(0 as i32 as isize)).pieces).as_mut_ptr(),
            (*be).num as i32,
        ) != (*be).key;
    }
    1 as i32 != 0
}
unsafe extern "C" fn decompress_pairs(mut d: *mut PairsData, mut idx: u64) -> *mut u8 {
    if (*d).idxBits == 0 {
        return ((*d).constValue).as_mut_ptr();
    }
    let mut mainIdx: u32 = (idx >> (*d).idxBits as i32) as u32;
    let mut litIdx: i32 =
        (idx & ((1 as i32 as u64) << (*d).idxBits as i32).wrapping_sub(1 as i32 as u64))
            .wrapping_sub((1 as i32 as u64) << ((*d).idxBits as i32 - 1 as i32)) as i32;
    let mut block: u32 = 0;
    memcpy(
        &mut block as *mut u32 as *mut libc::c_void,
        ((*d).indexTable).offset((6 as i32 as u32 * mainIdx) as isize) as *const libc::c_void,
        ::core::mem::size_of::<u32>() as u64,
    );
    block = from_le_u32(block);
    let mut idxOffset: u16 = *(((*d).indexTable)
        .offset((6 as i32 as u32 * mainIdx) as isize)
        .offset(4 as i32 as isize) as *mut u16);
    litIdx += from_le_u16(idxOffset) as i32;
    if litIdx < 0 as i32 {
        while litIdx < 0 as i32 {
            block = block.wrapping_sub(1);
            litIdx += *((*d).sizeTable).offset(block as isize) as i32 + 1 as i32;
        }
    } else {
        while litIdx > *((*d).sizeTable).offset(block as isize) as i32 {
            let fresh26 = block;
            block = block.wrapping_add(1);
            litIdx -= *((*d).sizeTable).offset(fresh26 as isize) as i32 + 1 as i32;
        }
    }
    let mut ptr: *mut u32 =
        ((*d).data).offset(((block as u64) << (*d).blockSize as i32) as isize) as *mut u32;
    let mut m: i32 = (*d).minLen as i32;
    let mut offset: *mut u16 = (*d).offset;
    let mut base: *mut u64 = ((*d).base).as_mut_ptr().offset(-(m as isize));
    let mut symLen: *mut u8 = (*d).symLen;
    let mut sym: u32 = 0;
    let mut bitCnt: u32 = 0;
    let mut code: u64 = from_be_u64(*(ptr as *mut u64));
    ptr = ptr.offset(2 as i32 as isize);
    bitCnt = 0 as i32 as u32;
    loop {
        let mut l: i32 = m;
        while code < *base.offset(l as isize) {
            l += 1;
        }
        sym = from_le_u16(*offset.offset(l as isize)) as u32;
        sym = sym
            .wrapping_add((code.wrapping_sub(*base.offset(l as isize)) >> (64 as i32 - l)) as u32);
        if litIdx < *symLen.offset(sym as isize) as i32 + 1 as i32 {
            break;
        }
        litIdx -= *symLen.offset(sym as isize) as i32 + 1 as i32;
        code <<= l;
        bitCnt = bitCnt.wrapping_add(l as u32);
        if bitCnt >= 32 as i32 as u32 {
            bitCnt = bitCnt.wrapping_sub(32 as i32 as u32);
            let fresh27 = ptr;
            ptr = ptr.offset(1);
            let mut tmp: u32 = from_be_u32(*fresh27);
            code |= (tmp as u64) << bitCnt;
        }
    }
    let mut symPat: *mut u8 = (*d).symPat;
    while *symLen.offset(sym as isize) as i32 != 0 as i32 {
        let mut w: *mut u8 = symPat.offset((3 as i32 as u32 * sym) as isize);
        let mut s1: i32 = (*w.offset(1 as i32 as isize) as i32 & 0xf as i32) << 8 as i32
            | *w.offset(0 as i32 as isize) as i32;
        if litIdx < *symLen.offset(s1 as isize) as i32 + 1 as i32 {
            sym = s1 as u32;
        } else {
            litIdx -= *symLen.offset(s1 as isize) as i32 + 1 as i32;
            sym = ((*w.offset(2 as i32 as isize) as i32) << 4 as i32
                | *w.offset(1 as i32 as isize) as i32 >> 4 as i32) as u32;
        }
    }
    &mut *symPat.offset((3 as i32 as u32 * sym) as isize) as *mut u8
}
#[inline]
unsafe extern "C" fn fill_squares(
    mut pos: *const PyrrhicPosition,
    mut pc: *mut u8,
    mut flip: bool,
    mut mirror: i32,
    mut p: *mut i32,
    mut i: i32,
) -> i32 {
    let mut color: i32 = pyrrhic_colour_of_piece(*pc.offset(i as isize));
    if flip {
        color = (color == 0) as i32;
    }
    let mut bb: u64 =
        pyrrhic_pieces_by_type(pos, color, pyrrhic_type_of_piece(*pc.offset(i as isize)));
    let mut sq: u32 = 0;
    loop {
        sq = poplsb(&mut bb) as u32;
        let fresh28 = i;
        i += 1;
        *p.offset(fresh28 as isize) = (sq ^ mirror as u32) as i32;
        if bb == 0 {
            break;
        }
    }
    i
}
#[no_mangle]
pub unsafe extern "C" fn probe_table(
    mut pos: *const PyrrhicPosition,
    mut s: i32,
    mut success: *mut i32,
    type_0: i32,
) -> i32 {
    let mut key: u64 = pyrrhic_calc_key(pos, 0 as i32);
    if type_0 == WDL as i32 && key as u64 == 0 as u64 {
        return 0 as i32;
    }
    let mut hashIdx: i32 = (key
        >> (64 as i32
            - (if (7 as i32) < 7 as i32 {
                11 as i32
            } else {
                12 as i32
            }))) as i32;
    while tbHash[hashIdx as usize].key != 0 && tbHash[hashIdx as usize].key != key {
        hashIdx = (hashIdx + 1 as i32)
            & (((1 as i32)
                << (if (7 as i32) < 7 as i32 {
                    11 as i32
                } else {
                    12 as i32
                }))
                - 1 as i32);
    }
    if (tbHash[hashIdx as usize].ptr).is_null() {
        *success = 0 as i32;
        return 0 as i32;
    }
    let mut be: *mut BaseEntry = tbHash[hashIdx as usize].ptr;
    if type_0 == DTM as i32 && !(*be).hasDtm || type_0 == DTZ as i32 && !(*be).hasDtz {
        *success = 0 as i32;
        return 0 as i32;
    }
    if !atomic_load_explicit(
        &mut *((*be).ready).as_mut_ptr().offset(type_0 as isize),
        memory_order_acquire as i32,
    ) {
        pthread_mutex_lock(addr_of_mut!(tbMutex));
        if !atomic_load_explicit(
            &mut *((*be).ready).as_mut_ptr().offset(type_0 as isize),
            memory_order_relaxed as i32,
        ) {
            let mut str: [i8; 16] = [0; 16];
            prt_str(pos, str.as_mut_ptr(), ((*be).key != key) as i32);
            if !init_table(be, str.as_mut_ptr(), type_0) {
                tbHash[hashIdx as usize].ptr = std::ptr::null_mut::<BaseEntry>();
                *success = 0 as i32;
                pthread_mutex_unlock(addr_of_mut!(tbMutex));
                return 0 as i32;
            }
            atomic_store_explicit(
                &mut *((*be).ready).as_mut_ptr().offset(type_0 as isize),
                1 as i32 != 0,
                memory_order_release as i32,
            );
        }
        pthread_mutex_unlock(addr_of_mut!(tbMutex));
    }
    let mut bside: bool = false;
    let mut flip: bool = false;
    if !(*be).symmetric {
        flip = key != (*be).key;
        bside = ((*pos).turn as i32 == PYRRHIC_WHITE as i32) as i32 == flip as i32;
        if type_0 == DTM as i32
            && (*be).hasPawns as i32 != 0
            && (*(be as *mut PawnEntry)).dtmSwitched as i32 != 0
        {
            flip = !flip;
            bside = !bside;
        }
    } else {
        flip = (*pos).turn as i32 != PYRRHIC_WHITE as i32;
        bside = 0 as i32 != 0;
    }
    let mut ei: *mut EncInfo = first_ei(be, type_0);
    let mut p: [i32; 7] = [0; 7];
    let mut idx: u64 = 0;
    let mut t: i32 = 0 as i32;
    let mut flags: u8 = 0 as i32 as u8;
    if !(*be).hasPawns {
        if type_0 == DTZ as i32 {
            flags = (*(be as *mut PieceEntry)).dtzFlags;
            if flags as i32 & 1 as i32 != bside as i32 && !(*be).symmetric {
                *success = -(1 as i32);
                return 0 as i32;
            }
        }
        ei = if type_0 != DTZ as i32 {
            &mut *ei.offset(bside as isize) as *mut EncInfo
        } else {
            ei
        };
        let mut i: i32 = 0 as i32;
        while i < (*be).num as i32 {
            i = fill_squares(
                pos,
                ((*ei).pieces).as_mut_ptr(),
                flip,
                0 as i32,
                p.as_mut_ptr(),
                i,
            );
        }
        idx = encode_piece(p.as_mut_ptr(), ei, be);
    } else {
        let mut i_0: i32 = fill_squares(
            pos,
            ((*ei).pieces).as_mut_ptr(),
            flip,
            if flip as i32 != 0 {
                0x38 as i32
            } else {
                0 as i32
            },
            p.as_mut_ptr(),
            0 as i32,
        );
        t = leading_pawn(
            p.as_mut_ptr(),
            be,
            if type_0 != DTM as i32 {
                FILE_ENC as i32
            } else {
                RANK_ENC as i32
            },
        );
        if type_0 == DTZ as i32 {
            flags = (*(be as *mut PawnEntry)).dtzFlags[t as usize];
            if flags as i32 & 1 as i32 != bside as i32 && !(*be).symmetric {
                *success = -(1 as i32);
                return 0 as i32;
            }
        }
        ei = if type_0 == WDL as i32 {
            &mut *ei.offset((t + 4 as i32 * bside as i32) as isize) as *mut EncInfo
        } else if type_0 == DTM as i32 {
            &mut *ei.offset((t + 6 as i32 * bside as i32) as isize) as *mut EncInfo
        } else {
            &mut *ei.offset(t as isize) as *mut EncInfo
        };
        while i_0 < (*be).num as i32 {
            i_0 = fill_squares(
                pos,
                ((*ei).pieces).as_mut_ptr(),
                flip,
                if flip as i32 != 0 {
                    0x38 as i32
                } else {
                    0 as i32
                },
                p.as_mut_ptr(),
                i_0,
            );
        }
        idx = if type_0 != DTM as i32 {
            encode_pawn_f(p.as_mut_ptr(), ei, be)
        } else {
            encode_pawn_r(p.as_mut_ptr(), ei, be)
        };
    }
    let mut w: *mut u8 = decompress_pairs((*ei).precomp, idx);
    if type_0 == WDL as i32 {
        return *w.offset(0 as i32 as isize) as i32 - 2 as i32;
    }
    let mut v: i32 = *w.offset(0 as i32 as isize) as i32
        + ((*w.offset(1 as i32 as isize) as i32 & 0xf as i32) << 8 as i32);
    if type_0 == DTM as i32 {
        if !(*be).dtmLossOnly {
            v = from_le_u16(
                (if (*be).hasPawns as i32 != 0 {
                    *((*(be as *mut PawnEntry)).dtmMap).offset(
                        ((*(be as *mut PawnEntry)).dtmMapIdx[t as usize][bside as usize][s as usize]
                            as i32
                            + v) as isize,
                    ) as i32
                } else {
                    *((*(be as *mut PieceEntry)).dtmMap).offset(
                        ((*(be as *mut PieceEntry)).dtmMapIdx[bside as usize][s as usize] as i32
                            + v) as isize,
                    ) as i32
                }) as u16,
            ) as i32;
        }
    } else {
        if flags as i32 & 2 as i32 != 0 {
            let mut m: i32 = WdlToMap[(s + 2 as i32) as usize];
            if flags as i32 & 16 as i32 == 0 {
                v = if (*be).hasPawns as i32 != 0 {
                    *((*(be as *mut PawnEntry)).dtzMap as *mut u8).offset(
                        ((*(be as *mut PawnEntry)).dtzMapIdx[t as usize][m as usize] as i32 + v)
                            as isize,
                    ) as i32
                } else {
                    *((*(be as *mut PieceEntry)).dtzMap as *mut u8).offset(
                        ((*(be as *mut PieceEntry)).dtzMapIdx[m as usize] as i32 + v) as isize,
                    ) as i32
                };
            } else {
                v = from_le_u16(
                    (if (*be).hasPawns as i32 != 0 {
                        *((*(be as *mut PawnEntry)).dtzMap as *mut u16).offset(
                            ((*(be as *mut PawnEntry)).dtzMapIdx[t as usize][m as usize] as i32 + v)
                                as isize,
                        ) as i32
                    } else {
                        *((*(be as *mut PieceEntry)).dtzMap as *mut u16).offset(
                            ((*(be as *mut PieceEntry)).dtzMapIdx[m as usize] as i32 + v) as isize,
                        ) as i32
                    }) as u16,
                ) as i32;
            }
        }
        if flags as i32 & PAFlags[(s + 2 as i32) as usize] as i32 == 0 || s & 1 as i32 != 0 {
            v *= 2 as i32;
        }
    }
    v
}
unsafe extern "C" fn probe_wdl_table(
    mut pos: *const PyrrhicPosition,
    mut success: *mut i32,
) -> i32 {
    probe_table(pos, 0 as i32, success, WDL as i32)
}
unsafe extern "C" fn probe_dtz_table(
    mut pos: *const PyrrhicPosition,
    mut wdl: i32,
    mut success: *mut i32,
) -> i32 {
    probe_table(pos, wdl, success, DTZ as i32)
}
unsafe extern "C" fn probe_ab(
    mut pos: *const PyrrhicPosition,
    mut alpha: i32,
    mut beta: i32,
    mut success: *mut i32,
) -> i32 {
    if (*pos).ep as i32 == 0 as i32 {
    } else {
        __assert_fail(
            b"pos->ep == 0\0" as *const u8 as *const i8,
            b"tbprobe.c\0" as *const u8 as *const i8,
            1665 as i32 as u32,
            (*::core::mem::transmute::<&[u8; 55], &[i8; 55]>(
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
        if pyrrhic_is_capture(pos, move_0) && pyrrhic_do_move(&mut pos1, pos, move_0) {
            let mut v: i32 = -probe_ab(&mut pos1, -beta, -alpha, success);
            if *success == 0 as i32 {
                return 0 as i32;
            }
            if v > alpha {
                if v >= beta {
                    return v;
                }
                alpha = v;
            }
        }
        m = m.offset(1);
    }
    let mut v_0: i32 = probe_wdl_table(pos, success);
    if alpha >= v_0 {
        alpha
    } else {
        v_0
    }
}
unsafe extern "C" fn probe_wdl(mut pos: *mut PyrrhicPosition, mut success: *mut i32) -> i32 {
    *success = 1 as i32;
    let mut moves0: [PyrrhicMove; 64] = [0; 64];
    let mut m: *mut PyrrhicMove = moves0.as_mut_ptr();
    let mut end: *mut PyrrhicMove = pyrrhic_gen_captures(pos, m);
    let mut bestCap: i32 = -(3 as i32);
    let mut bestEp: i32 = -(3 as i32);
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
        if pyrrhic_is_capture(pos, move_0) && pyrrhic_do_move(&mut pos1, pos, move_0) {
            let mut v: i32 = -probe_ab(&mut pos1, -(2 as i32), -bestCap, success);
            if *success == 0 as i32 {
                return 0 as i32;
            }
            if v > bestCap {
                if v == 2 as i32 {
                    *success = 2 as i32;
                    return 2 as i32;
                }
                if !pyrrhic_is_en_passant(pos, move_0) {
                    bestCap = v;
                } else if v > bestEp {
                    bestEp = v;
                }
            }
        }
        m = m.offset(1);
    }
    let mut v_0: i32 = probe_wdl_table(pos, success);
    if *success == 0 as i32 {
        return 0 as i32;
    }
    if bestEp > bestCap {
        if bestEp > v_0 {
            *success = 2 as i32;
            return bestEp;
        }
        bestCap = bestEp;
    }
    if bestCap >= v_0 {
        *success = 1 as i32 + (bestCap > 0 as i32) as i32;
        return bestCap;
    }
    if bestEp > -(3 as i32) && v_0 == 0 as i32 {
        let mut moves: [PyrrhicMove; 256] = [0; 256];
        let mut end2: *mut PyrrhicMove = pyrrhic_gen_moves(pos, moves.as_mut_ptr());
        m = moves.as_mut_ptr();
        while m < end2 {
            if !pyrrhic_is_en_passant(pos, *m) && pyrrhic_legal_move(pos, *m) as i32 != 0 {
                break;
            }
            m = m.offset(1);
        }
        if m == end2 && !pyrrhic_is_check(pos) {
            *success = 2 as i32;
            return bestEp;
        }
    }
    v_0
}
static mut WdlToDtz: [i32; 5] = [-(1 as i32), -(101 as i32), 0 as i32, 101 as i32, 1 as i32];
unsafe extern "C" fn probe_dtz(mut pos: *mut PyrrhicPosition, mut success: *mut i32) -> i32 {
    let mut wdl: i32 = probe_wdl(pos, success);
    if *success == 0 as i32 {
        return 0 as i32;
    }
    if wdl == 0 as i32 {
        return 0 as i32;
    }
    if *success == 2 as i32 {
        return WdlToDtz[(wdl + 2 as i32) as usize];
    }
    let mut moves: [PyrrhicMove; 256] = [0; 256];
    let mut m: *mut PyrrhicMove = moves.as_mut_ptr();
    let mut end: *mut PyrrhicMove = std::ptr::null_mut::<PyrrhicMove>();
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
    if wdl > 0 as i32 {
        end = pyrrhic_gen_legal(pos, moves.as_mut_ptr());
        m = moves.as_mut_ptr();
        while m < end {
            let mut move_0: PyrrhicMove = *m;
            if !(!pyrrhic_is_pawn_move(pos, move_0) || pyrrhic_is_capture(pos, move_0) as i32 != 0)
                && pyrrhic_do_move(&mut pos1, pos, move_0)
            {
                let mut v: i32 = -probe_wdl(&mut pos1, success);
                if *success == 0 as i32 {
                    return 0 as i32;
                }
                if v == wdl {
                    if wdl < 3 as i32 {
                    } else {
                        __assert_fail(
                            b"wdl < 3\0" as *const u8 as *const i8,
                            b"tbprobe.c\0" as *const u8 as *const i8,
                            1852 as i32 as u32,
                            (*::core::mem::transmute::<&[u8; 40], &[i8; 40]>(
                                b"int probe_dtz(PyrrhicPosition *, int *)\0",
                            ))
                            .as_ptr(),
                        );
                    };
                    return WdlToDtz[(wdl + 2 as i32) as usize];
                }
            }
            m = m.offset(1);
        }
    }
    let mut dtz: i32 = probe_dtz_table(pos, wdl, success);
    if *success >= 0 as i32 {
        return WdlToDtz[(wdl + 2 as i32) as usize] + (if wdl > 0 as i32 { dtz } else { -dtz });
    }
    let mut best: i32 = 0;
    if wdl > 0 as i32 {
        best = 2147483647 as i32;
    } else {
        best = WdlToDtz[(wdl + 2 as i32) as usize];
        end = pyrrhic_gen_moves(pos, m);
    }
    if !end.is_null() {
    } else {
        __assert_fail(
            b"end != NULL\0" as *const u8 as *const i8,
            b"tbprobe.c\0" as *const u8 as *const i8,
            1879 as i32 as u32,
            (*::core::mem::transmute::<&[u8; 40], &[i8; 40]>(
                b"int probe_dtz(PyrrhicPosition *, int *)\0",
            ))
            .as_ptr(),
        );
    };
    m = moves.as_mut_ptr();
    while m < end {
        let mut move_1: PyrrhicMove = *m;
        if !(pyrrhic_is_capture(pos, move_1) as i32 != 0
            || pyrrhic_is_pawn_move(pos, move_1) as i32 != 0)
            && pyrrhic_do_move(&mut pos1, pos, move_1)
        {
            let mut v_0: i32 = -probe_dtz(&mut pos1, success);
            if v_0 == 1 as i32 && pyrrhic_is_mate(&mut pos1) as i32 != 0 {
                best = 1 as i32;
            } else if wdl > 0 as i32 {
                if v_0 > 0 as i32 && (v_0 + 1 as i32) < best {
                    best = v_0 + 1 as i32;
                }
            } else if (v_0 - 1 as i32) < best {
                best = v_0 - 1 as i32;
            }
            if *success == 0 as i32 {
                return 0 as i32;
            }
        }
        m = m.offset(1);
    }
    best
}
#[no_mangle]
pub unsafe extern "C" fn root_probe_dtz(
    mut pos: *const PyrrhicPosition,
    mut hasRepeated: bool,
    mut useRule50: bool,
    mut rm: *mut TbRootMoves,
) -> i32 {
    let mut v: i32 = 0;
    let mut success: i32 = 0;
    let mut cnt50: i32 = (*pos).rule50 as i32;
    let mut bound: i32 = if useRule50 as i32 != 0 {
        0x40000 as i32 - 100 as i32
    } else {
        1 as i32
    };
    let mut rootMoves: [PyrrhicMove; 256] = [0; 256];
    let mut end: *mut PyrrhicMove = pyrrhic_gen_legal(pos, rootMoves.as_mut_ptr());
    (*rm).size = end.offset_from(rootMoves.as_mut_ptr()) as i64 as u32;
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
    let mut i: u32 = 0 as i32 as u32;
    while i < (*rm).size {
        let mut m: *mut TbRootMove =
            &mut *((*rm).moves).as_mut_ptr().offset(i as isize) as *mut TbRootMove;
        (*m).move_0 = rootMoves[i as usize];
        pyrrhic_do_move(&mut pos1, pos, (*m).move_0);
        if pos1.rule50 as i32 == 0 as i32 {
            v = -probe_wdl(&mut pos1, &mut success);
            if v < 3 as i32 {
            } else {
                __assert_fail(
                    b"v < 3\0" as *const u8 as *const i8,
                    b"tbprobe.c\0" as *const u8 as *const i8,
                    1935 as i32 as u32,
                    (*::core::mem::transmute::<
                        &[u8; 80],
                        &[i8; 80],
                    >(
                        b"int root_probe_dtz(const PyrrhicPosition *, _Bool, _Bool, struct TbRootMoves *)\0",
                    ))
                        .as_ptr(),
                );
            };
            v = WdlToDtz[(v + 2 as i32) as usize];
        } else {
            v = -probe_dtz(&mut pos1, &mut success);
            if v > 0 as i32 {
                v += 1;
            } else if v < 0 as i32 {
                v -= 1;
            }
        }
        if v == 2 as i32 && pyrrhic_is_mate(&mut pos1) as i32 != 0 {
            v = 1 as i32;
        }
        if success == 0 {
            return 0 as i32;
        }
        let mut r: i32 = if v > 0 as i32 {
            if v + cnt50 <= 99 as i32 && !hasRepeated {
                0x40000 as i32
            } else {
                0x40000 as i32 - (v + cnt50)
            }
        } else if v < 0 as i32 {
            if -v * 2 as i32 + cnt50 < 100 as i32 {
                -(0x40000 as i32)
            } else {
                -(0x40000 as i32) + (-v + cnt50)
            }
        } else {
            0 as i32
        };
        (*m).tbRank = r;
        (*m).tbScore = if r >= bound {
            32000 as i32 - 255 as i32 - 1 as i32
        } else if r > 0 as i32 {
            (if 3 as i32 > r - (0x40000 as i32 - 200 as i32) {
                3 as i32
            } else {
                r - (0x40000 as i32 - 200 as i32)
            }) * 100 as i32
                / 200 as i32
        } else if r == 0 as i32 {
            0 as i32
        } else if r > -bound {
            (if -(3 as i32) < r + (0x40000 as i32 - 200 as i32) {
                -(3 as i32)
            } else {
                r + (0x40000 as i32 - 200 as i32)
            }) * 100 as i32
                / 200 as i32
        } else {
            -(32000 as i32) + 255 as i32 + 1 as i32
        };
        i = i.wrapping_add(1);
    }
    1 as i32
}
#[no_mangle]
pub unsafe extern "C" fn root_probe_wdl(
    mut pos: *const PyrrhicPosition,
    mut useRule50: bool,
    mut rm: *mut TbRootMoves,
) -> i32 {
    static mut WdlToRank: [i32; 5] = [
        -(0x40000 as i32),
        -(0x40000 as i32) + 101 as i32,
        0 as i32,
        0x40000 as i32 - 101 as i32,
        0x40000 as i32,
    ];
    static mut WdlToValue: [i32; 5] = [
        -(32000 as i32) + 255 as i32 + 1 as i32,
        0 as i32 - 2 as i32,
        0 as i32,
        0 as i32 + 2 as i32,
        32000 as i32 - 255 as i32 - 1 as i32,
    ];
    let mut v: i32 = 0;
    let mut success: i32 = 0;
    let mut moves: [PyrrhicMove; 256] = [0; 256];
    let mut end: *mut PyrrhicMove = pyrrhic_gen_legal(pos, moves.as_mut_ptr());
    (*rm).size = end.offset_from(moves.as_mut_ptr()) as i64 as u32;
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
    let mut i: u32 = 0 as i32 as u32;
    while i < (*rm).size {
        let mut m: *mut TbRootMove =
            &mut *((*rm).moves).as_mut_ptr().offset(i as isize) as *mut TbRootMove;
        (*m).move_0 = moves[i as usize];
        pyrrhic_do_move(&mut pos1, pos, (*m).move_0);
        v = -probe_wdl(&mut pos1, &mut success);
        if success == 0 {
            return 0 as i32;
        }
        if !useRule50 {
            v = if v > 0 as i32 {
                2 as i32
            } else if v < 0 as i32 {
                -(2 as i32)
            } else {
                0 as i32
            };
        }
        (*m).tbRank = WdlToRank[(v + 2 as i32) as usize];
        (*m).tbScore = WdlToValue[(v + 2 as i32) as usize];
        i = i.wrapping_add(1);
    }
    1 as i32
}
static mut wdl_to_dtz: [i32; 5] = [-(1 as i32), -(101 as i32), 0 as i32, 101 as i32, 1 as i32];
unsafe extern "C" fn probe_root(
    mut pos: *mut PyrrhicPosition,
    mut score: *mut i32,
    mut results: *mut u32,
) -> u16 {
    let mut success: i32 = 0;
    let mut dtz: i32 = probe_dtz(pos, &mut success);
    if success == 0 {
        return 0 as i32 as u16;
    }
    let mut scores: [i16; 256] = [0; 256];
    let mut moves0: [u16; 256] = [0; 256];
    let mut moves: *mut u16 = moves0.as_mut_ptr();
    let mut end: *mut u16 = pyrrhic_gen_moves(pos, moves);
    let mut len: u64 = end.offset_from(moves) as i64 as u64;
    let mut num_draw: u64 = 0 as i32 as u64;
    let mut j: u32 = 0 as i32 as u32;
    let mut i: u32 = 0 as i32 as u32;
    while (i as u64) < len {
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
            scores[i as usize] = 0x7fff as i32 as i16;
        } else {
            let mut v: i32 = 0 as i32;
            if dtz > 0 as i32 && pyrrhic_is_mate(&mut pos1) as i32 != 0 {
                v = 1 as i32;
            } else if pos1.rule50 as i32 != 0 as i32 {
                v = -probe_dtz(&mut pos1, &mut success);
                if v > 0 as i32 {
                    v += 1;
                } else if v < 0 as i32 {
                    v -= 1;
                }
            } else {
                v = -probe_wdl(&mut pos1, &mut success);
                v = wdl_to_dtz[(v + 2 as i32) as usize];
            }
            num_draw = num_draw.wrapping_add((v == 0 as i32) as i32 as u64);
            if success == 0 {
                return 0 as i32 as u16;
            }
            scores[i as usize] = v as i16;
            if !results.is_null() {
                let mut res: u32 = 0 as i32 as u32;
                res = res & !(0xf as i32) as u32
                    | dtz_to_wdl((*pos).rule50 as i32, v) << 0 as i32 & 0xf as i32 as u32;
                res = res & !(0xfc00 as i32) as u32
                    | pyrrhic_move_from(*moves.offset(i as isize)) << 10 as i32
                        & 0xfc00 as i32 as u32;
                res = res & !(0x3f0 as i32) as u32
                    | pyrrhic_move_to(*moves.offset(i as isize)) << 4 as i32 & 0x3f0 as i32 as u32;
                res = res & !(0x70000 as i32) as u32
                    | pyrrhic_move_promotes(*moves.offset(i as isize)) << 16 as i32
                        & 0x70000 as i32 as u32;
                res = res & !(0x80000 as i32) as u32
                    | ((pyrrhic_is_en_passant(pos, *moves.offset(i as isize)) as i32) << 19 as i32
                        & 0x80000 as i32) as u32;
                res = res & !(0xfff00000 as u32)
                    | ((if v < 0 as i32 { -v } else { v }) << 20 as i32) as u32 & 0xfff00000 as u32;
                let fresh29 = j;
                j = j.wrapping_add(1);
                *results.offset(fresh29 as isize) = res;
            }
        }
        i = i.wrapping_add(1);
    }
    if !results.is_null() {
        let fresh30 = j;
        j = j.wrapping_add(1);
        *results.offset(fresh30 as isize) = 0xffffffff as u32;
    }
    if !score.is_null() {
        *score = dtz;
    }
    if dtz > 0 as i32 {
        let mut best: i32 = 0xffff as i32;
        let mut best_move: u16 = 0 as i32 as u16;
        let mut i_0: u32 = 0 as i32 as u32;
        while (i_0 as u64) < len {
            let mut v_0: i32 = scores[i_0 as usize] as i32;
            if v_0 != 0x7fff as i32 && v_0 > 0 as i32 && v_0 < best {
                best = v_0;
                best_move = *moves.offset(i_0 as isize);
            }
            i_0 = i_0.wrapping_add(1);
        }
        (if best == 0xffff as i32 {
            0 as i32
        } else {
            best_move as i32
        }) as u16
    } else if dtz < 0 as i32 {
        let mut best_0: i32 = 0 as i32;
        let mut best_move_0: u16 = 0 as i32 as u16;
        let mut i_1: u32 = 0 as i32 as u32;
        while (i_1 as u64) < len {
            let mut v_1: i32 = scores[i_1 as usize] as i32;
            if v_1 != 0x7fff as i32 && v_1 < best_0 {
                best_0 = v_1;
                best_move_0 = *moves.offset(i_1 as isize);
            }
            i_1 = i_1.wrapping_add(1);
        }
        return (if best_0 == 0 as i32 {
            0xfffe as i32
        } else {
            best_move_0 as i32
        }) as u16;
    } else {
        if num_draw == 0 as i32 as u64 {
            return 0xffff as i32 as u16;
        }
        let mut count: u64 = (pyrrhic_calc_key(pos, !(*pos).turn as i32)).wrapping_rem(num_draw);
        let mut i_2: u32 = 0 as i32 as u32;
        while (i_2 as u64) < len {
            let mut v_2: i32 = scores[i_2 as usize] as i32;
            if v_2 != 0x7fff as i32 && v_2 == 0 as i32 {
                if count == 0 as i32 as u64 {
                    return *moves.offset(i_2 as isize);
                }
                count = count.wrapping_sub(1);
            }
            i_2 = i_2.wrapping_add(1);
        }
        return 0 as i32 as u16;
    }
}