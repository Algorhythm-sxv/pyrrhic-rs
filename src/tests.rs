use std::{ffi::CString, str::FromStr};

use crate::{
    engine_adapter::{Color, EngineAdapter},
    tbprobe::*,
};
use cozy_chess::*;

struct CozyChessAdapter;

impl EngineAdapter for CozyChessAdapter {
    fn pawn_attacks(color: Color, sq: u64) -> u64 {
        let attacks = get_pawn_attacks(
            Square::index(sq as usize),
            if color == Color::Black {
                cozy_chess::Color::Black
            } else {
                cozy_chess::Color::White
            },
        );
        attacks.0
    }
    fn knight_attacks(sq: u64) -> u64 {
        get_knight_moves(Square::index(sq as usize)).0
    }
    fn bishop_attacks(sq: u64, occ: u64) -> u64 {
        get_bishop_moves(Square::index(sq as usize), BitBoard(occ)).0
    }
    fn rook_attacks(sq: u64, occ: u64) -> u64 {
        get_rook_moves(Square::index(sq as usize), BitBoard(occ)).0
    }
    fn king_attacks(sq: u64) -> u64 {
        get_king_moves(Square::index(sq as usize)).0
    }
    fn queen_attacks(sq: u64, occ: u64) -> u64 {
        (get_bishop_moves(Square::index(sq as usize), BitBoard(occ))
            | get_rook_moves(Square::index(sq as usize), BitBoard(occ)))
        .0
    }
}
#[test]
fn test_probe_kpvk() {
    unsafe {
        let syzygy_path = CString::new(env!("SYZYGY_PATH")).unwrap();
        let init = tb_init(syzygy_path.as_ptr() as *const i8);
        if !init {
            panic!("failed to init TBs")
        }
        let test_pos_wins = [
            ("6k1/8/8/3P4/4K3/8/8/8 w - - 0 1", 1),
            ("8/7k/1p6/1P6/7K/8/8/8 w - - 0 1", 21),
        ];
        let test_pos_draw = "6k1/8/8/3P4/4K3/8/8/8 b - - 0 1";

        for (win_pos, dtz) in test_pos_wins {
            let test_board_win = Board::from_str(win_pos).unwrap();

            let wdl_win = tb_probe_wdl::<CozyChessAdapter>(
                test_board_win.colors(cozy_chess::Color::White).0,
                test_board_win.colors(cozy_chess::Color::Black).0,
                test_board_win.pieces(Piece::King).0,
                test_board_win.pieces(Piece::Queen).0,
                test_board_win.pieces(Piece::Rook).0,
                test_board_win.pieces(Piece::Bishop).0,
                test_board_win.pieces(Piece::Knight).0,
                test_board_win.pieces(Piece::Pawn).0,
                0, // no ep square
                test_board_win.side_to_move() == cozy_chess::Color::White,
            );
            assert!(wdl_win == 4);
            let mut results = 0u32;
            let dtz_result = tb_probe_root::<CozyChessAdapter>(
                test_board_win.colors(cozy_chess::Color::White).0,
                test_board_win.colors(cozy_chess::Color::Black).0,
                test_board_win.pieces(Piece::King).0,
                test_board_win.pieces(Piece::Queen).0,
                test_board_win.pieces(Piece::Rook).0,
                test_board_win.pieces(Piece::Bishop).0,
                test_board_win.pieces(Piece::Knight).0,
                test_board_win.pieces(Piece::Pawn).0,
                0,
                0,
                test_board_win.side_to_move() == cozy_chess::Color::White,
                &mut results as *mut _,
            );

            assert!((dtz_result & 0xFFF00000) >> 20 == dtz);
        }
        let test_board_draw = Board::from_str(test_pos_draw).unwrap();
        let wdl_draw = tb_probe_wdl::<CozyChessAdapter>(
            test_board_draw.colors(cozy_chess::Color::White).0,
            test_board_draw.colors(cozy_chess::Color::Black).0,
            test_board_draw.pieces(Piece::King).0,
            test_board_draw.pieces(Piece::Queen).0,
            test_board_draw.pieces(Piece::Rook).0,
            test_board_draw.pieces(Piece::Bishop).0,
            test_board_draw.pieces(Piece::Knight).0,
            test_board_draw.pieces(Piece::Pawn).0,
            0, // no ep square
            test_board_draw.side_to_move() == cozy_chess::Color::White,
        );

        assert!(wdl_draw == 2);
        tb_free();
    }
}
