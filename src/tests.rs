use std::{ffi::CString, str::FromStr};

use crate::tbprobe::*;
use cozy_chess::*;

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

            let wdl_win = tb_probe_wdl(
                test_board_win.colors(Color::White).0,
                test_board_win.colors(Color::Black).0,
                test_board_win.pieces(Piece::King).0,
                test_board_win.pieces(Piece::Queen).0,
                test_board_win.pieces(Piece::Rook).0,
                test_board_win.pieces(Piece::Bishop).0,
                test_board_win.pieces(Piece::Knight).0,
                test_board_win.pieces(Piece::Pawn).0,
                0, // no ep square
                test_board_win.side_to_move() == Color::White,
            );
            assert!(wdl_win == 4);
            let mut results = 0u32;
            let dtz_result = tb_probe_root(
                test_board_win.colors(Color::White).0,
                test_board_win.colors(Color::Black).0,
                test_board_win.pieces(Piece::King).0,
                test_board_win.pieces(Piece::Queen).0,
                test_board_win.pieces(Piece::Rook).0,
                test_board_win.pieces(Piece::Bishop).0,
                test_board_win.pieces(Piece::Knight).0,
                test_board_win.pieces(Piece::Pawn).0,
                0,
                0,
                test_board_win.side_to_move() == Color::White,
                &mut results as *mut _,
            );

            assert!((dtz_result & 0xFFF00000) >> 20 == dtz);
        }
        let test_board_draw = Board::from_str(test_pos_draw).unwrap();
        let wdl_draw = tb_probe_wdl(
            test_board_draw.colors(Color::White).0,
            test_board_draw.colors(Color::Black).0,
            test_board_draw.pieces(Piece::King).0,
            test_board_draw.pieces(Piece::Queen).0,
            test_board_draw.pieces(Piece::Rook).0,
            test_board_draw.pieces(Piece::Bishop).0,
            test_board_draw.pieces(Piece::Knight).0,
            test_board_draw.pieces(Piece::Pawn).0,
            0, // no ep square
            test_board_draw.side_to_move() == Color::White,
        );

        assert!(wdl_draw == 2);
        tb_free();
    }
}
