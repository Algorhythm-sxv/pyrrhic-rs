#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Color {
    Black = 0,
    White = 1,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Piece {
    Pawn = 0,
    Knight = 1,
    Bishop = 2,
    Rook = 3,
    Queen = 4,
    King = 5,
}

pub trait EngineAdapter: Clone {
    fn pawn_attacks(color: Color, square: u64) -> u64;
    fn knight_attacks(square: u64) -> u64;
    fn bishop_attacks(square: u64, occupied: u64) -> u64;
    fn rook_attacks(square: u64, occupied: u64) -> u64;
    fn queen_attacks(square: u64, occupied: u64) -> u64;
    fn king_attacks(square: u64) -> u64;
}
