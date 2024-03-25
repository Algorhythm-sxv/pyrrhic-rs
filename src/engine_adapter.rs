#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Color {
    Black = 0,
    White = 1,
}

pub trait EngineAdapter {
    fn pawn_attacks(color: Color, square: u64) -> u64;
    fn knight_attacks(square: u64) -> u64;
    fn bishop_attacks(square: u64, occupied: u64) -> u64;
    fn rook_attacks(square: u64, occupied: u64) -> u64;
    fn queen_attacks(square: u64, occupied: u64) -> u64;
    fn king_attacks(square: u64) -> u64;
}
