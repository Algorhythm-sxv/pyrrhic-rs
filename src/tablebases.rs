use std::{
    marker::PhantomData,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use crate::{
    engine_adapter::{EngineAdapter, Piece},
    tbprobe::{tb_free, tb_init, tb_probe_root, tb_probe_wdl},
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TBError {
    BadPath,
    InitFailed,
    AlreadyInitialized,
    NotSingleton,
    ProbeFailed,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WdlProbeResult {
    Loss,
    BlessedLoss,
    Draw,
    CursedWin,
    Win,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DtzProbeResult {
    Stalemate,
    Checkmate,
    DtzResult {
        wdl: WdlProbeResult,
        from_square: u8,
        to_square: u8,
        promotion: Piece,
        ep: bool,
        dtz: u16,
    },
}

#[derive(Clone)]
pub struct TableBases<E: EngineAdapter> {
    handle: Arc<()>,
    _engine: PhantomData<E>,
}

// guard against multiple initialization and freeing
static TB_INITIALIZED: AtomicBool = AtomicBool::new(false);

impl<E: EngineAdapter> TableBases<E> {
    pub fn new<P: AsRef<str>>(path: P) -> Result<Self, TBError> {
        if TB_INITIALIZED.load(Ordering::SeqCst) {
            return Err(TBError::AlreadyInitialized);
        }
        TB_INITIALIZED.store(true, Ordering::SeqCst);

        let init = unsafe { tb_init(path.as_ref()) };

        if init {
            Ok(Self {
                handle: Arc::new(()),
                _engine: PhantomData,
            })
        } else {
            TB_INITIALIZED.store(false, Ordering::SeqCst);
            Err(TBError::InitFailed)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn probe_wdl(
        &self,
        white: u64,
        black: u64,
        kings: u64,
        queens: u64,
        rooks: u64,
        bishops: u64,
        knights: u64,
        pawns: u64,
        ep: u32,
        turn: bool,
    ) -> Result<WdlProbeResult, TBError> {
        let result = unsafe {
            tb_probe_wdl::<E>(
                white, black, kings, queens, rooks, bishops, knights, pawns, ep, turn,
            )
        };

        match result {
            0 => Ok(WdlProbeResult::Loss),
            1 => Ok(WdlProbeResult::BlessedLoss),
            2 => Ok(WdlProbeResult::Draw),
            3 => Ok(WdlProbeResult::CursedWin),
            4 => Ok(WdlProbeResult::Win),
            _ => Err(TBError::ProbeFailed),
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn probe_root(
        &self,
        white: u64,
        black: u64,
        kings: u64,
        queens: u64,
        rooks: u64,
        bishops: u64,
        knights: u64,
        pawns: u64,
        rule50: u32,
        ep: u32,
        turn: bool,
    ) -> Result<DtzProbeResult, TBError> {
        // tb_probe_root is NOT thread safe, only allow if there is only one thread using the tablebases
        // This thread is the only one that can change the strong count from 1 to more, and will be busy
        // probing until this function returns
        if Arc::strong_count(&self.handle) > 1 {
            return Err(TBError::NotSingleton);
        }
        let result = unsafe {
            tb_probe_root::<E>(
                white,
                black,
                kings,
                queens,
                rooks,
                bishops,
                knights,
                pawns,
                rule50,
                ep,
                turn,
                std::ptr::null_mut(),
            )
        };

        match result {
            0xFFFFFFFF => Err(TBError::ProbeFailed),
            2 => Ok(DtzProbeResult::Stalemate),
            4 => Ok(DtzProbeResult::Checkmate),
            other => {
                let wdl_result = other & 0xF;
                let to_square = (other & 0x3F0) >> 4;
                let from_square = (other & 0xFC00) >> 10;
                let promotion = (other & 0x70000) >> 16;
                let ep = (other & 0x80000) >> 19;
                let dtz = (other & 0xFFF00000) >> 20;

                Ok(DtzProbeResult::DtzResult {
                    wdl: match wdl_result {
                        0 => WdlProbeResult::Loss,
                        1 => WdlProbeResult::BlessedLoss,
                        2 => WdlProbeResult::Draw,
                        3 => WdlProbeResult::CursedWin,
                        4 => WdlProbeResult::Win,
                        _ => unreachable!(),
                    },
                    from_square: from_square as u8,
                    to_square: to_square as u8,
                    promotion: match promotion {
                        1 => Piece::Queen,
                        2 => Piece::Rook,
                        3 => Piece::Bishop,
                        4 => Piece::Knight,
                        _ => Piece::Pawn,
                    },
                    ep: ep != 0,
                    dtz: dtz as u16,
                })
            }
        }
    }
}

impl<E: EngineAdapter> Drop for TableBases<E> {
    fn drop(&mut self) {
        unsafe { tb_free() };
        TB_INITIALIZED.store(false, Ordering::SeqCst);
    }
}
