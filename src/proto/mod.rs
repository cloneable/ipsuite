pub mod ethernet;
pub mod ipv4;
pub mod tcp;
pub mod udp;

use core::fmt;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, network_endian};

pub struct DataDebug<'a>(&'a [u8]);

impl fmt::Debug for DataDebug<'_> {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TOOD: include (truncated) slice?
        f.debug_tuple("Data").field(&self.0.len()).finish()
    }
}

// TODO: native byteorder
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
struct ChecksumWords<const WORDS: usize, const CKSUM: usize> {
    fixed: [network_endian::U16; WORDS],
    variable: [network_endian::U16],
}

impl<const WORDS: usize, const CKSUM: usize> ChecksumWords<WORDS, CKSUM> {
    #[allow(clippy::indexing_slicing, reason = "checked index from const generic")]
    fn update_checksum(&mut self, initial: u32) {
        self.fixed[CKSUM] = 0.into();
        let cs = self.checksum(initial);
        self.fixed[CKSUM] = cs.into();
    }

    #[allow(clippy::indexing_slicing, reason = "checked index from const generic")]
    fn update_checksum_nonzero(&mut self, initial: u32) {
        self.fixed[CKSUM] = 0.into();
        let cs = self.checksum(initial);
        let cs = if cs == 0 { !cs } else { cs };
        self.fixed[CKSUM] = cs.into();
    }

    fn verify_checksum(&self, initial: u32) -> Result<(), ()> {
        if self.checksum(initial) == 0 {
            Ok(())
        } else {
            Err(())
        }
    }

    #[allow(clippy::as_conversions, reason = "u16 to u32")]
    #[allow(clippy::cast_possible_truncation, reason = "truncate checksum")]
    fn checksum(&self, initial: u32) -> u16 {
        let mut cs = initial;
        for word in self.fixed {
            cs = cs.wrapping_add(word.get() as u32);
        }
        for word in self.variable.iter() {
            cs = cs.wrapping_add(word.get() as u32);
        }
        !(cs as u16).wrapping_add(cs.wrapping_shr(16) as u16)
    }
}
