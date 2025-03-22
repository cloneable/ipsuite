use core::{fmt, mem};

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, SizeError, Unaligned, network_endian,
};

use super::ChecksumWords;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UdpPduError {
    InvalidChecksum,
    BufferTooShort,
}

impl From<zerocopy::SizeError<&[u8], UdpPdu>> for UdpPduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&[u8], UdpPdu>) -> Self {
        UdpPduError::BufferTooShort
    }
}

impl From<zerocopy::SizeError<&mut [u8], UdpPdu>> for UdpPduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&mut [u8], UdpPdu>) -> Self {
        UdpPduError::BufferTooShort
    }
}

impl From<zerocopy::SizeError<&[u8], UdpPduWords>> for UdpPduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&[u8], UdpPduWords>) -> Self {
        UdpPduError::BufferTooShort
    }
}

impl From<zerocopy::SizeError<&mut [u8], UdpPduWords>> for UdpPduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&mut [u8], UdpPduWords>) -> Self {
        UdpPduError::BufferTooShort
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct UdpPdu {
    pub header: UdpHeader,
    pub payload: [u8],
}

type UdpPduWords = ChecksumWords<{ UdpHeader::WORDS }, 3>;

impl UdpPdu {
    #[must_use]
    #[inline]
    pub const fn length(&self) -> usize {
        mem::size_of_val(&self.header).wrapping_add(self.payload.len())
    }

    #[inline]
    pub fn update_checksum(&mut self, partial: u32) -> Result<(), UdpPduError> {
        self.as_mut_words()?.update_checksum_nonzero(partial);
        Ok(())
    }

    #[inline]
    pub fn verify_checksum(&self, partial: u32) -> Result<(), UdpPduError> {
        self.as_words()?
            .verify_checksum(partial)
            .map_err(|()| UdpPduError::InvalidChecksum)
    }

    #[inline]
    fn as_words(&self) -> Result<&UdpPduWords, UdpPduError> {
        // TODO: half word at end
        UdpPduWords::ref_from_bytes(self.as_bytes())
            .map_err(SizeError::from)
            .map_err(Into::into)
    }

    #[inline]
    fn as_mut_words(&mut self) -> Result<&mut UdpPduWords, UdpPduError> {
        // TODO: half word at end
        UdpPduWords::mut_from_bytes(self.as_mut_bytes())
            .map_err(SizeError::from)
            .map_err(Into::into)
    }

    #[inline]
    pub fn from_bytes(buf: &[u8]) -> Result<&Self, UdpPduError> {
        UdpPdu::ref_from_bytes(buf)
            .map_err(SizeError::from)
            .map_err(Into::into)
    }

    #[inline]
    pub fn from_bytes_mut(buf: &mut [u8]) -> Result<&mut Self, UdpPduError> {
        UdpPdu::mut_from_bytes(buf)
            .map_err(SizeError::from)
            .map_err(Into::into)
    }

    #[inline]
    pub fn as_parts(&self) -> Result<(&UdpHeader, &[u8]), UdpPduError> {
        Ok((&self.header, &self.payload))
    }

    #[inline]
    pub fn as_mut_parts(&mut self) -> Result<(&mut UdpHeader, &mut [u8]), UdpPduError> {
        Ok((&mut self.header, &mut self.payload))
    }
}

impl fmt::Debug for UdpPdu {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpPdu")
            .field("header", &self.header)
            // TODO: debug print options
            .field("payload", &self.payload.len())
            .finish()
    }
}

#[derive(Copy, Clone, Debug, Default, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct UdpHeader {
    pub src_port: network_endian::U16,
    pub dst_port: network_endian::U16,
    pub length: network_endian::U16,
    pub checksum: network_endian::U16,
}

impl UdpHeader {
    pub const SIZE: usize = mem::size_of::<Self>();
    pub const WORDS: usize = Self::SIZE >> 1;
}

impl fmt::Display for UdpHeader {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "src={} dst={} len={} cksum={:04x}",
            self.src_port, self.dst_port, self.length, self.checksum,
        )
    }
}
