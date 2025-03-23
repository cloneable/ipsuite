use core::{fmt, mem, ops};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, network_endian};

use super::ChecksumWords;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct TcpPdu {
    pub fields: TcpHeaderFields,
    pub options_payload: [u8],
}

type TcpPduWords = ChecksumWords<{ TcpHeaderFields::WORDS }, 8>;

impl TcpPdu {
    #[inline]
    pub fn from_bytes(buf: &[u8]) -> Result<&Self, TcpPduError> {
        TcpPdu::ref_from_bytes(buf)
            .map_err(zerocopy::SizeError::from)
            .map_err(Into::into)
    }

    #[inline]
    pub fn from_bytes_mut(buf: &mut [u8]) -> Result<&mut Self, TcpPduError> {
        TcpPdu::mut_from_bytes(buf)
            .map_err(zerocopy::SizeError::from)
            .map_err(Into::into)
    }

    #[inline]
    pub fn as_parts(&self) -> Result<(&TcpHeader, &[u8]), TcpPduError> {
        let len = self.fields.header_length();
        let buf = self.as_bytes();
        if len < TcpHeaderFields::SIZE {
            return Err(TcpPduError::InvalidHeaderLength);
        }
        let (header, payload) = buf
            .split_at_checked(len)
            .ok_or(TcpPduError::InvalidHeaderLength)?;

        Ok((
            TcpHeader::ref_from_bytes(header).map_err(zerocopy::SizeError::from)?,
            payload,
        ))
    }

    #[inline]
    pub fn as_mut_parts(
        &mut self,
        options: usize,
    ) -> Result<(&mut TcpHeader, &mut [u8]), TcpPduError> {
        let buf = self.as_mut_bytes();
        let (header, payload) = buf
            .split_at_mut_checked(TcpHeaderFields::SIZE.saturating_add(options))
            .ok_or(TcpPduError::InvalidHeaderLength)?;
        Ok((
            TcpHeader::mut_from_bytes(header).map_err(zerocopy::SizeError::from)?,
            payload,
        ))
    }

    #[inline]
    pub fn update_checksum(&mut self, partial: u32) -> Result<(), TcpPduError> {
        self.as_mut_words()?.update_checksum(partial);
        Ok(())
    }

    #[inline]
    pub fn verify_checksum(&self, initial: u32) -> Result<(), TcpPduError> {
        self.as_words()?
            .verify_checksum(initial)
            .map_err(|()| TcpPduError::InvalidChecksum)
    }

    fn as_words(&self) -> Result<&TcpPduWords, TcpPduError> {
        // TODO: half word at end
        TcpPduWords::ref_from_bytes(self.as_bytes())
            .map_err(zerocopy::SizeError::from)
            .map_err(Into::into)
    }

    fn as_mut_words(&mut self) -> Result<&mut TcpPduWords, TcpPduError> {
        // TODO: half word at end
        TcpPduWords::mut_from_bytes(self.as_mut_bytes())
            .map_err(zerocopy::SizeError::from)
            .map_err(Into::into)
    }
}

impl fmt::Debug for TcpPdu {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpPdu")
            .field("header", &self.fields)
            // TODO: debug print options
            .field("options_payload", &self.options_payload.len())
            .finish()
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct TcpHeader {
    pub fields: TcpHeaderFields,
    pub options: [u8],
}

impl TcpHeader {
    #[inline]
    #[must_use]
    pub const fn length(&self) -> usize {
        mem::size_of_val(&self.fields).wrapping_add(self.options.len())
    }
}

impl fmt::Debug for TcpHeader {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpHeader")
            .field("fields", &self.fields)
            // TODO: debug print options
            .field("options", &format_args!("{:x?}", &self.options))
            .finish()
    }
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct TcpHeaderFields {
    pub sport: network_endian::U16,
    pub dport: network_endian::U16,
    pub seq_num: network_endian::U32,
    pub ack_num: network_endian::U32,
    pub data_offset: u8,
    pub flags: TcpFlagSet,
    pub window: network_endian::U16,
    pub checksum: network_endian::U16,
    pub urgent_ptr: network_endian::U16,
}

impl Default for TcpHeaderFields {
    #[inline]
    fn default() -> Self {
        TcpHeaderFields {
            sport: 0.into(),
            dport: 0.into(),
            seq_num: 0.into(),
            ack_num: 0.into(),
            data_offset: 0x50,
            flags: TcpFlagSet(0),
            window: 0.into(),
            checksum: 0.into(),
            urgent_ptr: 0.into(),
        }
    }
}

impl fmt::Display for TcpHeaderFields {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP: sport={} dport={} seq={} ack={} dataofs={} flags={} window={} checksum={:04x} urgent_ptr={}",
            self.sport,
            self.dport,
            self.seq_num,
            self.ack_num,
            self.header_length(),
            self.flags,
            self.window,
            self.checksum,
            self.urgent_ptr,
        )
    }
}

impl TcpHeaderFields {
    pub const SIZE: usize = mem::size_of::<Self>();
    pub const WORDS: usize = Self::SIZE >> 1;

    #[inline]
    #[must_use]
    pub const fn data_offset(&self) -> u8 {
        (self.data_offset >> 4) & 0b1111
    }

    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "unsigned to usize")]
    pub const fn header_length(&self) -> usize {
        (self.data_offset() as usize).wrapping_mul(4)
    }
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(transparent)]
pub struct TcpFlagSet(u8);

impl TcpFlagSet {
    pub const ALL: [TcpFlag; 8] = [
        TcpFlag::CWR,
        TcpFlag::ECE,
        TcpFlag::URG,
        TcpFlag::ACK,
        TcpFlag::PSH,
        TcpFlag::RST,
        TcpFlag::SYN,
        TcpFlag::FIN,
    ];

    #[inline]
    #[must_use]
    pub const fn has(self, flag: TcpFlag) -> bool {
        self.0 & flag.bit() != 0
    }
}

impl fmt::Display for TcpFlagSet {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for flag in TcpFlagSet::ALL {
            use fmt::Write;
            if self.has(flag) {
                f.write_char(char::from(flag.letter()))?;
            } else {
                f.write_char('.')?;
            }
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TcpFlag {
    FIN = 1,
    SYN = 2,
    RST = 4,
    PSH = 8,
    ACK = 16,
    URG = 32,
    ECE = 64,
    CWR = 128,
}

impl From<TcpFlag> for TcpFlagSet {
    #[inline]
    fn from(flag: TcpFlag) -> Self {
        TcpFlagSet(flag.bit())
    }
}

impl ops::BitOr<TcpFlag> for TcpFlag {
    type Output = TcpFlagSet;

    #[inline]
    fn bitor(self, rhs: TcpFlag) -> Self::Output {
        TcpFlagSet(self.bit() | rhs.bit())
    }
}

impl TcpFlag {
    #[allow(clippy::as_conversions, reason = "repr == u8")]
    const fn bit(self) -> u8 {
        self as u8
    }

    #[inline]
    #[must_use]
    pub const fn short(self) -> &'static str {
        match self {
            Self::CWR => "CWR",
            Self::ECE => "ECE",
            Self::URG => "URG",
            Self::ACK => "ACK",
            Self::PSH => "PSH",
            Self::RST => "RST",
            Self::SYN => "SYN",
            Self::FIN => "FIN",
        }
    }

    #[inline]
    #[must_use]
    pub const fn letter(self) -> u8 {
        match self {
            Self::CWR => b'C',
            Self::ECE => b'E',
            Self::URG => b'U',
            Self::ACK => b'A',
            Self::PSH => b'P',
            Self::RST => b'R',
            Self::SYN => b'S',
            Self::FIN => b'F',
        }
    }
}

impl fmt::Display for TcpFlag {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.short())
    }
}

#[derive(
    Copy,
    Clone,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[repr(transparent)]
pub struct TcpOptionKind(pub u8);

impl TcpOptionKind {
    pub const EOL: Self = Self(0);
    pub const NOP: Self = Self(1);
    pub const MSS: Self = Self(2);
    pub const WINDOW_SCALE: Self = Self(3);
    pub const SACK_PERM: Self = Self(4);
    pub const SACK: Self = Self(5);
    pub const TIMESTAMP: Self = Self(8);
    pub const USER_TIMEOUT: Self = Self(28);
    pub const TCP_AUTH: Self = Self(29);
    pub const MULTIPATH: Self = Self(30);

    #[inline]
    #[must_use]
    pub const fn syn_only(self) -> bool {
        matches!(self, Self::MSS | Self::WINDOW_SCALE | Self::SACK_PERM)
    }

    #[inline]
    #[must_use]
    pub const fn has_length(self) -> bool {
        !matches!(self, Self::EOL | Self::NOP)
    }

    fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::EOL => "EOL",
            Self::NOP => "NOP",
            Self::MSS => "MSS",
            Self::WINDOW_SCALE => "WINDOW_SCALE",
            Self::SACK_PERM => "SACK_PERM",
            Self::SACK => "SACK",
            Self::TIMESTAMP => "TIMESTAMP",
            Self::USER_TIMEOUT => "USER_TIMEOUT",
            Self::TCP_AUTH => "TCP_AUTH",
            Self::MULTIPATH => "MULTIPATH",
            _ => return None,
        })
    }
}

impl fmt::Debug for TcpOptionKind {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TcpOptionKind")
            .field(&format_args!("{self}"))
            .finish()
    }
}

impl fmt::Display for TcpOptionKind {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "{}", self.0),
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct TcpOption {
    kind: TcpOptionKind,
    length: u8,
    data: [u8],
}

impl TcpOption {
    #[inline]
    pub fn parse(buf: &[u8]) -> Result<&TcpOption, zerocopy::SizeError<&[u8], TcpOption>> {
        TcpOption::ref_from_prefix(buf)
            .map_err(zerocopy::SizeError::from)
            .map(|r| r.0)
    }
}

impl fmt::Debug for TcpOption {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpOption")
            .field("kind", &self.kind)
            .field("length", &self.length)
            .field("data", &format_args!("{:x?}", &self.data))
            .finish()
    }
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct MaximumSegmentSizeTcpOption {
    kind: TcpOptionKind,
    length: u8,
    value: network_endian::U16,
}

#[derive(Copy, Clone, Debug)]
pub enum TcpOptionEnum {
    MaximumSegmentSize {
        kind: TcpOptionKind,
        length: u8,
        value: network_endian::U16,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TcpPduError {
    InvalidHeaderLength,
    InvalidChecksum,
    BufferTooShort,
}

// TODO: sealed trait for T
impl<T: ?Sized> From<zerocopy::SizeError<&mut [u8], T>> for TcpPduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&mut [u8], T>) -> Self {
        TcpPduError::BufferTooShort
    }
}

impl<T: ?Sized> From<zerocopy::SizeError<&[u8], T>> for TcpPduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&[u8], T>) -> Self {
        TcpPduError::BufferTooShort
    }
}
