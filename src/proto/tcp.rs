use core::{fmt, iter::FusedIterator, mem, ops};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, network_endian};

use crate::proto::Checksum;

use super::{ChecksumWords, DataDebug};

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
        let buf = self.as_bytes();
        let header_len = self.fields.header_length();
        let (header, payload) = buf
            .split_at_checked(header_len)
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
        let header_len = TcpHeaderFields::SIZE.saturating_add(options);
        let (header, payload) = buf
            .split_at_mut_checked(header_len)
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
            .field("options_payload", &DataDebug(&self.options_payload))
            .finish()
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct TcpHeader {
    pub fields: TcpHeaderFields,
    pub options: TcpOptions,
}

impl TcpHeader {
    #[inline]
    #[must_use]
    pub const fn length(&self) -> usize {
        mem::size_of_val(&self.fields).wrapping_add(self.options.0.len())
    }
}

impl fmt::Debug for TcpHeader {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpHeader")
            .field("fields", &self.fields)
            // TODO: debug print options
            .field("options", &&self.options)
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
    pub checksum: Checksum,
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
            checksum: Checksum::default(),
            urgent_ptr: 0.into(),
        }
    }
}

impl fmt::Display for TcpHeaderFields {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP: sport={} dport={} seq={} ack={} dataofs={} flags={} window={} checksum={} \
             urgent_ptr={}",
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

#[derive(Copy, Clone, Debug)]
#[non_exhaustive]
pub enum TcpOption<'a> {
    Nop,
    Mss(MaximumSegmentSize),
    WindowScale(WindowScale),
    SackPerm,
    Sack(&'a SelectiveAck),
    Timestamp(Timestamp),
    Md5(Md5Signature),
    UserTimeout(UserTimeout),
    TcpAuth(&'a TcpAuth),
    Multipath(&'a Multipath),
    TcpFastOpen(&'a TcpFastOpen),
    Unknown { kind: TcpOptionKind, data: &'a [u8] },
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct TcpOptions([u8]);

impl TcpOptions {
    #[inline]
    #[must_use]
    pub fn length(&self) -> usize {
        self.0.len()
    }

    #[inline]
    #[must_use]
    pub fn iter(&self) -> TcpOptionsIter<'_> {
        TcpOptionsIter {
            buf: &self.0,
            fused: false,
        }
    }
}

impl<'a> IntoIterator for &'a TcpOptions {
    type Item = Result<TcpOption<'a>, TcpPduError>;
    type IntoIter = TcpOptionsIter<'a>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[derive(Debug)]
pub struct TcpOptionsIter<'a> {
    buf: &'a [u8],
    fused: bool,
}

impl<'a> TcpOptionsIter<'a> {
    fn parse_next(&mut self) -> Result<Option<TcpOption<'a>>, TcpPduError> {
        let Some((&first, rest)) = self.buf.split_first() else {
            return Ok(None);
        };
        let kind = TcpOptionKind(first);
        match kind {
            TcpOptionKind::EOL => Ok(None), // TODO: check trailing data?
            TcpOptionKind::NOP => {
                self.buf = rest;
                Ok(Some(TcpOption::Nop))
            }
            _ => {
                // TODO: bypass header, read length directly
                let (header, remainder) = TcpOptionHeader::ref_from_prefix(self.buf)
                    .map_err(zerocopy::SizeError::from)?;
                let body_len = usize::from(header.length)
                    .checked_sub(mem::size_of::<TcpOptionHeader>())
                    .ok_or(TcpPduError::InvalidOptionLength)?;
                let (opt_buf, remainder) = remainder
                    .split_at_checked(body_len)
                    .ok_or(TcpPduError::BufferTooShort)?;
                let opt = match header.kind {
                    TcpOptionKind::MSS => {
                        TcpOption::Mss(MaximumSegmentSize::read_from_bytes(opt_buf)?)
                    }
                    TcpOptionKind::WINDOW_SCALE => {
                        TcpOption::WindowScale(WindowScale::read_from_bytes(opt_buf)?)
                    }
                    TcpOptionKind::SACK_PERM => {
                        if !opt_buf.is_empty() {
                            return Err(TcpPduError::InvalidOptionLength);
                        }
                        TcpOption::SackPerm
                    }
                    TcpOptionKind::SACK => {
                        // TODO: lengths, ref_from_bytes_with_elems?
                        TcpOption::Sack(
                            SelectiveAck::ref_from_bytes(opt_buf)
                                .map_err(zerocopy::SizeError::from)?,
                        )
                    }
                    TcpOptionKind::TIMESTAMP => {
                        TcpOption::Timestamp(Timestamp::read_from_bytes(opt_buf)?)
                    }
                    TcpOptionKind::MD5 => TcpOption::Md5(Md5Signature::read_from_bytes(opt_buf)?),
                    TcpOptionKind::USER_TIMEOUT => {
                        TcpOption::UserTimeout(UserTimeout::read_from_bytes(opt_buf)?)
                    }
                    TcpOptionKind::TCP_AUTH => TcpOption::TcpAuth(
                        TcpAuth::ref_from_bytes(opt_buf).map_err(zerocopy::SizeError::from)?,
                    ),
                    TcpOptionKind::MULTIPATH => TcpOption::Multipath(
                        Multipath::ref_from_bytes(opt_buf).map_err(zerocopy::SizeError::from)?,
                    ),
                    TcpOptionKind::TFO => TcpOption::TcpFastOpen(
                        TcpFastOpen::ref_from_bytes(opt_buf).map_err(zerocopy::SizeError::from)?,
                    ),
                    _ => TcpOption::Unknown {
                        kind: header.kind,
                        data: opt_buf,
                    },
                };
                self.buf = remainder;
                Ok(Some(opt))
            }
        }
    }
}

impl<'a> Iterator for TcpOptionsIter<'a> {
    type Item = Result<TcpOption<'a>, TcpPduError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.fused {
            return None;
        }
        match self.parse_next() {
            Ok(Some(opt)) => Some(Ok(opt)),
            Ok(None) => {
                self.fused = true;
                None
            }
            Err(e) => {
                self.fused = true;
                Some(Err(e))
            }
        }
    }
}

impl FusedIterator for TcpOptionsIter<'_> {}

impl fmt::Debug for TcpOptions {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TcpOptions").finish_non_exhaustive()
    }
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct TcpOptionHeader {
    kind: TcpOptionKind,
    length: u8,
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
    pub const MD5: Self = Self(19);
    pub const USER_TIMEOUT: Self = Self(28);
    pub const TCP_AUTH: Self = Self(29);
    pub const MULTIPATH: Self = Self(30);
    pub const TFO: Self = Self(34);

    #[inline]
    #[must_use]
    pub const fn syn_only(self) -> bool {
        matches!(
            self,
            Self::MSS | Self::WINDOW_SCALE | Self::SACK_PERM | Self::TFO
        )
    }

    #[inline]
    #[must_use]
    pub const fn has_length(self) -> bool {
        !matches!(self, Self::EOL | Self::NOP)
    }

    #[inline]
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::EOL => "EOL",
            Self::NOP => "NOP",
            Self::MSS => "MSS",
            Self::WINDOW_SCALE => "WINDOW_SCALE",
            Self::SACK_PERM => "SACK_PERM",
            Self::SACK => "SACK",
            Self::TIMESTAMP => "TIMESTAMP",
            Self::MD5 => "MD5",
            Self::USER_TIMEOUT => "USER_TIMEOUT",
            Self::TCP_AUTH => "TCP_AUTH",
            Self::MULTIPATH => "MULTIPATH",
            Self::TFO => "TFO",
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

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct MaximumSegmentSize(pub network_endian::U16);

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(transparent)]
pub struct WindowScale(pub u8);

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct SelectiveAck(pub [SelectiveAckRange]);

impl fmt::Debug for SelectiveAck {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SelectiveAck").field(&&self.0).finish()
    }
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct SelectiveAckRange {
    pub begin: network_endian::U32,
    pub end: network_endian::U32,
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct Timestamp {
    pub value: network_endian::U32,
    pub echo_reply: network_endian::U32,
}

#[derive(Copy, Clone, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct Md5Signature {
    pub digest: [u8; 16],
}

impl fmt::Debug for Md5Signature {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Md5Signature")
            .field("digest", &format_args!("{:02x?}", &self.digest))
            .finish()
    }
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct UserTimeout {
    pub granularity_timeout: network_endian::U16,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct TcpAuth {
    pub key_id: u8,
    pub next_key_id: u8,
    pub mac: [u8],
}

impl fmt::Debug for TcpAuth {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpAuth")
            .field("key_id", &self.key_id)
            .field("next_key_id", &self.next_key_id)
            .field("mac", &format_args!("{:02x?}", &self.mac))
            .finish()
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct Multipath {
    pub subtype_flags: u8,
    pub data: [u8],
}

impl Multipath {
    #[inline]
    #[must_use]
    pub const fn subtype(&self) -> MultipathSubtype {
        MultipathSubtype((self.subtype_flags >> 4) & 0b1111)
    }

    #[inline]
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.subtype_flags & 0b1111
    }
}

impl fmt::Debug for Multipath {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Multipath")
            .field("subtype", &self.subtype())
            .field("flags", &self.flags())
            .field("data", &format_args!("{:02x?}", &self.data))
            .finish()
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
pub struct MultipathSubtype(pub u8);

impl MultipathSubtype {
    pub const MP_CAPABLE: Self = Self(0x0);
    pub const MP_JOIN: Self = Self(0x1);
    pub const DSS: Self = Self(0x2);
    pub const ADD_ADDR: Self = Self(0x3);
    pub const REMOVE_ADDR: Self = Self(0x4);
    pub const MP_PRIO: Self = Self(0x5);
    pub const MP_FAIL: Self = Self(0x6);
    pub const MP_FASTCLOSE: Self = Self(0x7);
    pub const MP_TCPRST: Self = Self(0x8);

    #[inline]
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::MP_CAPABLE => "MP_CAPABLE",
            Self::MP_JOIN => "MP_JOIN",
            Self::DSS => "DSS",
            Self::ADD_ADDR => "ADD_ADDR",
            Self::REMOVE_ADDR => "REMOVE_ADDR",
            Self::MP_PRIO => "MP_PRIO",
            Self::MP_FAIL => "MP_FAIL",
            Self::MP_FASTCLOSE => "MP_FASTCLOSE",
            Self::MP_TCPRST => "MP_TCPRST",
            _ => return None,
        })
    }
}

impl fmt::Debug for MultipathSubtype {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MultipathSubtype")
            .field(&format_args!("{self}"))
            .finish()
    }
}

impl fmt::Display for MultipathSubtype {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "0x{:x}", self.0),
        }
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct TcpFastOpen {
    pub cookie: [u8],
}

impl TcpFastOpen {
    /// `true` when the option carries no cookie, signalling a request for the peer to mint one.
    #[inline]
    #[must_use]
    pub const fn is_request(&self) -> bool {
        self.cookie.is_empty()
    }
}

impl fmt::Debug for TcpFastOpen {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpFastOpen")
            .field("cookie", &format_args!("{:02x?}", &self.cookie))
            .finish()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TcpPduError {
    InvalidHeaderLength,
    InvalidChecksum,
    BufferTooShort,
    InvalidOptionLength,
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
