use core::{fmt, mem};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, network_endian};

use super::ChecksumWords;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct Ipv4Pdu {
    pub fields: Ipv4HeaderFields,
    pub options_payload: [u8],
}

impl Ipv4Pdu {
    #[inline]
    pub fn from_bytes(buf: &[u8]) -> Result<&Self, Ipv4PduError> {
        Ipv4Pdu::ref_from_bytes(buf)
            .map_err(zerocopy::SizeError::from)
            .map_err(Into::into)
    }

    #[inline]
    pub fn from_bytes_mut(buf: &mut [u8]) -> Result<&mut Self, Ipv4PduError> {
        Ipv4Pdu::mut_from_bytes(buf)
            .map_err(zerocopy::SizeError::from)
            .map_err(Into::into)
    }

    #[inline]
    pub fn as_parts(&self) -> Result<(&Ipv4Header, &[u8]), Ipv4PduError> {
        let len = self.fields.header_length();
        let buf = self.as_bytes();
        if len < Ipv4HeaderFields::SIZE {
            return Err(Ipv4PduError::InvalidHeaderLength);
        }
        let (header, payload) = buf
            .split_at_checked(len)
            .ok_or(Ipv4PduError::InvalidHeaderLength)?;

        Ok((
            Ipv4Header::ref_from_bytes(header).map_err(zerocopy::SizeError::from)?,
            payload,
        ))
    }

    // XXX: split again?
    #[inline]
    pub fn as_mut_parts(
        &mut self,
        options: usize,
    ) -> Result<(&mut Ipv4Header, &mut [u8]), Ipv4PduError> {
        let buf = self.as_mut_bytes();
        let (header, payload) = buf
            .split_at_mut_checked(Ipv4HeaderFields::SIZE.saturating_add(options))
            .ok_or(Ipv4PduError::InvalidHeaderLength)?;
        Ok((
            Ipv4Header::mut_from_bytes(header).map_err(zerocopy::SizeError::from)?,
            payload,
        ))
    }
}

impl fmt::Debug for Ipv4Pdu {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipv4Pdu")
            .field("fields", &self.fields)
            // TODO: debug print options
            .field("options_payload", &self.options_payload.len())
            .finish()
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct Ipv4Header {
    pub fields: Ipv4HeaderFields,
    pub options: [u8],
}

impl Ipv4Header {
    #[inline]
    #[must_use]
    pub const fn length(&self) -> usize {
        mem::size_of_val(&self.fields).wrapping_add(self.options.len())
    }

    #[inline]
    pub fn update_checksum(&mut self) -> Result<(), Ipv4PduError> {
        self.as_mut_words()?.update_checksum(0);
        Ok(())
    }

    #[inline]
    pub fn verify_checksum(&self) -> Result<(), Ipv4PduError> {
        self.as_words()?
            .verify_checksum(0)
            .map_err(|()| Ipv4PduError::InvalidChecksum)
    }

    #[inline]
    pub fn pseudo_header(&self) -> Result<&Ipv4PseudoHeader, Ipv4PduError> {
        // TODO: half word at end
        Ipv4PseudoHeader::ref_from_bytes(self.as_bytes())
            .map_err(zerocopy::SizeError::from)
            .map_err(Into::into)
    }

    fn as_words(&self) -> Result<&Ipv4HeaderWords, Ipv4PduError> {
        // TODO: half word at end
        Ipv4HeaderWords::ref_from_bytes(self.as_bytes())
            .map_err(zerocopy::SizeError::from)
            .map_err(Into::into)
    }

    fn as_mut_words(&mut self) -> Result<&mut Ipv4HeaderWords, Ipv4PduError> {
        // TODO: half word at end
        Ipv4HeaderWords::mut_from_bytes(self.as_mut_bytes())
            .map_err(zerocopy::SizeError::from)
            .map_err(Into::into)
    }
}

impl fmt::Debug for Ipv4Header {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipv4Header")
            .field("fields", &self.fields)
            // TODO: debug print options
            .field("options", &format_args!("{:x?}", &self.options))
            .finish()
    }
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct Ipv4HeaderFields {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: network_endian::U16,
    pub identification: network_endian::U16,
    pub fragmentation: Fragmentation,
    pub ttl: u8,
    pub protocol: InetProtocol,
    pub checksum: network_endian::U16,
    pub saddr: Ipv4Address,
    pub daddr: Ipv4Address,
}

impl Default for Ipv4HeaderFields {
    #[inline]
    fn default() -> Self {
        Ipv4HeaderFields {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: 20.into(),
            identification: 0.into(),
            fragmentation: Fragmentation::default(),
            ttl: 255,
            protocol: InetProtocol::TCP,
            checksum: 0.into(),
            saddr: Ipv4Address::UNSPECIFIED,
            daddr: Ipv4Address::UNSPECIFIED,
        }
    }
}

impl fmt::Display for Ipv4HeaderFields {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv4: len={} id={} frag={}/{} ttl={} protocol={} checksum={:04x} saddr={} daddr={}",
            self.total_length,
            self.identification,
            self.fragmentation.flags(),
            self.fragmentation.offset(),
            self.ttl,
            self.protocol,
            self.checksum,
            self.saddr,
            self.daddr,
        )
    }
}

impl Ipv4HeaderFields {
    pub const SIZE: usize = mem::size_of::<Self>();
    pub const WORDS: usize = Self::SIZE >> 1;

    #[inline]
    pub const fn set_version(&mut self, version: u8) {
        self.version_ihl = (self.version_ihl & 0b0000_1111) | ((version & 0b1111) << 4);
    }

    #[inline]
    pub const fn set_ihl(&mut self, ihl: u8) {
        self.version_ihl = (self.version_ihl & 0b1111_0000) | (ihl & 0b1111);
    }

    #[inline]
    #[must_use]
    pub const fn version(&self) -> u8 {
        (self.version_ihl >> 4) & 0b1111
    }

    #[inline]
    #[must_use]
    pub const fn ihl(&self) -> u8 {
        self.version_ihl & 0b1111
    }

    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "unsigned to usize")]
    pub const fn header_length(&self) -> usize {
        (self.ihl() as usize).wrapping_mul(4)
    }

    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "unsigned to usize")]
    pub const fn packet_length(&self) -> usize {
        self.total_length.get() as usize
    }
}

#[derive(
    Copy,
    Clone,
    Debug,
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
pub struct Ipv4Address(pub [u8; 4]);

impl Ipv4Address {
    pub const UNSPECIFIED: Self = Self([0, 0, 0, 0]);
}

impl fmt::Display for Ipv4Address {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

#[derive(
    Copy,
    Clone,
    Debug,
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
pub struct InetProtocol(pub u8);

impl InetProtocol {
    pub const ICMP: Self = Self(1);
    pub const IGMP: Self = Self(2);
    pub const TCP: Self = Self(6);
    pub const UDP: Self = Self(17);
    pub const ENCAP: Self = Self(41);
    pub const OSPF: Self = Self(89);
    pub const SCTP: Self = Self(132);

    #[inline]
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::ICMP => "ICMP",
            Self::IGMP => "IGMP",
            Self::TCP => "TCP",
            Self::UDP => "UDP",
            Self::ENCAP => "ENCAP",
            Self::OSPF => "OSPF",
            Self::SCTP => "SCTP",
            _ => return None,
        })
    }
}

impl fmt::Display for InetProtocol {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name() {
            f.write_str(name)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

#[derive(
    Copy,
    Clone,
    Debug,
    Default,
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
pub struct Fragmentation(pub network_endian::U16);

impl Fragmentation {
    #[inline]
    #[must_use]
    pub const fn flags(self) -> u16 {
        self.0.get() >> 13
    }

    #[inline]
    #[must_use]
    pub const fn dont_fragment(self) -> bool {
        self.flags() & 0b010 != 0
    }

    #[inline]
    #[must_use]
    pub const fn more_fragments(self) -> bool {
        self.flags() & 0b001 != 0
    }

    #[inline]
    #[must_use]
    #[allow(clippy::as_conversions, reason = "unsigned to usize")]
    pub const fn offset(self) -> usize {
        (self.0.get() & 0b1_1111_1111_1111) as usize
    }
}

type Ipv4HeaderWords = ChecksumWords<{ Ipv4HeaderFields::WORDS }, 5>;

// TODO: native byteorder
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct Ipv4PseudoHeader {
    version_ihl_dscp_ecn: network_endian::U16,
    total_length: network_endian::U16,
    _identification: network_endian::U16,
    _fragmentation: Fragmentation,
    ttl_protocol: network_endian::U16,
    _checksum: network_endian::U16,
    saddr: [network_endian::U16; 2],
    daddr: [network_endian::U16; 2],
    _options: [u8],
}

impl Ipv4PseudoHeader {
    #[allow(clippy::as_conversions, reason = "u16 to u32")]
    #[inline]
    #[must_use]
    pub const fn checksum(&self) -> u32 {
        let mut cs = 0u32;
        cs = cs.wrapping_add(self.saddr[0].get() as u32);
        cs = cs.wrapping_add(self.saddr[1].get() as u32);
        cs = cs.wrapping_add(self.daddr[0].get() as u32);
        cs = cs.wrapping_add(self.daddr[1].get() as u32);
        cs = cs.wrapping_add(self.protocol() as u32);
        cs.wrapping_add(self.payload_length() as u32)
    }

    const fn protocol(&self) -> u16 {
        self.ttl_protocol.get() & 0xff
    }

    const fn header_length(&self) -> u16 {
        ((self.version_ihl_dscp_ecn.get() & 0x0F00) >> 8).wrapping_mul(4)
    }

    const fn total_length(&self) -> u16 {
        self.total_length.get()
    }

    const fn payload_length(&self) -> u16 {
        self.total_length().wrapping_sub(self.header_length())
    }
}

impl fmt::Debug for Ipv4PseudoHeader {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ipv4PseudoHeader")
            .field("saddr", &self.saddr)
            .field("daddr", &self.daddr)
            .field("proto", &self.protocol())
            .field("len", &self.payload_length())
            .finish()
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Ipv4PduError {
    InvalidHeaderLength,
    InvalidChecksum,
    BufferTooShort,
}

impl From<zerocopy::SizeError<&[u8], Ipv4Pdu>> for Ipv4PduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&[u8], Ipv4Pdu>) -> Self {
        Ipv4PduError::BufferTooShort
    }
}

impl From<zerocopy::SizeError<&mut [u8], Ipv4Pdu>> for Ipv4PduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&mut [u8], Ipv4Pdu>) -> Self {
        Ipv4PduError::BufferTooShort
    }
}

impl From<zerocopy::SizeError<&[u8], Ipv4Header>> for Ipv4PduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&[u8], Ipv4Header>) -> Self {
        Ipv4PduError::BufferTooShort
    }
}

impl From<zerocopy::SizeError<&mut [u8], Ipv4Header>> for Ipv4PduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&mut [u8], Ipv4Header>) -> Self {
        Ipv4PduError::BufferTooShort
    }
}

impl From<zerocopy::SizeError<&[u8], Ipv4HeaderWords>> for Ipv4PduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&[u8], Ipv4HeaderWords>) -> Self {
        Ipv4PduError::BufferTooShort
    }
}

impl From<zerocopy::SizeError<&mut [u8], Ipv4HeaderWords>> for Ipv4PduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&mut [u8], Ipv4HeaderWords>) -> Self {
        Ipv4PduError::BufferTooShort
    }
}

impl From<zerocopy::SizeError<&[u8], Ipv4PseudoHeader>> for Ipv4PduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&[u8], Ipv4PseudoHeader>) -> Self {
        Ipv4PduError::BufferTooShort
    }
}
