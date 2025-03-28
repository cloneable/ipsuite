use core::fmt;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, network_endian};

use crate::proto::DataDebug;
use crate::proto::ethernet::MacAddress;
use crate::proto::ipv4::Ipv4Address;

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct ArpPdu {
    pub header: ArpHeader,
    pub addresses: [u8],
}

impl fmt::Debug for ArpPdu {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArpPdu")
            .field("header", &self.header)
            .field("addresses", &DataDebug(&self.addresses))
            .finish()
    }
}

impl ArpPdu {
    #[inline]
    pub fn from_bytes(buf: &[u8]) -> Result<&Self, ArpPduError> {
        ArpPdu::ref_from_bytes(buf)
            .map_err(zerocopy::SizeError::from)
            .map_err(Into::into)
    }
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct ArpHeader {
    pub htype: HardwareType,
    pub ptype: ProtocolType,
    pub hlen: u8,
    pub plen: u8,
    pub oper: ArpOperation,
}

impl ArpHeader {
    #[inline]
    pub const fn payload_length(self) -> usize {
        (self.hlen as usize)
            .wrapping_shl(1)
            .wrapping_add((self.plen as usize).wrapping_shl(1))
    }
}

impl fmt::Display for ArpHeader {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ARP: htype={} ptype={} hlen={} plen={} oper={}",
            self.htype, self.ptype, self.hlen, self.plen, self.oper
        )
    }
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct ArpEthernetIPv4Addresses {
    pub sender: ArpEthernetIPv4,
    pub target: ArpEthernetIPv4,
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct ArpEthernetIPv4 {
    pub mac: MacAddress,
    pub ipv4: Ipv4Address,
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
#[repr(C, packed)]
pub struct HardwareType(pub network_endian::U16);

impl HardwareType {
    const ETHERNET: Self = Self::new(1);

    const fn new(type_: u16) -> Self {
        HardwareType(network_endian::U16::new(type_))
    }

    #[inline]
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::ETHERNET => "Ethernet",
            _ => return None,
        })
    }
}

impl fmt::Display for HardwareType {
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
#[repr(C, packed)]
pub struct ProtocolType(pub network_endian::U16);

impl ProtocolType {
    const IPV4: Self = Self::new(0x0800);

    const fn new(type_: u16) -> Self {
        ProtocolType(network_endian::U16::new(type_))
    }

    #[inline]
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::IPV4 => "IPv4",
            _ => return None,
        })
    }
}

impl fmt::Display for ProtocolType {
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
#[repr(C, packed)]
pub struct ArpOperation(pub network_endian::U16);

impl ArpOperation {
    const REQUEST: Self = Self::new(1);
    const REPLY: Self = Self::new(2);

    const fn new(type_: u16) -> Self {
        ArpOperation(network_endian::U16::new(type_))
    }

    #[inline]
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::REQUEST => "Request",
            Self::REPLY => "Reply",
            _ => return None,
        })
    }
}

impl fmt::Display for ArpOperation {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name() {
            f.write_str(name)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ArpPduError {
    InvalidHeaderLength,
    InvalidChecksum,
    BufferTooShort,
}

// TODO: sealed trait for T
impl<T: ?Sized> From<zerocopy::SizeError<&mut [u8], T>> for ArpPduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&mut [u8], T>) -> Self {
        ArpPduError::BufferTooShort
    }
}

impl<T: ?Sized> From<zerocopy::SizeError<&[u8], T>> for ArpPduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&[u8], T>) -> Self {
        ArpPduError::BufferTooShort
    }
}
