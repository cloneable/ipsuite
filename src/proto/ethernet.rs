use core::{fmt, mem};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, network_endian};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct EthernetPdu {
    pub header: EthernetHeader,
    pub payload: [u8],
}

impl EthernetPdu {
    #[inline]
    pub fn from_bytes(buf: &[u8]) -> Result<&Self, EthernetPduError> {
        EthernetPdu::ref_from_bytes(buf)
            .map_err(zerocopy::SizeError::from)
            .map_err(Into::into)
    }

    #[inline]
    pub fn from_bytes_mut(buf: &mut [u8]) -> Result<&mut Self, EthernetPduError> {
        EthernetPdu::mut_from_bytes(buf)
            .map_err(zerocopy::SizeError::from)
            .map_err(Into::into)
    }

    #[inline]
    pub fn as_parts(&self) -> Result<(&EthernetHeader, &[u8]), EthernetPduError> {
        Ok((&self.header, &self.payload))
    }

    #[inline]
    pub fn as_mut_parts(&mut self) -> Result<(&mut EthernetHeader, &mut [u8]), EthernetPduError> {
        Ok((&mut self.header, &mut self.payload))
    }
}

impl fmt::Debug for EthernetPdu {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthernetPdu")
            .field("header", &self.header)
            .field("payload", &self.payload.len())
            .finish()
    }
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C, packed)]
pub struct EthernetHeader {
    pub dst: MacAddress,
    pub src: MacAddress,
    pub ethertype: EtherType,
    // TODO: checksum
}

impl EthernetHeader {
    pub const SIZE: usize = mem::size_of::<Self>();
}

impl fmt::Display for EthernetHeader {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ethernet: src={} dst={} type={}",
            self.src, self.dst, self.ethertype
        )
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
pub struct MacAddress(pub [u8; 6]);

impl From<[u8; 6]> for MacAddress {
    #[inline]
    fn from(value: [u8; 6]) -> Self {
        MacAddress(value)
    }
}

impl fmt::Debug for MacAddress {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddress({self})")
    }
}

impl fmt::Display for MacAddress {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
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
pub struct EtherType(pub network_endian::U16);

impl EtherType {
    pub const IPV4: Self = Self(network_endian::U16::new(0x0800));
    pub const ARP: Self = Self(network_endian::U16::new(0x0806));
    pub const IPV6: Self = Self(network_endian::U16::new(0x86DD));

    #[inline]
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::IPV4 => "IPV4",
            Self::ARP => "ARP",
            Self::IPV6 => "IPV6",
            _ => return None,
        })
    }
}

impl fmt::Display for EtherType {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name() {
            f.write_str(name)
        } else {
            write!(f, "0x{:04X}", self.0)
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EthernetPduError {
    BufferTooShort,
}

// TODO: sealed trait for T
impl<T: ?Sized> From<zerocopy::SizeError<&mut [u8], T>> for EthernetPduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&mut [u8], T>) -> Self {
        EthernetPduError::BufferTooShort
    }
}

impl<T: ?Sized> From<zerocopy::SizeError<&[u8], T>> for EthernetPduError {
    #[inline]
    fn from(_err: zerocopy::SizeError<&[u8], T>) -> Self {
        EthernetPduError::BufferTooShort
    }
}
