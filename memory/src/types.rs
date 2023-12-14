use faithe::FaitheError;
use std::sync::Arc;
use tokio::sync::Mutex;

use thiserror::Error;

pub use aobscan::Pattern as ExternPattern;
pub use aobscan::PatternBuilder as ExternPatternBuilder;

pub type UPtr = usize;
pub type Address = usize;
pub type ArcMutex<T> = Arc<Mutex<T>>;
pub type AutoResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub enum MemorySelector {
    GodMode,
    Health,
    Money,
}

/// Represents a pattern.
#[derive(Clone)]
pub struct Pattern {
    /// The bytes of the pattern.
    pub bytes: Vec<Option<u8>>,
}

impl TryFrom<&str> for Pattern {
    type Error = std::num::ParseIntError;

    /// Creates a new `Pattern` from a string representation.
    ///
    /// # Arguments
    ///
    /// * `value` - The string representation of the pattern.
    ///
    /// # Examples
    ///
    /// ```
    /// let pattern = Pattern::try_from("8D 34 85 ? ? ? ? 89 15 ? ? ? ? 8B 41 08 8B 48 04 83 F9 FF").unwrap();
    /// ```
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let bytes = value
            .split_whitespace()
            .map(|s| {
                Ok(match s {
                    "?" => None,
                    _ => Some(u8::from_str_radix(s, 16)?),
                })
            })
            .collect::<Result<Vec<Option<u8>>, _>>()?;

        Ok(Self { bytes })
    }
}
impl Into<Box<[Option<u8>]>> for Pattern {
    fn into(self) -> Box<[Option<u8>]> {
        self.bytes.into_boxed_slice()
    }
}
impl Into<String> for Pattern {
    fn into(self) -> String {
        let mut buf: String;
        for b in self.bytes {
            match b {
                Some(b) => {
                    buf.push_str(&format!("{:02X} ", b));
                }
                None => {
                    buf.push_str("? ");
                }
            }
        }
        buf.chars().take(buf.len() - 1).collect::<String>()
    }
}
impl Into<ExternPattern> for Pattern {
    fn into(self) -> ExternPattern {
        let pattern: String = self.into();
        ExternPatternBuilder::from_ida_style(&pattern).unwrap().with_all_threads().build()
    }
}

#[derive(Clone, Default)]
pub enum ValueTypes {
    #[default]
    Undefined,
    Ptr(UPtr),
    Bytes1(bool),
    Bytes2(i16),
    Bytes2U(u16),
    Bytes4(i32),
    Bytes4U(u32),
    Bytes8(i64),
    Bytes8U(u64),
    Float(f32),
    Double(f64),
    RawBytes(Box<[u8]>),
}
impl PartialEq for ValueTypes {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Undefined, Self::Undefined) => true,
            (Self::Ptr(_), Self::Ptr(_)) => true,
            (Self::Bytes1(_), Self::Bytes1(_)) => true,
            (Self::Bytes2(_), Self::Bytes2(_)) => true,
            (Self::Bytes2U(_), Self::Bytes2U(_)) => true,
            (Self::Bytes4(_), Self::Bytes4(_)) => true,
            (Self::Bytes4U(_), Self::Bytes4U(_)) => true,
            (Self::Bytes8(_), Self::Bytes8(_)) => true,
            (Self::Bytes8U(_), Self::Bytes8U(_)) => true,
            (Self::Float(_), Self::Float(_)) => true,
            (Self::Double(_), Self::Double(_)) => true,
            (Self::RawBytes(_), Self::RawBytes(_)) => true,
            _ => false,
        }
    }
}
impl ToString for ValueTypes {
    fn to_string(&self) -> String {
        match self {
            ValueTypes::Undefined => "undefined".to_string(),
            ValueTypes::Ptr(_) => "ptr".to_string(),
            ValueTypes::Bytes1(_) => "bool".to_string(),
            ValueTypes::Bytes2(_) => "i16".to_string(),
            ValueTypes::Bytes2U(_) => "u16".to_string(),
            ValueTypes::Bytes4(_) => "i32".to_string(),
            ValueTypes::Bytes4U(_) => "u32".to_string(),
            ValueTypes::Bytes8(_) => "i64".to_string(),
            ValueTypes::Bytes8U(_) => "u64".to_string(),
            ValueTypes::Float(_) => "f32".to_string(),
            ValueTypes::Double(_) => "f64".to_string(),
            ValueTypes::RawBytes(_) => "raw".to_string(),
        }
    }
}

#[derive(Error, Debug)]
pub enum IOError {
    #[error("unknown error")]
    Unexpected,
    #[error("ValueTypes undefined state")]
    UndefinedType,
    #[error("attempt to access a null pointer")]
    NullPtr,
    #[error("runtime sanity check failed")]
    RuntimeSanityCheckError,
    #[error("invalid header (expected {expected:?}, found {found:?})")]
    TypeError { expected: String, found: String },
    #[error("external lib memory errors")]
    MemoryFailed(FaitheError),
    #[error("read access unavailable")]
    ReadAccessUnavailable,
    #[error("write access unavailable")]
    WriteAccessUnavailable,
}
impl Default for IOError {
    fn default() -> Self {
        Self::Unexpected
    }
}
impl From<FaitheError> for IOError {
    fn from(err: FaitheError) -> Self {
        IOError::MemoryFailed(err)
    }
}
