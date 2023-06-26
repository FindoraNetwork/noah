use noah_algebra::error;
use noah_algebra::prelude::AlgebraError;

pub(crate) type Result<T> = core::result::Result<T, AccumulatorError>;

#[derive(Debug, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum AccumulatorError {
    Message(String),
    Ruc(String),
    Algebra(AlgebraError),
}

impl core::fmt::Display for AccumulatorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use AccumulatorError::*;
        f.write_str(match self {
            Message(e) => Box::leak(format!("Message: {}", e).into_boxed_str()),
            Ruc(e) => Box::leak(format!("Ruc: {}", e).into_boxed_str()),
            Algebra(e) => Box::leak(format!("Algebra: {}", e).into_boxed_str()),
        })
    }
}

impl From<AlgebraError> for AccumulatorError {
    fn from(e: AlgebraError) -> AccumulatorError {
        AccumulatorError::Algebra(e)
    }
}

impl From<Box<dyn ruc::err::RucError>> for AccumulatorError {
    fn from(e: Box<dyn ruc::err::RucError>) -> AccumulatorError {
        AccumulatorError::Ruc(format!("{}", e))
    }
}

impl error::Error for AccumulatorError {
    #[cfg(feature = "std")]
    fn description(&self) -> &str {
        Box::leak(format!("{}", self).into_boxed_str())
    }
}
