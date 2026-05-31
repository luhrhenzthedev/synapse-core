/// Authentication module with input validation and metrics collection.
///
/// See [idempotency.md](./idempotency.md) for comprehensive documentation on idempotency keys.
pub mod error;
pub mod health;
pub mod input_validation;
pub mod metrics;

pub use error::*;
pub use health::*;
pub use input_validation::*;
pub use metrics::*;
