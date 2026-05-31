//! Error types for the Security module — rate limiting and input validation.
//!
//! # Error Hierarchy
//!
//! ```text
//! SecurityError
//! ├── RateLimit   — request throttling violations
//! └── Validation  — input constraint violations
//! ```
//!
//! # HTTP Mapping
//!
//! | Variant | HTTP Status | Stable Code |
//! |---------|-------------|-------------|
//! | `RateLimit::Exceeded` | 429 | `ERR_SEC_001` |
//! | `RateLimit::BurstExceeded` | 429 | `ERR_SEC_002` |
//! | `RateLimit::InvalidConfig` | 500 | `ERR_SEC_003` |
//! | `Validation::EmptyInput` | 400 | `ERR_SEC_010` |
//! | `Validation::InputTooLong` | 400 | `ERR_SEC_011` |
//! | `Validation::InvalidCharacters` | 400 | `ERR_SEC_012` |
//! | `Validation::InvalidFormat` | 400 | `ERR_SEC_013` |
//!
//! # Security Considerations
//!
//! - Error messages **never** include raw user input to prevent log injection.
//! - `RateLimit::Exceeded` exposes `retry_after_secs` so clients can back off
//!   without probing the server.
//! - All variants implement `std::error::Error` via [`thiserror`] so they
//!   compose cleanly with `?` and `anyhow`.
//!
//! # Example
//!
//! ```rust
//! use synapse_core::security::error::{RateLimitError, ValidationError, SecurityError};
//!
//! fn check_key(key: &str) -> Result<(), SecurityError> {
//!     if key.is_empty() {
//!         return Err(ValidationError::EmptyInput { field: "api_key" }.into());
//!     }
//!     Ok(())
//! }
//! ```

use thiserror::Error;

// ---------------------------------------------------------------------------
// Rate-limit errors
// ---------------------------------------------------------------------------

/// Errors produced by the rate-limiting subsystem.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RateLimitError {
    /// The caller has exhausted their request quota for the current window.
    ///
    /// `retry_after_secs` is the number of seconds the caller should wait
    /// before retrying. Expose this in the `Retry-After` HTTP response header.
    #[error("rate limit exceeded; retry after {retry_after_secs}s")]
    Exceeded {
        /// Seconds until the rate-limit window resets.
        retry_after_secs: u64,
    },

    /// The caller exceeded the short-burst allowance (e.g. 10 req/s).
    ///
    /// Distinct from `Exceeded` so callers can differentiate sustained
    /// overload from momentary spikes.
    #[error("burst limit exceeded; retry after {retry_after_secs}s")]
    BurstExceeded {
        /// Seconds until the burst window resets.
        retry_after_secs: u64,
    },

    /// The rate-limit configuration is internally inconsistent (e.g. zero
    /// `max_requests` or a zero-duration window). This is a programming error
    /// and should never reach production.
    #[error("invalid rate-limit configuration: {reason}")]
    InvalidConfig {
        /// Human-readable description of the misconfiguration.
        reason: &'static str,
    },
}

impl RateLimitError {
    /// HTTP status code for this error (always 429 for limit violations, 500
    /// for configuration errors).
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Exceeded { .. } | Self::BurstExceeded { .. } => 429,
            Self::InvalidConfig { .. } => 500,
        }
    }

    /// Stable, machine-readable error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Exceeded { .. } => "ERR_SEC_001",
            Self::BurstExceeded { .. } => "ERR_SEC_002",
            Self::InvalidConfig { .. } => "ERR_SEC_003",
        }
    }

    /// Seconds until the client may retry, if applicable.
    ///
    /// Returns `None` for configuration errors where retrying immediately
    /// would not help.
    pub fn retry_after_secs(&self) -> Option<u64> {
        match self {
            Self::Exceeded { retry_after_secs } | Self::BurstExceeded { retry_after_secs } => {
                Some(*retry_after_secs)
            }
            Self::InvalidConfig { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

/// Errors produced by security-layer input validation.
///
/// These are checked **before** any business logic runs so that malformed or
/// oversized inputs are rejected at the boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    /// A required field was empty.
    #[error("field '{field}' must not be empty")]
    EmptyInput {
        /// Name of the field that was empty (e.g. `"api_key"`).
        field: &'static str,
    },

    /// A field exceeded its maximum allowed length.
    #[error("field '{field}' exceeds maximum length of {max_len} characters")]
    InputTooLong {
        /// Name of the field.
        field: &'static str,
        /// Maximum allowed length in characters.
        max_len: usize,
    },

    /// A field contained characters outside the allowed set.
    ///
    /// The raw input is **not** included in the message to prevent log
    /// injection. Callers should log the field name only.
    #[error("field '{field}' contains invalid characters")]
    InvalidCharacters {
        /// Name of the field.
        field: &'static str,
    },

    /// A field did not match the expected format (e.g. UUID, IP address).
    #[error("field '{field}' has invalid format: {reason}")]
    InvalidFormat {
        /// Name of the field.
        field: &'static str,
        /// Short description of the expected format.
        reason: &'static str,
    },
}

impl ValidationError {
    /// HTTP status code (always 400 for validation errors).
    pub fn status_code(&self) -> u16 {
        400
    }

    /// Stable, machine-readable error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::EmptyInput { .. } => "ERR_SEC_010",
            Self::InputTooLong { .. } => "ERR_SEC_011",
            Self::InvalidCharacters { .. } => "ERR_SEC_012",
            Self::InvalidFormat { .. } => "ERR_SEC_013",
        }
    }
}

// ---------------------------------------------------------------------------
// Top-level SecurityError
// ---------------------------------------------------------------------------

/// Top-level error type for the security module.
///
/// Wraps [`RateLimitError`] and [`ValidationError`] so callers can handle
/// both with a single `match` arm or propagate them uniformly via `?`.
#[derive(Debug, Error)]
pub enum SecurityError {
    /// A rate-limiting constraint was violated.
    #[error(transparent)]
    RateLimit(#[from] RateLimitError),

    /// An input validation constraint was violated.
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

impl SecurityError {
    /// HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            Self::RateLimit(e) => e.status_code(),
            Self::Validation(e) => e.status_code(),
        }
    }

    /// Stable, machine-readable error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::RateLimit(e) => e.code(),
            Self::Validation(e) => e.code(),
        }
    }

    /// Optional retry delay for rate-limit violations.
    pub fn retry_after_secs(&self) -> Option<u64> {
        match self {
            Self::RateLimit(e) => e.retry_after_secs(),
            Self::Validation(_) => None,
        }
    }

    /// Returns `true` when the error maps to a 4xx HTTP status.
    pub fn is_client_error(&self) -> bool {
        self.status_code() < 500
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── RateLimitError ───────────────────────────────────────────────────────

    #[test]
    fn rate_limit_exceeded_status_and_code() {
        let e = RateLimitError::Exceeded { retry_after_secs: 30 };
        assert_eq!(e.status_code(), 429);
        assert_eq!(e.code(), "ERR_SEC_001");
        assert_eq!(e.retry_after_secs(), Some(30));
    }

    #[test]
    fn burst_exceeded_status_and_code() {
        let e = RateLimitError::BurstExceeded { retry_after_secs: 5 };
        assert_eq!(e.status_code(), 429);
        assert_eq!(e.code(), "ERR_SEC_002");
        assert_eq!(e.retry_after_secs(), Some(5));
    }

    #[test]
    fn invalid_config_status_and_code() {
        let e = RateLimitError::InvalidConfig { reason: "max_requests is zero" };
        assert_eq!(e.status_code(), 500);
        assert_eq!(e.code(), "ERR_SEC_003");
        assert_eq!(e.retry_after_secs(), None);
    }

    #[test]
    fn rate_limit_exceeded_display() {
        let e = RateLimitError::Exceeded { retry_after_secs: 60 };
        assert!(e.to_string().contains("60"));
    }

    #[test]
    fn burst_exceeded_display() {
        let e = RateLimitError::BurstExceeded { retry_after_secs: 1 };
        assert!(e.to_string().contains("burst"));
    }

    // ── ValidationError ──────────────────────────────────────────────────────

    #[test]
    fn empty_input_status_and_code() {
        let e = ValidationError::EmptyInput { field: "api_key" };
        assert_eq!(e.status_code(), 400);
        assert_eq!(e.code(), "ERR_SEC_010");
        assert!(e.to_string().contains("api_key"));
    }

    #[test]
    fn input_too_long_status_and_code() {
        let e = ValidationError::InputTooLong { field: "token", max_len: 256 };
        assert_eq!(e.status_code(), 400);
        assert_eq!(e.code(), "ERR_SEC_011");
        assert!(e.to_string().contains("256"));
    }

    #[test]
    fn invalid_characters_does_not_leak_input() {
        let e = ValidationError::InvalidCharacters { field: "user_id" };
        // The raw input must not appear in the error message.
        let msg = e.to_string();
        assert!(msg.contains("user_id"));
        assert!(!msg.contains("DROP TABLE")); // sanity: no injection
    }

    #[test]
    fn invalid_format_status_and_code() {
        let e = ValidationError::InvalidFormat { field: "tenant_id", reason: "expected UUID v4" };
        assert_eq!(e.status_code(), 400);
        assert_eq!(e.code(), "ERR_SEC_013");
        assert!(e.to_string().contains("UUID v4"));
    }

    // ── SecurityError ────────────────────────────────────────────────────────

    #[test]
    fn security_error_from_rate_limit() {
        let e: SecurityError = RateLimitError::Exceeded { retry_after_secs: 10 }.into();
        assert_eq!(e.status_code(), 429);
        assert_eq!(e.code(), "ERR_SEC_001");
    }

    #[test]
    fn security_error_from_validation() {
        let e: SecurityError = ValidationError::EmptyInput { field: "secret" }.into();
        assert_eq!(e.status_code(), 400);
        assert_eq!(e.code(), "ERR_SEC_010");
        assert_eq!(e.retry_after_secs(), None);
        assert!(e.is_client_error());
    }

    #[test]
    fn security_error_retry_after_for_rate_limits() {
        let e: SecurityError = RateLimitError::Exceeded { retry_after_secs: 15 }.into();
        assert_eq!(e.retry_after_secs(), Some(15));
        assert!(e.is_client_error());
    }

    #[test]
    fn security_error_display_is_transparent() {
        let inner = RateLimitError::BurstExceeded { retry_after_secs: 2 };
        let outer: SecurityError = inner.into();
        assert!(outer.to_string().contains("burst"));
    }
}
