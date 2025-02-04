/*!
Provides error types and handling for Supabase authentication operations.

This module defines the primary [`Error`] enum and supporting types for handling various
error conditions that may occur during authentication operations.

The most common error is [`Error::Supabase`] which wraps [`SupabaseHTTPError`]. This is a transparent error which gives you the `status` as a [`StatusCode`] and `message` from the Supabase response.
*/

use std::{
    env,
    fmt::{self, Display},
};

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("User Already Exists")]
    AlreadySignedUp,
    #[error("Invalid Credentials")]
    WrongCredentials,
    #[error("User Not Found")]
    UserNotFound,
    #[error("Supabase Client not Authenticated")]
    NotAuthenticated,
    #[error("Missing Refresh Token")]
    MissingRefreshToken,
    #[error("JWT Is Invalid")]
    WrongToken,
    #[error("Internal Error")]
    InternalError,
    #[error("Network Error")]
    NetworkError(#[from] reqwest::Error),
    #[error("Failed to Parse")]
    ParseError(#[from] serde_json::Error),
    #[error("Header Value is Invalid")]
    InvalidHeaderValue(#[from] reqwest::header::InvalidHeaderValue),
    #[error("Environment Variable Unreadable")]
    InvalidEnvironmentVariable(#[from] env::VarError),
    #[error("Failed to parse URL")]
    ParseUrlError,
    #[error("{0}")]
    Supabase(SupabaseHTTPError),
    #[error("Error: {status}: {message}")]
    AuthError { status: StatusCode, message: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SupabaseHTTPError {
    pub code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(rename = "msg")]
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_error: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal_message: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_id: Option<String>,
}

impl Display for SupabaseHTTPError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Status Code {}", self.code)?;

        if let Some(error_code) = &self.error_code {
            write!(f, " ({})", error_code)?;
        }

        if let Some(error_id) = &self.error_id {
            write!(f, " [Error ID: {}]", error_id)?;
        }

        if let Some(internal_message) = &self.internal_message {
            write!(f, "\nInternal message: {}", internal_message)?;
        }

        if let Some(internal_error) = &self.internal_error {
            write!(f, "\nInternal error: {}", internal_error)?;
        }

        write!(f, "\nMessage: {}", self.message)
    }
}
