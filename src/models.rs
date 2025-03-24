#![cfg(not(doctest))]

use core::fmt;
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, fmt::Display};
use std::cell::RefCell;
use uuid::Uuid;

/// Supabase Auth Client
#[derive(Clone)]
pub struct AuthClient {
    pub(crate) client: Client,
    /// REST endpoint for querying and managing your database
    /// Example: `https://YOUR_PROJECT_ID.supabase.co`
    pub(crate) project_url: String,
    /// WARN: The `service role` key has the ability to bypass Row Level Security. Never share it publicly.
    pub(crate) api_key: String,
    /// Used to decode your JWTs. You can also use this to mint your own JWTs.
    pub(crate) jwt_secret: String,

    pub(crate) session: RefCell<Option<Session>>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Session {
    /// The oauth provider token. If present, this can be used to make external API requests to the oauth provider used.
    pub provider_token: Option<String>,
    /// The oauth provider refresh token. If present, this can be used to refresh the provider_token via the oauth provider's API.
    ///
    /// Not all oauth providers return a provider refresh token. If the provider_refresh_token is missing, please refer to the oauth provider's documentation for information on how to obtain the provider refresh token.
    pub provider_refresh_token: Option<String>,
    /// The access token jwt. It is recommended to set the JWT_EXPIRY to a shorter expiry value.
    pub access_token: String,
    pub token_type: String,
    /// The number of seconds until the token expires (since it was issued). Returned when a login is confirmed.
    pub expires_in: i64,
    /// A timestamp of when the token will expire. Returned when a login is confirmed.
    pub expires_at: u64,
    /// A one-time used refresh token that never expires.
    pub refresh_token: String,
    pub user: User,
}

/// User respresents a registered user
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct User {
    pub id: Uuid,
    pub aud: String,
    pub role: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invited_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_sent_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_confirmed_at: Option<String>,
    pub phone: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_confirmed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_sent_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sign_in_at: Option<String>,
    pub app_metadata: AppMetadata,
    pub user_metadata: UserMetadata,
    pub identities: Vec<Identity>,
    pub created_at: String,
    pub updated_at: String,
    pub is_anonymous: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct AppMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub providers: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct UserMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(flatten)]
    pub custom: HashMap<String, Value>,
}

#[derive(Debug)]
pub enum EmailSignUpResult {
    SessionResult(Session),
    ConfirmationResult(EmailSignUpConfirmation),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Default)]
pub struct EmailSignUpConfirmation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmation_sent_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_anonymous: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdTokenCredentials {
    /// Provider name or OIDC `iss` value identifying which provider should be used to verify the provided token.
    pub provider: Provider,
    /// OIDC ID token issued by the specified provider. The iss claim in the ID token must match the supplied provider. Some ID tokens contain an at_hash which require that you provide an access_token value to be accepted properly. If the token contains a nonce claim you must supply the nonce used to obtain the ID token.
    #[serde(rename = "id_token")]
    pub token: String,
    /// If the ID token contains an at_hash claim, then the hash of this value is compared to the value in the ID token.
    pub access_token: Option<String>,
    /// If the ID token contains a nonce claim, then the hash of this value is compared to the value in the ID token.
    pub nonce: Option<String>,
    /// Optional Object which may contain a captcha token
    pub gotrue_meta_security: Option<GotrueMetaSecurity>,
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Default)]
pub struct LoginWithOAuthOptions {
    pub query_params: Option<HashMap<String, String>>,
    pub redirect_to: Option<String>,
    pub scopes: Option<String>,
    pub skip_brower_redirect: Option<bool>,
}

#[derive(Debug, PartialEq)]
pub struct OAuthResponse {
    pub url: Url,
    pub provider: Provider,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GotrueMetaSecurity {
    /// Verification token received when the user completes the captcha on the site.
    captcha_token: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Identity {
    pub identity_id: String,
    pub id: String,
    pub user_id: String,
    pub identity_data: IdentityData,
    pub provider: String,
    pub last_sign_in_at: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub email_verified: bool,
    pub phone_verified: bool,
    pub sub: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LoginOptions {
    Email(String),
    Phone(String),
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct LoginWithEmailAndPasswordPayload<'a> {
    pub(crate) email: &'a str,
    pub(crate) password: &'a str,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct LoginWithPhoneAndPasswordPayload<'a> {
    pub(crate) phone: &'a str,
    pub(crate) password: &'a str,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SignUpWithEmailAndPasswordPayload<'a> {
    pub(crate) email: &'a str,
    pub(crate) password: &'a str,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) options: Option<SignUpWithPasswordOptions>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SignUpWithPhoneAndPasswordPayload<'a> {
    pub(crate) phone: &'a str,
    pub(crate) password: &'a str,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) options: Option<SignUpWithPasswordOptions>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct LoginAnonymouslyPayload {
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) options: Option<LoginAnonymouslyOptions>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignUpWithPasswordOptions {
    /// The redirect url embedded in the email link
    #[serde(skip)]
    pub email_redirect_to: Option<String>,
    /// A custom data object to store the user's metadata. This maps to the `auth.users.raw_user_meta_data` column.
    ///
    /// The `data` should be a JSON object that includes user-specific info, such as their first and last name.
    pub data: Option<Value>,
    /// Verification token received when the user completes the captcha on the site.
    pub captcha_token: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResetPasswordOptions {
    /// The redirect url embedded in the email link
    #[serde(skip)]
    pub email_redirect_to: Option<String>,

    /// Verification token received when the user completes the captcha on the site.
    pub captcha_token: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoginAnonymouslyOptions {
    /// The `data` should be a JSON object that includes user-specific info, such as their first and last name.
    pub data: Option<Value>,
    /// Verification token received when the user completes the captcha on the site.
    pub captcha_token: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct RequestMagicLinkPayload<'a> {
    pub(crate) email: &'a str,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdatedUser {
    pub email: Option<String>,
    pub password: Option<String>,
    pub data: Option<serde_json::Value>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct SendSMSOtpPayload<'a> {
    pub phone: &'a str,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OTPResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum VerifyOtpParams {
    Mobile(VerifyMobileOtpParams),
    Email(VerifyEmailOtpParams),
    TokenHash(VerifyTokenHashParams),
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifyMobileOtpParams {
    /// The user's phone number.
    pub phone: String,
    /// The otp sent to the user's phone number.
    pub token: String,
    /// The user's verification type.
    #[serde(rename = "type")]
    pub otp_type: OtpType,
    /// Optional parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<VerifyOtpOptions>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifyEmailOtpParams {
    /// The user's email.
    pub email: String,
    /// The otp sent to the user's email.
    pub token: String,
    /// The user's verification type.
    #[serde(rename = "type")]
    pub otp_type: OtpType,
    /// Optional parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<VerifyOtpOptions>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifyTokenHashParams {
    /// The user's phone number.
    pub token_hash: String,
    /// The user's verification type.
    #[serde(rename = "type")]
    pub otp_type: OtpType,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OtpType {
    #[default]
    Signup,
    EmailChange,
    Sms,
    Email,
    PhoneChange,
    Invite,
    Magiclink,
    Recovery,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerifyOtpOptions {
    /// A URL to send the user to after they are confirmed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_to: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Default)]
pub(crate) struct LoginWithEmailOtpPayload<'a> {
    pub email: &'a str,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) options: Option<LoginEmailOtpParams>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoginEmailOtpParams {
    /// Verification token received when the user completes the captcha on the site.
    pub captcha_token: Option<String>,
    /// A custom data object to store the user's metadata. This maps to the `auth.users.raw_user_meta_data` column.
    pub data: Option<serde_json::Value>,
    /// The redirect url embedded in the email link
    pub email_redirect_to: Option<String>,
    /// If set to false, this method will not create a new user. Defaults to true.
    pub should_create_user: Option<bool>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoginMobileOtpParams {
    /// Verification token received when the user completes the captcha on the site.
    pub captcha_token: Option<String>,
    /// A custom data object to store the user's metadata. This maps to the `auth.users.raw_user_meta_data` column.
    pub data: Option<serde_json::Value>,
    /// The redirect url embedded in the email link
    pub channel: Option<Channel>,
    /// If set to false, this method will not create a new user. Defaults to true.
    pub should_create_user: Option<bool>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct RefreshSessionPayload<'a> {
    pub refresh_token: &'a str,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct ResetPasswordForEmailPayload {
    pub email: String,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) options: Option<ResetPasswordOptions>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResendParams {
    #[serde(rename = "type")]
    pub otp_type: OtpType,
    pub email: String,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<DesktopResendOptions>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InviteParams {
    pub email: String,
    pub data: Option<Value>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DesktopResendOptions {
    pub email_redirect_to: Option<String>,
    pub captcha_token: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MobileResendParams {
    #[serde(rename = "type")]
    pub otp_type: OtpType,
    pub phone: String,
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<MobileResendOptions>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MobileResendOptions {
    captcha_token: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    #[default]
    Sms,
    Whatsapp,
}

impl Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Channel::Sms => write!(f, "sms"),
            Channel::Whatsapp => write!(f, "whatsapp"),
        }
    }
}

/// Health status of the Auth Server
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuthServerHealth {
    /// Version of the service
    pub version: String,
    /// Name of the service
    pub name: String,
    /// Description of the service
    pub description: String,
}

/// Settings of the Auth Server
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthServerSettings {
    pub external: External,
    pub disable_signup: bool,
    pub mailer_autoconfirm: bool,
    pub phone_autoconfirm: bool,
    pub sms_provider: String,
    pub saml_enabled: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct External {
    pub anonymous_users: bool,
    pub apple: bool,
    pub azure: bool,
    pub bitbucket: bool,
    pub discord: bool,
    pub facebook: bool,
    pub figma: bool,
    pub fly: bool,
    pub github: bool,
    pub gitlab: bool,
    pub google: bool,
    pub keycloak: bool,
    pub kakao: bool,
    pub linkedin: bool,
    pub linkedin_oidc: bool,
    pub notion: bool,
    pub spotify: bool,
    pub slack: bool,
    pub slack_oidc: bool,
    pub workos: bool,
    pub twitch: bool,
    pub twitter: bool,
    pub email: bool,
    pub phone: bool,
    pub zoom: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Currently enabled OAuth providers.
///
/// # Example
/// ```
/// let provider = Provider::Github.to_string();
/// println!("{provider}") // "github"
/// ```
pub enum Provider {
    Apple,
    Azure,
    Bitbucket,
    Discord,
    Facebook,
    Figma,
    Fly,
    Github,
    Gitlab,
    Google,
    Kakao,
    Keycloak,
    Linkedin,
    LinkedinOidc,
    Notion,
    Slack,
    SlackOidc,
    Spotify,
    Twitch,
    Twitter,
    Workos,
    Zoom,
}

impl Display for Provider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Provider::Apple => write!(f, "apple"),
            Provider::Azure => write!(f, "azure"),
            Provider::Bitbucket => write!(f, "bitbucket"),
            Provider::Discord => write!(f, "discord"),
            Provider::Facebook => write!(f, "facebook"),
            Provider::Figma => write!(f, "figma"),
            Provider::Fly => write!(f, "fly"),
            Provider::Github => write!(f, "github"),
            Provider::Gitlab => write!(f, "gitlab"),
            Provider::Google => write!(f, "google"),
            Provider::Kakao => write!(f, "kakao"),
            Provider::Keycloak => write!(f, "keycloak"),
            Provider::Linkedin => write!(f, "linkedin"),
            Provider::LinkedinOidc => write!(f, "linkedin_oidc"),
            Provider::Notion => write!(f, "notion"),
            Provider::Slack => write!(f, "slack"),
            Provider::SlackOidc => write!(f, "slack_oidc"),
            Provider::Spotify => write!(f, "spotify"),
            Provider::Twitch => write!(f, "twitch"),
            Provider::Twitter => write!(f, "twitter"),
            Provider::Workos => write!(f, "workos"),
            Provider::Zoom => write!(f, "zoom"),
        }
    }
}

/// Represents the scope of the logout operation
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LogoutScope {
    #[default]
    Global,
    Local,
    Others,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LoginWithSSO {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// UUID of the SSO provider to invoke single-sign on to
    pub provider_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Domain of the SSO provider where users can initiate sign on
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<SSOLoginOptions>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SSOLoginOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Verification token received when the user completes the captcha on the site.
    captcha_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// A URL to send the user to after they have signed-in.
    redirect_to: Option<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SSOSuccess {
    /// URL to open in a browser which will complete the sign-in flow by
    /// taking the user to the identity provider's authentication flow.
    ///
    /// On browsers you can set the URL to `window.location.href` to take
    /// the user to the authentication flow.
    pub url: String,
    pub status: u16,
    pub headers: Headers,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Headers {
    pub date: String,
    #[serde(rename = "content-type")]
    pub content_type: String,
    #[serde(rename = "transfer-encoding")]
    pub transfer_encoding: String,
    pub connection: String,
    pub server: String,
    pub vary: String,
    #[serde(rename = "x-okta-request-id")]
    pub x_okta_request_id: String,
    #[serde(rename = "x-xss-protection")]
    pub x_xss_protection: String,
    pub p3p: String,
    #[serde(rename = "set-cookie")]
    pub set_cookie: Vec<String>,
    #[serde(rename = "content-security-policy-report-only")]
    pub content_security_policy_report_only: String,
    #[serde(rename = "content-security-policy")]
    pub content_security_policy: String,
    #[serde(rename = "x-rate-limit-limit")]
    pub x_rate_limit_limit: String,
    #[serde(rename = "x-rate-limit-remaining")]
    pub x_rate_limit_remaining: String,
    #[serde(rename = "x-rate-limit-reset")]
    pub x_rate_limit_reset: String,
    #[serde(rename = "referrer-policy")]
    pub referrer_policy: String,
    #[serde(rename = "accept-ch")]
    pub accept_ch: String,
    #[serde(rename = "cache-control")]
    pub cache_control: String,
    pub pragma: String,
    pub expires: String,
    #[serde(rename = "x-frame-options")]
    pub x_frame_options: String,
    #[serde(rename = "x-content-type-options")]
    pub x_content_type_options: String,
    #[serde(rename = "x-ua-compatible")]
    pub x_ua_compatible: String,
    #[serde(rename = "content-language")]
    pub content_language: String,
    #[serde(rename = "strict-transport-security")]
    pub strict_transport_security: String,
    #[serde(rename = "x-robots-tag")]
    pub x_robots_tag: String,
}

// Implement custom Debug to avoid exposing sensitive information
impl fmt::Debug for AuthClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthClient")
            .field("project_url", &self.project_url())
            .field("api_key", &"[REDACTED]")
            .field("jwt_secret", &"[REDACTED]")
            .finish()
    }
}

pub const AUTH_V1: &str = "/auth/v1";
