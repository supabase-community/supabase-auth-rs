/*!
The `client` module provides a comprehensive interface for interacting with Supabase Authentication services.

This module enables user authentication, session management, user administration, and server health monitoring
through the [`AuthClient`] struct.

# Notes

- Some features require Supabase Pro plan subscription
- OAuth and SSO require configuration in Supabase dashboard
- Rate limiting may apply to authentication operations
- Always use HTTPS in production environments
- Properly handle token expiration and refresh cycles
*/

use std::env;

use reqwest::{
    header::{self, HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE},
    Client, Url,
};
use serde_json::{from_str, Value};

use crate::{
    error::{
        Error::{self, AuthError},
        SupabaseHTTPError,
    },
    models::{
        AdminCreateUserParams, AdminUpdateUserParams, AdminUserListResponse, AuthClient,
        AuthServerHealth, AuthServerSettings, EmailSignUpConfirmation, EmailSignUpResult,
        ExchangeCodeForSessionPayload, IdTokenCredentials, InviteParams,
        LoginAnonymouslyOptions, LoginAnonymouslyPayload, LoginEmailOtpParams,
        LoginWithEmailAndPasswordPayload, LoginWithEmailOtpPayload, LoginWithOAuthOptions,
        LoginWithPhoneAndPasswordPayload, LoginWithSSO, LogoutScope, MfaChallengeResponse,
        MfaEnrollParams, MfaEnrollResponse, MfaUnenrollResponse, MfaVerifyParams, OAuthResponse,
        OTPResponse, Provider, RefreshSessionPayload, RequestMagicLinkPayload, ResendParams,
        ResetPasswordForEmailPayload, ResetPasswordOptions, SendSMSOtpPayload, Session,
        SignUpWithEmailAndPasswordPayload, SignUpWithPasswordOptions,
        SignUpWithPhoneAndPasswordPayload, UpdatedUser, User, VerifyOtpParams, AUTH_V1,
    },
};

impl AuthClient {
    /// Create a new Auth Client
    /// You can find your project url and keys at `https://supabase.com/dashboard/project/YOUR_PROJECT_ID/settings/api`
    /// # Example
    /// ```
    /// let auth_client = AuthClient::new(project_url, api_key, jwt_secret).unwrap();
    /// ```
    pub fn new(
        project_url: impl Into<String>,
        api_key: impl Into<String>,
        jwt_secret: impl Into<String>,
    ) -> Self {
        AuthClient {
            client: Client::new(),
            project_url: project_url.into(),
            api_key: api_key.into(),
            jwt_secret: jwt_secret.into(),
        }
    }

    /// Create a new AuthClient from environment variables
    /// Requires `SUPABASE_URL`, `SUPABASE_API_KEY`, and `SUPABASE_JWT_SECRET` environment variables
    /// # Example
    /// ```
    /// let auth_client = AuthClient::new_from_env().unwrap();
    ///
    /// assert!(auth_client.project_url == env::var("SUPABASE_URL").unwrap())
    /// ```
    pub fn new_from_env() -> Result<AuthClient, Error> {
        let project_url = env::var("SUPABASE_URL")?;
        let api_key = env::var("SUPABASE_API_KEY")?;
        let jwt_secret = env::var("SUPABASE_JWT_SECRET")?;

        Ok(AuthClient {
            client: Client::new(),
            project_url,
            api_key,
            jwt_secret,
        })
    }

    /// Sign in a user with an email and password
    /// # Example
    /// ```
    /// let session = auth_client
    ///     .login_with_email(demo_email, demo_password)
    ///     .await
    ///     .unwrap();
    ///
    /// assert!(session.user.email == demo_email)
    /// ```
    pub async fn login_with_email(&self, email: &str, password: &str) -> Result<Session, Error> {
        let payload = LoginWithEmailAndPasswordPayload { email, password };

        let mut headers = header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!(
                "{}{}/token?grant_type=password",
                self.project_url, AUTH_V1
            ))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(session) = from_str(&res_body) {
            return Ok(session);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Sign in a user with phone number and password
    /// # Example
    /// ```
    /// let session = auth_client
    ///     .login_with_phone(demo_phone, demo_password)
    ///     .await
    ///     .unwrap();
    ///
    /// assert!(session.user.phone == demo_phone)
    /// ```
    pub async fn login_with_phone(&self, phone: &str, password: &str) -> Result<Session, Error> {
        let payload = LoginWithPhoneAndPasswordPayload { phone, password };

        let mut headers = header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!(
                "{}{}/token?grant_type=password",
                self.project_url, AUTH_V1
            ))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(session) = from_str(&res_body) {
            return Ok(session);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Sign up a new user with an email and password
    /// # Example
    /// ```
    /// let result = auth_client
    ///     .sign_up_with_email_and_password(demo_email, demo_password)
    ///     .await
    ///     .unwrap();
    ///
    /// assert!(result.session.user.email == demo_email)
    ///```
    pub async fn sign_up_with_email_and_password(
        &self,
        email: &str,
        password: &str,
        options: Option<SignUpWithPasswordOptions>,
    ) -> Result<EmailSignUpResult, Error> {
        let redirect_to = options
            .as_ref()
            .and_then(|o| o.email_redirect_to.as_deref().map(str::to_owned));

        let payload = SignUpWithEmailAndPasswordPayload {
            email,
            password,
            options,
        };

        let mut headers = header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!("{}{}/signup", self.project_url, AUTH_V1))
            .query(&[("redirect_to", redirect_to.as_deref())])
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(session) = from_str::<Session>(&res_body) {
            return Ok(EmailSignUpResult::SessionResult(session));
        }

        if let Ok(result) = from_str::<EmailSignUpConfirmation>(&res_body) {
            return Ok(EmailSignUpResult::ConfirmationResult(result));
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Sign up a new user with an email and password
    /// # Example
    /// ```
    /// let session = auth_client
    ///     .sign_up_with_phone_and_password(demo_phone, demo_password)
    ///     .await
    ///     .unwrap();
    ///
    /// assert!(session.user.phone == demo_phone)
    ///```
    pub async fn sign_up_with_phone_and_password(
        &self,
        phone: &str,
        password: &str,
        options: Option<SignUpWithPasswordOptions>,
    ) -> Result<Session, Error> {
        let redirect_to = options
            .as_ref()
            .and_then(|o| o.email_redirect_to.as_deref().map(str::to_owned));

        let payload = SignUpWithPhoneAndPasswordPayload {
            phone,
            password,
            options,
        };

        let mut headers = header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!("{}{}/signup", self.project_url, AUTH_V1))
            .query(&[("email_redirect_to", redirect_to.as_deref())])
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(session) = from_str(&res_body) {
            return Ok(session);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Sign in a new user anonymously. This actually signs up a user, but it's
    /// called "sign in" by Supabase in their own client, so that's why it's
    /// named like this here. You can also pass in the same signup options
    /// that work for the other `sign_up_*` methods, but that's not required.
    ///
    /// This method requires anonymous sign in to be enabled in your dashboard.
    ///
    /// # Example
    /// ```
    /// let session = auth_client
    ///     .login_anonymously(demo_options)
    ///     .await
    ///     .unwrap();
    ///
    /// assert!(session.user.user_metadata.display_name == demo_options.data.display_name)
    /// ```
    pub async fn login_anonymously(
        &self,
        options: Option<LoginAnonymouslyOptions>,
    ) -> Result<Session, Error> {
        let payload = LoginAnonymouslyPayload { options };

        let mut headers = header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!("{}{}/signup", self.project_url, AUTH_V1))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(session) = from_str(&res_body) {
            return Ok(session);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Sends a login email containing a magic link
    /// # Example
    /// ```
    /// let _response = auth_client
    ///     .send_login_email_with_magic_link(demo_email)
    ///    .await
    ///    .unwrap();
    ///```
    pub async fn send_login_email_with_magic_link(&self, email: &str) -> Result<(), Error> {
        let payload = RequestMagicLinkPayload { email };

        let mut headers = header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!("{}{}/magiclink", self.project_url, AUTH_V1))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if res_status.is_success() {
            Ok(())
        } else {
            if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
                return Err(AuthError {
                    status: res_status,
                    message: error.message,
                });
            }

            // Fallback: return raw error
            return Err(AuthError {
                status: res_status,
                message: res_body,
            });
        }
    }

    /// Send a Login OTP via SMS
    ///
    /// # Example
    /// ```
    /// let response = auth_client.send_sms_with_otp(demo_phone).await;
    /// ```
    pub async fn send_sms_with_otp(&self, phone: &str) -> Result<OTPResponse, Error> {
        let payload = SendSMSOtpPayload { phone };

        let mut headers = header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!("{}{}/otp", self.project_url, AUTH_V1))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if res_status.is_success() {
            let message = serde_json::from_str(&res_body)?;
            Ok(message)
        } else {
            if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
                return Err(AuthError {
                    status: res_status,
                    message: error.message,
                });
            }

            // Fallback: return raw error
            return Err(AuthError {
                status: res_status,
                message: res_body,
            });
        }
    }

    /// Send a Login OTP via email
    ///
    /// Returns an OTPResponse on success
    /// # Example
    /// ```
    /// let send = auth_client.send_sms_with_otp(demo_phone).await.unwrap();
    /// ```
    pub async fn send_email_with_otp(
        &self,
        email: &str,
        options: Option<LoginEmailOtpParams>,
    ) -> Result<OTPResponse, Error> {
        let payload = LoginWithEmailOtpPayload { email, options };

        let mut headers = header::HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(format!("{}{}/otp", self.project_url, AUTH_V1))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if res_status.is_success() {
            let message = serde_json::from_str(&res_body)?;
            Ok(message)
        } else {
            if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
                return Err(AuthError {
                    status: res_status,
                    message: error.message,
                });
            }

            // Fallback: return raw error
            return Err(AuthError {
                status: res_status,
                message: res_body,
            });
        }
    }

    /// Sign in a user using an OAuth provider.
    /// # Example
    /// ```
    /// // You can add custom parameters using a HashMap<String, String>
    /// let mut params = HashMap::new();
    /// params.insert("key".to_string(), "value".to_string());
    ///
    /// let options = LoginWithOAuthOptions {
    ///     query_params: Some(params),
    ///     redirect_to: Some("localhost".to_string()),
    ///     scopes: Some("repo gist notifications".to_string()),
    ///     skip_browser_redirect: Some(true),
    /// };
    ///
    /// let response = auth_client
    ///     .login_with_oauth(supabase_auth::models::Provider::Github, Some(options))
    ///     .unwrap();
    /// ```
    pub fn login_with_oauth(
        &self,
        provider: Provider,
        options: Option<LoginWithOAuthOptions>,
    ) -> Result<OAuthResponse, Error> {
        let query_params = options.as_ref().map_or_else(
            || vec![("provider", provider.to_string())],
            |o| {
                let mut params = vec![("provider", provider.to_string())];

                if let Some(ref redirect) = o.redirect_to {
                    params.push(("redirect_to", redirect.to_string()));
                }

                if let Some(ref extra) = o.query_params {
                    params.extend(extra.iter().map(|(k, v)| (k.as_str(), v.to_string())));
                }

                params
            },
        );

        let url = Url::parse_with_params(
            format!("{}{}/authorize", self.project_url, AUTH_V1).as_str(),
            query_params,
        )
        .map_err(|_| Error::ParseUrlError)?;

        Ok(OAuthResponse { url, provider })
    }

    /// Sign up a user using an OAuth provider.
    /// # Example
    /// ```
    /// // You can add custom parameters using a HashMap<String, String>
    /// let mut params = HashMap::new();
    /// params.insert("key".to_string(), "value".to_string());
    ///
    /// let options = LoginWithOAuthOptions {
    ///     query_params: Some(params),
    ///     redirect_to: Some("localhost".to_string()),
    ///     scopes: Some("repo gist notifications".to_string()),
    ///     skip_browser_redirect: Some(true),
    /// };
    ///
    /// let response = auth_client
    ///     .sign_up_with_oauth(supabase_auth::models::Provider::Github, Some(options))
    ///     .unwrap();
    /// ```
    pub fn sign_up_with_oauth(
        &self,
        provider: Provider,
        options: Option<LoginWithOAuthOptions>,
    ) -> Result<OAuthResponse, Error> {
        self.login_with_oauth(provider, options)
    }

    /// Return the signed in User
    /// # Example
    /// ```
    /// let user = auth_client
    ///     .get_user(session.unwrap().access_token)
    ///     .await
    ///     .unwrap();
    ///
    /// assert!(user.email == demo_email)
    /// ```
    pub async fn get_user(&self, bearer_token: &str) -> Result<User, Error> {
        let mut headers = header::HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let response = self
            .client
            .get(format!("{}{}/user", self.project_url, AUTH_V1))
            .headers(headers)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(user) = from_str(&res_body) {
            return Ok(user);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Update the user, such as changing email or password. Each field (email, password, and data) is optional
    /// # Example
    /// ```
    /// let updated_user_data = UpdateUserPayload {
    ///     email: Some("demo@demo.com".to_string()),
    ///     password: Some("demo_password".to_string()),
    ///     data: None, // This field can hold any valid JSON value
    /// };
    ///
    /// let user = auth_client
    ///     .update_user(updated_user_data, access_token)
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn update_user(
        &self,
        updated_user: UpdatedUser,
        bearer_token: &str,
    ) -> Result<User, Error> {
        let mut headers = header::HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let body = serde_json::to_string::<UpdatedUser>(&updated_user)?;

        let response = self
            .client
            .put(format!("{}{}/user", self.project_url, AUTH_V1))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(user) = from_str(&res_body) {
            return Ok(user);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Allows signing in with an OIDC ID token. The authentication provider used should be enabled and configured.
    /// # Example
    /// ```
    /// let credentials = IdTokenCredentials {
    ///     provider: Provider::Github,
    ///     token: "<id-token-from-auth-provider>",
    /// };
    ///
    /// let session = auth_client
    ///     .login_with_id_token(credentials)
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn login_with_id_token(
        &self,
        credentials: IdTokenCredentials,
    ) -> Result<Session, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);

        let body = serde_json::to_string(&credentials)?;

        let response = self
            .client
            .post(format!(
                "{}{}/token?grant_type=id_token",
                self.project_url, AUTH_V1
            ))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(session) = from_str(&res_body) {
            return Ok(session);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Sends an invite link to an email address.
    /// Requires admin permissions to issue invites
    ///
    /// The data field corresponds to the `raw_user_meta_data` User field
    /// # Example
    /// ```
    /// let demo_email = env::var("DEMO_INVITE").unwrap();
    ///
    /// let user = auth_client
    ///     .invite_user_by_email(&demo_email, None, auth_client.api_key())
    ///     .await
    ///     .unwrap();
    ///```
    pub async fn invite_user_by_email(
        &self,
        email: &str,
        data: Option<Value>,
        bearer_token: &str,
    ) -> Result<User, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let invite_payload = InviteParams {
            email: email.into(),
            data,
        };

        let body = serde_json::to_string(&invite_payload)?;

        let response = self
            .client
            .post(format!("{}{}/invite", self.project_url, AUTH_V1))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(user) = from_str(&res_body) {
            return Ok(user);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Verify the OTP sent to the user
    /// # Example
    /// ```
    /// let params = VerifyEmailOtpParams {
    ///     token: "abc123",
    ///     otp_type: OtpType::EmailChange,
    ///     options: None,
    /// };
    ///
    /// let session = auth_client
    ///     .verify_otp(params)
    ///     .await
    ///     .unwrap();
    ///```
    pub async fn verify_otp(&self, params: VerifyOtpParams) -> Result<Session, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);

        let body = serde_json::to_string(&params)?;

        let response = self
            .client
            .post(&format!("{}{}/verify", self.project_url, AUTH_V1))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(session) = from_str(&res_body) {
            return Ok(session);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Check the Health Status of the Auth Server
    /// # Example
    /// ```
    /// let health = auth_client
    ///     .get_health()
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn get_health(&self) -> Result<AuthServerHealth, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

        let response = self
            .client
            .get(&format!("{}{}/health", self.project_url, AUTH_V1))
            .headers(headers)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(health) = from_str::<AuthServerHealth>(&res_body) {
            return Ok(health);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Retrieve the public settings of the server
    /// # Example
    /// ```
    /// let settings = auth_client
    ///     .get_settings()
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn get_settings(&self) -> Result<AuthServerSettings, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

        let response = self
            .client
            .get(&format!("{}{}/settings", self.project_url, AUTH_V1))
            .headers(headers)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(settings) = from_str(&res_body) {
            return Ok(settings);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Exchange refresh token for a new session
    /// # Example
    /// ```
    /// // When a user signs in they get a session
    /// let original_session = auth_client
    ///     .login_with_email_and_password(demo_email.as_ref(), demo_password)
    ///     .await
    ///     .unwrap();
    ///
    /// // Exchange the refresh token from the original session to create a new session
    /// let new_session = auth_client
    ///     .refresh_session(original_session.refresh_token)
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn exchange_token_for_session(&self, refresh_token: &str) -> Result<Session, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);

        let body = serde_json::to_string(&RefreshSessionPayload { refresh_token })?;

        let response = self
            .client
            .post(&format!(
                "{}{}/token?grant_type=refresh_token",
                self.project_url, AUTH_V1
            ))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(session) = from_str(&res_body) {
            return Ok(session);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    pub async fn refresh_session(&self, refresh_token: &str) -> Result<Session, Error> {
        self.exchange_token_for_session(refresh_token).await
    }

    /// Exchange code for a new session
    /// # Example
    /// ```
    /// // When a user signs in they get a session
    /// let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    ///
    /// let options = LoginWithOAuthOptions {
    ///     query_params: Some(HashMap::from([
    ///         (
    ///             "redirect_to".to_owned(),
    ///             "http://localhost:3000/auth/callback".to_owned(),
    ///         ),
    ///         ("response_type".to_owned(), "code".to_owned()),
    ///         ("skip_browser_redirect".to_owned(), "true".to_owned()),
    ///         (
    ///             "code_challenge".to_owned(),
    ///             pkce_challenge.as_str().to_owned(),
    ///         ),
    ///         ("code_challenge_method".to_owned(), "S256".to_owned()),
    ///     ])),
    ///     ..Default::default()
    /// };
    ///
    /// let oauth_res = auth_client
    ///     .login_with_oauth(Provider::Github, Some(options))?;
    ///
    /// // Exchange the code to create a new session
    /// let new_session = auth_client
    ///     .exchange_code_for_session(auth_code, pkce_verifier)
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn exchange_code_for_session(
        &self,
        auth_code: &str,
        code_verifier: &str,
    ) -> Result<Session, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);

        let body = serde_json::to_string(&ExchangeCodeForSessionPayload {
            auth_code,
            code_verifier,
        })?;

        let response = self
            .client
            .post(&format!(
                "{}{}/token?grant_type=pkce",
                self.project_url, AUTH_V1
            ))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(session) = from_str(&res_body) {
            return Ok(session);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        // Fallback: return raw error
        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Send a password recovery email. Invalid Email addresses will return Error Code 400.
    /// Valid email addresses that are not registered as users will not return an error.
    /// # Example
    /// ```
    /// let response = auth_client.reset_password_for_email(demo_email, None).await.unwrap();
    /// ```
    pub async fn reset_password_for_email(
        &self,
        email: &str,
        options: Option<ResetPasswordOptions>,
    ) -> Result<(), Error> {
        let redirect_to = options
            .as_ref()
            .and_then(|o| o.email_redirect_to.as_deref().map(str::to_owned));

        let payload = ResetPasswordForEmailPayload {
            email: String::from(email),
            options,
        };

        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);

        let body = serde_json::to_string(&payload)?;

        let response = self
            .client
            .post(&format!("{}{}/recover", self.project_url, AUTH_V1))
            .query(&[("redirect_to", redirect_to.as_deref())])
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if res_status.is_success() {
            return Ok(());
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Resends emails for existing signup confirmation, email change, SMS OTP, or phone change OTP.
    /// # Example
    /// ```
    /// // Resend can also take MobileResendParams
    /// let credentials = DesktopResendParams {
    ///     otp_type: supabase_auth::models::EmailOtpType::Email,
    ///     email: demo_email.to_owned(),
    ///     options: None,
    /// };
    ///
    /// let resend = auth_client.resend(ResendParams::Desktop(credentials)).await;
    /// ```
    pub async fn resend(&self, credentials: ResendParams) -> Result<(), Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);

        let body = serde_json::to_string(&credentials)?;

        let response = self
            .client
            .post(&format!("{}{}/resend", self.project_url, AUTH_V1))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if res_status.is_success() {
            return Ok(());
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Logs out a user with a given scope
    /// # Example
    /// ```
    /// auth_client.logout(Some(LogoutScope::Global), session.access_token).await.unwrap();
    /// ```
    pub async fn logout(
        &self,
        scope: Option<LogoutScope>,
        bearer_token: &str,
    ) -> Result<(), Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let body = serde_json::to_string(&scope)?;

        let response = self
            .client
            .post(&format!("{}{}/logout", self.project_url, AUTH_V1))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if res_status.is_success() {
            return Ok(());
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(Error::AuthError {
                status: res_status,
                message: error.message,
            });
        }

        Err(Error::AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Initiates an SSO Login Flow
    /// Returns the URL where the user must authenticate with the SSO Provider
    ///
    /// WARNING: Requires an SSO Provider and Supabase Pro plan
    ///
    /// # Example
    /// ```
    /// let url = auth_client.sso(params).await.unwrap();
    ///
    /// println!("{}", url.to_string());
    /// ```
    pub async fn sso(&self, params: LoginWithSSO) -> Result<Url, Error> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);

        let body = serde_json::to_string::<crate::models::LoginWithSSO>(&params)?;

        let response = self
            .client
            .post(&format!("{}{}/sso", self.project_url, AUTH_V1))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let url = response.url().clone();
        let res_body = response.text().await?;

        if res_status.is_server_error() || res_status.is_client_error() {
            if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
                return Err(AuthError {
                    status: res_status,
                    message: error.message,
                });
            }

            // Fallback: return raw error
            return Err(AuthError {
                status: res_status,
                message: res_body,
            });
        }

        Ok(url)
    }

    /// Get the project URL from an AuthClient
    pub fn project_url(&self) -> &str {
        &self.project_url
    }

    /// Get the API Key from an AuthClient
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// Get the JWT Secret from an AuthClient
    pub fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    // ── MFA Methods ────────────────────────────────────────────────────────

    /// Enroll a new MFA factor for the authenticated user.
    ///
    /// Supports TOTP and phone factor types. For TOTP, the response includes
    /// a QR code and secret for use with authenticator apps.
    ///
    /// # Example
    /// ```
    /// use supabase_auth::models::MfaEnrollParams;
    ///
    /// let response = auth_client
    ///     .mfa_enroll(access_token, MfaEnrollParams::totp().friendly_name("My App"))
    ///     .await
    ///     .unwrap();
    ///
    /// println!("Factor ID: {}", response.id);
    /// if let Some(totp) = response.totp {
    ///     println!("QR Code: {}", totp.qr_code);
    /// }
    /// ```
    pub async fn mfa_enroll(
        &self,
        bearer_token: &str,
        params: MfaEnrollParams,
    ) -> Result<MfaEnrollResponse, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let body = serde_json::to_string(&params)?;

        let response = self
            .client
            .post(format!("{}{}/factors", self.project_url, AUTH_V1))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(enroll_response) = from_str(&res_body) {
            return Ok(enroll_response);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(AuthError {
                status: res_status,
                message: error.message,
            });
        }

        Err(AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Create a challenge for an enrolled MFA factor.
    ///
    /// The challenge must be verified with [`AuthClient::mfa_verify`] before it expires.
    ///
    /// # Example
    /// ```
    /// let challenge = auth_client
    ///     .mfa_challenge(access_token, factor_id)
    ///     .await
    ///     .unwrap();
    ///
    /// println!("Challenge ID: {}", challenge.id);
    /// ```
    pub async fn mfa_challenge(
        &self,
        bearer_token: &str,
        factor_id: &str,
    ) -> Result<MfaChallengeResponse, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let response = self
            .client
            .post(format!(
                "{}{}/factors/{}/challenge",
                self.project_url, AUTH_V1, factor_id
            ))
            .headers(headers)
            .body("{}")
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(challenge) = from_str(&res_body) {
            return Ok(challenge);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(AuthError {
                status: res_status,
                message: error.message,
            });
        }

        Err(AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Verify an MFA challenge with a TOTP or SMS code.
    ///
    /// On success, returns a new session with AAL2 (Authenticator Assurance Level 2).
    ///
    /// # Example
    /// ```
    /// use supabase_auth::models::MfaVerifyParams;
    ///
    /// let session = auth_client
    ///     .mfa_verify(
    ///         access_token,
    ///         factor_id,
    ///         MfaVerifyParams::new(challenge_id, "123456"),
    ///     )
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn mfa_verify(
        &self,
        bearer_token: &str,
        factor_id: &str,
        params: MfaVerifyParams,
    ) -> Result<Session, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let body = serde_json::to_string(&params)?;

        let response = self
            .client
            .post(format!(
                "{}{}/factors/{}/verify",
                self.project_url, AUTH_V1, factor_id
            ))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(session) = from_str(&res_body) {
            return Ok(session);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(AuthError {
                status: res_status,
                message: error.message,
            });
        }

        Err(AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Unenroll (delete) an MFA factor.
    ///
    /// # Example
    /// ```
    /// let response = auth_client
    ///     .mfa_unenroll(access_token, factor_id)
    ///     .await
    ///     .unwrap();
    ///
    /// println!("Unenrolled factor: {}", response.id);
    /// ```
    pub async fn mfa_unenroll(
        &self,
        bearer_token: &str,
        factor_id: &str,
    ) -> Result<MfaUnenrollResponse, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let response = self
            .client
            .delete(format!(
                "{}{}/factors/{}",
                self.project_url, AUTH_V1, factor_id
            ))
            .headers(headers)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(unenroll_response) = from_str(&res_body) {
            return Ok(unenroll_response);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(AuthError {
                status: res_status,
                message: error.message,
            });
        }

        Err(AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Combined challenge + verify for convenience.
    ///
    /// Creates a challenge for the given factor and immediately verifies it
    /// with the provided code. This is a shortcut for calling [`AuthClient::mfa_challenge`]
    /// followed by [`AuthClient::mfa_verify`].
    ///
    /// # Example
    /// ```
    /// let session = auth_client
    ///     .mfa_challenge_and_verify(access_token, factor_id, "123456")
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn mfa_challenge_and_verify(
        &self,
        bearer_token: &str,
        factor_id: &str,
        code: &str,
    ) -> Result<Session, Error> {
        let challenge = self.mfa_challenge(bearer_token, factor_id).await?;
        self.mfa_verify(
            bearer_token,
            factor_id,
            MfaVerifyParams::new(&challenge.id, code),
        )
        .await
    }

    // ── Admin User Management Methods ──────────────────────────────────────
    //
    // These methods require a service role key as the bearer token.
    // They should only be used in server-side contexts.

    /// List all users (admin, paginated).
    ///
    /// Requires a service role key. Returns a paginated list of users.
    ///
    /// # Example
    /// ```
    /// let response = auth_client
    ///     .admin_list_users(service_role_key, Some(1), Some(50))
    ///     .await
    ///     .unwrap();
    ///
    /// for user in response.users {
    ///     println!("{}: {}", user.id, user.email);
    /// }
    /// ```
    pub async fn admin_list_users(
        &self,
        bearer_token: &str,
        page: Option<u32>,
        per_page: Option<u32>,
    ) -> Result<AdminUserListResponse, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let mut query_params: Vec<(String, String)> = Vec::new();
        if let Some(page) = page {
            query_params.push(("page".to_string(), page.to_string()));
        }
        if let Some(per_page) = per_page {
            query_params.push(("per_page".to_string(), per_page.to_string()));
        }

        let response = self
            .client
            .get(format!(
                "{}{}/admin/users",
                self.project_url, AUTH_V1
            ))
            .headers(headers)
            .query(&query_params)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(list) = from_str(&res_body) {
            return Ok(list);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(AuthError {
                status: res_status,
                message: error.message,
            });
        }

        Err(AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Get a user by their ID (admin).
    ///
    /// Requires a service role key.
    ///
    /// # Example
    /// ```
    /// let user = auth_client
    ///     .admin_get_user_by_id(service_role_key, user_id)
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn admin_get_user_by_id(
        &self,
        bearer_token: &str,
        user_id: &str,
    ) -> Result<User, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let response = self
            .client
            .get(format!(
                "{}{}/admin/users/{}",
                self.project_url, AUTH_V1, user_id
            ))
            .headers(headers)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(user) = from_str(&res_body) {
            return Ok(user);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(AuthError {
                status: res_status,
                message: error.message,
            });
        }

        Err(AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Create a new user (admin).
    ///
    /// Does not send confirmation emails. Use [`AuthClient::invite_user_by_email`] for that.
    /// Requires a service role key.
    ///
    /// # Example
    /// ```
    /// use supabase_auth::models::AdminCreateUserParams;
    ///
    /// let user = auth_client
    ///     .admin_create_user(
    ///         service_role_key,
    ///         AdminCreateUserParams {
    ///             email: Some("newuser@example.com".to_string()),
    ///             password: Some("secure-password".to_string()),
    ///             email_confirm: Some(true),
    ///             ..Default::default()
    ///         },
    ///     )
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn admin_create_user(
        &self,
        bearer_token: &str,
        params: AdminCreateUserParams,
    ) -> Result<User, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let body = serde_json::to_string(&params)?;

        let response = self
            .client
            .post(format!(
                "{}{}/admin/users",
                self.project_url, AUTH_V1
            ))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(user) = from_str(&res_body) {
            return Ok(user);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(AuthError {
                status: res_status,
                message: error.message,
            });
        }

        Err(AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Update a user by their ID (admin).
    ///
    /// Changes are applied immediately without confirmation flows.
    /// Requires a service role key.
    ///
    /// # Example
    /// ```
    /// use supabase_auth::models::AdminUpdateUserParams;
    ///
    /// let user = auth_client
    ///     .admin_update_user_by_id(
    ///         service_role_key,
    ///         user_id,
    ///         AdminUpdateUserParams {
    ///             email: Some("updated@example.com".to_string()),
    ///             ..Default::default()
    ///         },
    ///     )
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn admin_update_user_by_id(
        &self,
        bearer_token: &str,
        user_id: &str,
        params: AdminUpdateUserParams,
    ) -> Result<User, Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(CONTENT_TYPE, HeaderValue::from_str("application/json")?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let body = serde_json::to_string(&params)?;

        let response = self
            .client
            .put(format!(
                "{}{}/admin/users/{}",
                self.project_url, AUTH_V1, user_id
            ))
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if let Ok(user) = from_str(&res_body) {
            return Ok(user);
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(AuthError {
                status: res_status,
                message: error.message,
            });
        }

        Err(AuthError {
            status: res_status,
            message: res_body,
        })
    }

    /// Delete a user by their ID (admin).
    ///
    /// Requires a service role key.
    ///
    /// # Example
    /// ```
    /// auth_client
    ///     .admin_delete_user(service_role_key, user_id)
    ///     .await
    ///     .unwrap();
    /// ```
    pub async fn admin_delete_user(
        &self,
        bearer_token: &str,
        user_id: &str,
    ) -> Result<(), Error> {
        let mut headers = HeaderMap::new();
        headers.insert("apikey", HeaderValue::from_str(&self.api_key)?);
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", bearer_token))?,
        );

        let response = self
            .client
            .delete(format!(
                "{}{}/admin/users/{}",
                self.project_url, AUTH_V1, user_id
            ))
            .headers(headers)
            .send()
            .await?;

        let res_status = response.status();
        let res_body = response.text().await?;

        if res_status.is_success() {
            return Ok(());
        }

        if let Ok(error) = from_str::<SupabaseHTTPError>(&res_body) {
            return Err(AuthError {
                status: res_status,
                message: error.message,
            });
        }

        Err(AuthError {
            status: res_status,
            message: res_body,
        })
    }
}
