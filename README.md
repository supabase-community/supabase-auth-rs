# Supabase Auth

![Crates.io License](https://img.shields.io/crates/l/supabase-auth?style=for-the-badge)
[![Crates.io Version](https://img.shields.io/crates/v/supabase-auth?style=for-the-badge)](https://crates.io/crates/supabase-auth)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/proziam/supabase-auth-rs/rust.yml?branch=main&style=for-the-badge)
[![docs.rs](https://img.shields.io/docsrs/supabase-auth?style=for-the-badge)](https://docs.rs/supabase-auth/latest/supabase_auth/index.html)

This is a Rust implementation of the [supabase js auth client](https://github.com/supabase/gotrue-js). The goal is to have feature parity and an easy-to-use API. 

Currently this software is functional, but not yet battle-tested. Your feedback is welcome, and I will do my best to quickly address any issues that you come across.

## Installation

### Cargo

```bash
cargo add supabase-auth 
```

## Usage

### Create an Auth Client

```rust
// You can manually pass in the values
let auth_client = AuthClient::new(project_url, api_key, jwt_secret).unwrap();

// Or you can use environment variables
// Requires `SUPABASE_URL`, `SUPABASE_API_KEY`, and `SUPABASE_JWT_SECRET` environment variables
let auth_client = AuthClient::new_from_env().unwrap();
```

### Sign Up

```rust
// Sign up methods return the session which you can use for creating cookies
let session = auth_client
    .sign_up_with_email_and_password(demo_email, demo_password)
    .await
    .unwrap();

// You can also sign up using a phone number and password
let session = auth_client
    .sign_up_with_phone_and_password(demo_phone, demo_password)
    .await
    .unwrap();
```

### Sign In

```rust
// Sign in methods return the session which you can use for creating cookies
let session = auth_client
    .login_with_email(&demo_email, &demo_password)
    .await
    .unwrap();

// You can also login using a phone number
let session = auth_client
    .login_with_phone(demo_phone, demo_password)
    .await
    .unwrap();
```

### OAuth

```rust
// Returns the provider and the url where the user will continue the auth flow
let oauth_response = auth_client
    .login_with_oauth(Provider::Github, None)
    .await
    .unwrap();

// You can also customize the options like so:
let mut query_params = HashMap::new();

query_params.insert("key".to_string(), "value".to_string());
query_params.insert("second_key".to_string(), "second_value".to_string());
query_params.insert("third_key".to_string(), "third_value".to_string());

let options = SignInWithOAuthOptions {
    query_params: Some(query_params),
    redirect_to: Some("your-redirect-url".to_string()),
    scopes: Some("repo gist notifications".to_string()),
    skip_brower_redirect: Some(true),
};

let response = auth_client
    .login_with_oauth(Provider::Github, Some(options))
    .await
    .unwrap();
```

### SSO

NOTE: Requires an SSO Provider and Supabase Pro plan

```rust
let params = SignInWithSSO {
    domain: Some(demo_domain),
    options: None,
    provider_id: None,
};

// Returns the URL where the user will continue the auth flow with your SSO provider
let url = auth_client.sso(params).await.unwrap();
```


## Features
- [x] Create Client
- [x] Sign In with Email & Password
- [x] Sign In with Phone & Password
- [x] Sign Up with Email & Password
- [x] Sign Up with Phone & Password
- [x] Sign In with Third Party Auth (OAuth)
- [x] Sign In with Magic Link 
- [x] Send Sign-In OTP (Email, SMS, Whatsapp)
- [x] Sign In with OTP
- [x] Refresh Session
- [x] Resend OTP Tokens (Email & SMS)
- [x] Retrieve User
- [x] Reset Password
- [x] Change User Data (e.g., Email or password)
- [x] SSO

## Contributions

Contributors are always welcome. I only ask that you add or update tests to cover your changes. Until this crate reaches 1.0.0 we're in the "move fast and break things" phase. Don't concern yourself with elegance.
