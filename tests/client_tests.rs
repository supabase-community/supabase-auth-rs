use core::time;
use std::{collections::HashMap, env, thread};

use supabase_auth::{
    error::Error,
    models::{
        AuthClient, EmailSignUpResult, LoginEmailOtpParams, LoginWithOAuthOptions, LoginWithSSO,
        LogoutScope, ResendParams, ResetPasswordOptions, SignUpWithPasswordOptions, UpdatedUser,
    },
};

fn create_test_client() -> AuthClient {
    AuthClient::new_from_env().unwrap()
}

#[tokio::test]
async fn create_client_test_valid() {
    let auth_client = AuthClient::new_from_env().unwrap();

    assert!(*auth_client.project_url() == env::var("SUPABASE_URL").unwrap())
}

#[tokio::test]
async fn test_login_with_email() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_EMAIL").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();

    let session = auth_client
        .login_with_email(&demo_email, &demo_password)
        .await
        .unwrap();

    assert!(session.user.email == demo_email)
}

#[tokio::test]
async fn test_login_with_email_invalid() {
    let auth_client = create_test_client();

    let demo_email = "invalid@demo.com";
    let demo_password = "invalid";

    match auth_client
        .login_with_email(demo_email, demo_password)
        .await
    {
        Err(Error::AuthError { message, .. }) => {
            assert!(message.contains("Invalid login credentials"));
        }
        other => panic!("Expected AuthError, got {:?}", other),
    }
}

#[tokio::test]
async fn sign_up_with_email_test_valid() {
    let auth_client = create_test_client();

    let uuid = uuid::Uuid::now_v7();

    let demo_email = format!("signup__{}@demo.com", uuid);
    let demo_password = "ciJUAojfZZYKfCxkiUWH";

    let data = serde_json::json!({
        "test": format!("test" ),
        "name": format!("test" )
    });

    let options = SignUpWithPasswordOptions {
        data: Some(data),
        email_redirect_to: Some("https://www.thisisnotarealdomain.com".to_string()),
        ..Default::default()
    };

    let result = auth_client
        .sign_up_with_email_and_password(demo_email.as_ref(), demo_password, Some(options))
        .await
        .unwrap();

    // Wait to prevent running into Supabase rate limits when running cargo test
    let one_minute = time::Duration::from_secs(60);
    thread::sleep(one_minute);

    if let EmailSignUpResult::SessionResult(session) = result {
        assert!(session.user.email == demo_email);
        assert!(session.user.user_metadata.name.unwrap() == "test");
        assert!(
            session
                .user
                .user_metadata
                .custom
                .get("test")
                .unwrap()
                .as_str()
                .unwrap()
                == "test"
        )
    }
}

#[tokio::test]
async fn send_login_email_with_magic_link() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_EMAIL").unwrap();

    let response = auth_client
        .send_login_email_with_magic_link(&demo_email)
        .await;

    if response.is_err() {
        eprintln!("{:?}", response.as_ref().unwrap_err())
    }

    // Wait to prevent running into Supabase rate limits when running cargo test
    let one_minute = time::Duration::from_secs(60);
    thread::sleep(one_minute);

    assert!(response.is_ok())
}

#[tokio::test]
async fn send_email_with_otp() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_EMAIL").unwrap();

    let data = serde_json::json!({
        "otp": format!("test" )
    });

    let options = LoginEmailOtpParams {
        data: Some(data),
        ..Default::default()
    };

    let response = auth_client
        .send_email_with_otp(&demo_email, Some(options))
        .await;

    if response.is_err() {
        eprintln!("{:?}", response.as_ref().unwrap_err())
    }

    // Wait to prevent running into Supabase rate limits when running cargo test
    let one_minute = time::Duration::from_secs(60);
    thread::sleep(one_minute);

    assert!(response.is_ok())
}

#[test]
fn login_with_oauth_test() {
    let auth_client = create_test_client();

    let mut params = HashMap::new();
    params.insert("key".to_string(), "value".to_string());
    params.insert("second_key".to_string(), "second_value".to_string());
    params.insert("third_key".to_string(), "third_value".to_string());

    let options = LoginWithOAuthOptions {
        query_params: Some(params),
        redirect_to: Some("localhost".to_string()),
        scopes: Some("repo gist notifications".to_string()),
        skip_brower_redirect: Some(true),
    };

    let response =
        auth_client.login_with_oauth(supabase_auth::models::Provider::Github, Some(options));

    if response.is_err() {
        println!("SIGN IN WITH OAUTH TEST RESPONSE -- \n{:?}", response);
    }

    assert!(response.unwrap().url.to_string().len() > 1);
}

#[ignore]
#[test]
fn sign_up_with_oauth_test() {
    let auth_client = create_test_client();

    let mut params = HashMap::new();
    params.insert("key".to_string(), "value".to_string());
    params.insert("second_key".to_string(), "second_value".to_string());
    params.insert("third_key".to_string(), "third_value".to_string());

    let options = LoginWithOAuthOptions {
        query_params: Some(params),
        redirect_to: Some("localhost".to_string()),
        scopes: Some("repo gist notifications".to_string()),
        skip_brower_redirect: Some(true),
    };

    let response =
        auth_client.sign_up_with_oauth(supabase_auth::models::Provider::Github, Some(options));

    if response.is_err() {
        println!("SIGN IN WITH OAUTH TEST RESPONSE -- \n{:?}", response);
    }

    assert!(response.unwrap().url.to_string().len() > 1);
}

#[test]
fn login_with_oauth_no_options_test() {
    let auth_client = create_test_client();

    // // Must login to get a user bearer token
    // let demo_email = env::var("DEMO_EMAIL").unwrap();
    // let demo_password = env::var("DEMO_PASSWORD").unwrap();
    //
    // let session = auth_client
    //     .login_with_email(demo_email, demo_password)
    //     .await;
    //
    // if session.is_err() {
    //     eprintln!("{:?}", session.as_ref().unwrap_err())
    // }

    let response = auth_client.login_with_oauth(supabase_auth::models::Provider::Github, None);

    println!(
        "SIGN IN WITH OAUTH \n NO OPTIONS TEST RESPONSE -- \n{:?}",
        response
    );

    if response.is_err() {
        eprintln!("{:?}", response.as_ref().unwrap_err())
    }

    assert!(response.is_ok())
}

#[tokio::test]
async fn get_user_test() {
    let auth_client = create_test_client();

    // Must login to get a user bearer token
    let demo_email = env::var("DEMO_EMAIL").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();

    let session = auth_client
        .login_with_email(&demo_email, &demo_password)
        .await;

    if session.is_err() {
        eprintln!("{:?}", session.as_ref().unwrap_err())
    }

    let user = auth_client
        .get_user(&session.unwrap().access_token)
        .await
        .unwrap();

    assert!(user.email == demo_email)
}

#[tokio::test]
async fn update_user_test() {
    let auth_client = create_test_client();

    // Must login to get a user bearer token
    let demo_email = env::var("DEMO_EMAIL").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();
    let uuid = uuid::Uuid::now_v7();

    let session = auth_client
        .login_with_email(&demo_email, &demo_password)
        .await
        .unwrap();

    let data = serde_json::json!({
        "update_user": format!("{}" ,uuid),
    });

    let updated_user = UpdatedUser {
        email: Some(demo_email.clone()),
        password: Some("qqqqwwww".to_string()),
        data: Some(data),
    };

    let first_response = auth_client
        .update_user(updated_user, &session.access_token)
        .await;

    if first_response.is_err() {
        eprintln!("{:?}", first_response.as_ref().unwrap_err())
    }

    // Login with new password to validate the change
    let test_password = "qqqqwwww";

    // Validate that user_metadata has changed
    assert!(
        first_response
            .unwrap()
            .user_metadata
            .custom
            .get("update_user")
            .unwrap()
            .as_str()
            .unwrap()
            == format!("{}", uuid)
    );

    let new_session = auth_client
        .login_with_email(demo_email.as_ref(), test_password)
        .await;

    if new_session.is_err() {
        eprintln!("{:?}", new_session.as_ref().unwrap_err())
    }

    // Return the user to original condition
    let original_user = UpdatedUser {
        email: Some(demo_email),
        password: Some("qwerqwer".to_string()),
        data: None,
    };

    let second_response = auth_client
        .update_user(original_user, &new_session.unwrap().access_token)
        .await;

    assert!(second_response.is_ok())
}

#[tokio::test]
async fn exchange_token_for_session() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_EMAIL").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();

    let original_session = auth_client
        .login_with_email(&demo_email, &demo_password)
        .await
        .unwrap();

    assert!(original_session.user.email == demo_email);

    let new_session = auth_client
        .refresh_session(&original_session.refresh_token)
        .await
        .unwrap();

    assert!(new_session.user.email == demo_email)
}

#[tokio::test]
async fn reset_password_for_email_test() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_EMAIL").unwrap();

    let options = ResetPasswordOptions {
        email_redirect_to: Some("https://www.thisisnotarealdomain.com".to_string()),
        ..Default::default()
    };

    let response = auth_client
        .reset_password_for_email(&demo_email, Some(options))
        .await;

    // Wait to prevent running into Supabase rate limits when running cargo test
    let one_minute = time::Duration::from_secs(60);
    thread::sleep(one_minute);

    assert!(response.is_ok())
}

#[tokio::test]
async fn resend_email_test() {
    let auth_client = create_test_client();

    let uuid = uuid::Uuid::now_v7();

    let demo_email = format!("signup__{}@demo.com", uuid);
    let demo_password = "ciJUAojfZZYKfCxkiUWH";

    let result = auth_client
        .sign_up_with_email_and_password(&demo_email, demo_password, None)
        .await;

    if result.is_err() {
        eprintln!("{:?}", result.as_ref().unwrap_err())
    }

    let credentials = ResendParams {
        otp_type: supabase_auth::models::OtpType::Signup,
        email: demo_email.to_owned(),
        options: None,
    };

    // Wait to prevent running into Supabase rate limits when running cargo test
    let one_minute = time::Duration::from_secs(60);
    thread::sleep(one_minute);

    let response = auth_client.resend(credentials).await;

    if response.is_err() {
        println!("{:?}", response)
    }

    match result.unwrap() {
        EmailSignUpResult::SessionResult(session) => {
            assert!(response.is_ok() && session.user.email == demo_email)
        }
        EmailSignUpResult::ConfirmationResult(email_sign_up_confirmation) => {
            assert!(response.is_ok() && email_sign_up_confirmation.email.unwrap() == demo_email)
        }
    }
}

#[tokio::test]
async fn logout_test() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_EMAIL").unwrap();
    let demo_password = env::var("DEMO_PASSWORD").unwrap();

    let session = auth_client
        .login_with_email(&demo_email, &demo_password)
        .await
        .unwrap();

    let logout = auth_client
        .logout(Some(LogoutScope::Global), &session.access_token)
        .await;

    if logout.is_err() {
        println!("{:?}", logout)
    }

    assert!(logout.is_ok())
}

#[tokio::test]
#[ignore = "SSO Requires Pro plan"]
async fn test_sso_login() {
    let auth_client = create_test_client();
    let demo_domain = env::var("DEMO_DOMAIN").unwrap();
    let params = LoginWithSSO {
        domain: Some(demo_domain),
        options: None,
        provider_id: None,
    };

    let url = auth_client.sso(params).await.unwrap();

    println!("{}", url);

    assert!(url.to_string().len() > 1);
}

#[tokio::test]
async fn invite_by_email_test() {
    let auth_client = create_test_client();

    let demo_email = env::var("DEMO_INVITE").unwrap();

    let user = auth_client
        // NOTE: Requires admin permissions to issue invites
        .invite_user_by_email(&demo_email, None, auth_client.api_key())
        .await
        .unwrap();

    assert!(user.email == demo_email)
}

#[tokio::test]
async fn login_anonymously_test() {
    let auth_client = create_test_client();

    let session = auth_client.login_anonymously(None).await.unwrap();

    println!("{}", session.user.created_at);

    assert!(!session.access_token.is_empty() && session.user.role == "authenticated")
}

#[tokio::test]
async fn get_settings_test() {
    let auth_client = create_test_client();

    let settings = auth_client.get_settings().await.unwrap();

    assert!(settings.external.github)
}

#[tokio::test]
async fn get_health_test() {
    let auth_client = create_test_client();

    let health = auth_client.get_health().await.unwrap();

    assert!(!health.description.is_empty())
}
