use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use minijinja::render;
use rmcp::transport::auth::OAuthState;
use rmcp::transport::AuthorizationManager;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tracing::warn;

use crate::oauth::persist::{load_cached_state, save_credentials};

pub use persist::clear_credentials;

pub mod persist;

const CALLBACK_TEMPLATE: &str = include_str!("oauth_callback.html");

#[derive(Clone)]
struct AppState {
    code_receiver: Arc<Mutex<Option<oneshot::Sender<String>>>>,
}

#[derive(Debug, Deserialize)]
struct CallbackParams {
    code: String,
    #[allow(dead_code)]
    state: Option<String>,
}

pub async fn oauth_flow(
    mcp_server_url: &str,
    name: &str,
) -> Result<AuthorizationManager, anyhow::Error> {
    if let Ok(oauth_state) = load_cached_state(mcp_server_url, name).await {
        if let Some(authorization_manager) = oauth_state.into_authorization_manager() {
            match authorization_manager.refresh_token().await {
                Ok(_) => {
                    return Ok(authorization_manager);
                }
                Err(e) => {
                    tracing::warn!("Failed to refresh OAuth token for '{}': {}", name, e);
                }
            }
        }

        if let Err(e) = crate::oauth::persist::clear_credentials(name) {
            warn!("error clearing bad credentials: {}", e);
        }
    }

    let (code_sender, code_receiver) = oneshot::channel::<String>();
    let app_state = AppState {
        code_receiver: Arc::new(Mutex::new(Some(code_sender))),
    };

    let rendered = render!(CALLBACK_TEMPLATE, name => name);
    let handler = move |Query(params): Query<CallbackParams>, State(state): State<AppState>| {
        let rendered = rendered.clone();
        async move {
            if let Some(sender) = state.code_receiver.lock().await.take() {
                let _ = sender.send(params.code);
            }
            Html(rendered)
        }
    };
    let app = Router::new()
        .route("/oauth_callback", get(handler))
        .with_state(app_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let used_addr = listener.local_addr()?;
    tokio::spawn(async move {
        let result = axum::serve(listener, app).await;
        if let Err(e) = result {
            eprintln!("Callback server error: {}", e);
        }
    });

    let mut oauth_state = OAuthState::new(mcp_server_url, None).await?;
    let redirect_uri = format!("http://localhost:{}/oauth_callback", used_addr.port());
    oauth_state
        .start_authorization(&[], redirect_uri.as_str())
        .await?;

    let authorization_url = oauth_state.get_authorization_url().await?;
    if webbrowser::open(authorization_url.as_str()).is_err() {
        eprintln!("Open the following URL to authorize {}:", name);
        eprintln!("  {}", authorization_url);
    }

    let auth_code = code_receiver.await?;
    oauth_state.handle_callback(&auth_code).await?;

    if let Err(e) = save_credentials(name, &oauth_state).await {
        warn!("Failed to save credentials: {}", e);
    }

    let auth_manager = oauth_state
        .into_authorization_manager()
        .ok_or_else(|| anyhow::anyhow!("Failed to get authorization manager"))?;

    Ok(auth_manager)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth::persist::clear_credentials;

    #[test]
    fn test_oauth_flow_function_signature() {
        // Test that oauth_flow function exists and accepts correct parameter types
        // This is a compile-time test to verify the function signature

        // The function should accept &str parameters, not &String
        // We just test that the function exists and can be referenced
        let _oauth_fn = oauth_flow;

        // This test ensures our API change from &String to &str works correctly
    }

    #[test]
    fn test_clear_credentials_function_exported() {
        // Test that clear_credentials function is properly exported
        // This ensures the function is accessible from the module's public interface

        // The function should exist and be callable
        let _: fn(&str) -> _ = clear_credentials;

        // This verifies the function is properly exported from persist module
    }

    #[test]
    fn test_oauth_module_exports() {
        // Test that the oauth module properly exports its public interface

        // Verify the clear_credentials function is re-exported
        let _ = clear_credentials; // Should compile

        // Verify oauth_flow function is exported
        let _ = oauth_flow; // Should compile

        // This test ensures the module structure changes work correctly
    }

    // Note: We don't test the actual OAuth flow functionality here as it requires
    // external dependencies (network, keychain, browser) that would make tests
    // non-deterministic and potentially interactive. The OAuth flow is tested
    // through integration tests in a controlled environment.
}
