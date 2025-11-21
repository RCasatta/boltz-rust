use bitcoin::hex::FromHex;
use std::time::Duration;

pub mod ec;
pub mod fees;
#[cfg(feature = "lnurl")]
pub mod lnurl;
pub mod secrets;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use gloo_timers::future::TimeoutFuture;

use crate::error::Error;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
static INIT: std::sync::Once = std::sync::Once::new();

/// Setup function that will only run once, even if called multiple times.
pub fn setup_logger() {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    INIT.call_once(|| {
        env_logger::Builder::from_env(
            env_logger::Env::default()
                .default_filter_or("debug")
                .default_write_style_or("always"),
        )
        .filter_module("serial_test", log::LevelFilter::Error)
        // .is_test(true)
        .init();
    });
}

pub async fn sleep(duration: Duration) {
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    {
        tokio::time::sleep(duration).await;
    }
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    {
        let millis = duration.as_millis() as i32;
        let mut cb = |resolve: js_sys::Function, _reject: js_sys::Function| {
            web_sys::window()
                .unwrap()
                .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, millis)
                .unwrap();
        };
        let p = js_sys::Promise::new(&mut cb);
        wasm_bindgen_futures::JsFuture::from(p).await.unwrap();
    }
}

pub(crate) fn hex_to_bytes32(hex: &str) -> Result<[u8; 32], Error> {
    let bytes = Vec::from_hex(hex)?;
    if bytes.len() != 32 {
        return Err(Error::Protocol(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}
