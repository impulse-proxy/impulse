#[cfg(test)]
use std::any::Any;
use std::{
    panic::{self, PanicHookInfo},
    sync::{
        Once,
        atomic::{AtomicU64, Ordering},
    },
};

use log::error;

static PANIC_COUNT: AtomicU64 = AtomicU64::new(0);
static PANIC_HOOK_ONCE: Once = Once::new();

pub fn install_panic_hook() {
    PANIC_HOOK_ONCE.call_once(|| {
        let previous = panic::take_hook();
        panic::set_hook(Box::new(move |info| {
            PANIC_COUNT.fetch_add(1, Ordering::Relaxed);
            error!("panic captured: {}", format_panic_info(info));
            previous(info);
        }));
    });
}

pub fn panic_count() -> u64 {
    PANIC_COUNT.load(Ordering::Relaxed)
}

#[cfg(test)]
pub fn panic_payload_message(payload: &(dyn Any + Send + 'static)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "non-string panic payload".to_string()
}

fn format_panic_info(info: &PanicHookInfo<'_>) -> String {
    let location = info
        .location()
        .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
        .unwrap_or_else(|| "unknown-location".to_string());
    let message = panic_message(info);
    format!("{message} at {location}")
}

fn panic_message(info: &PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_string();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "panic with non-string payload".to_string()
}

#[cfg(test)]
mod tests {
    use super::panic_payload_message;

    #[test]
    fn panic_payload_message_supports_str_and_string() {
        let str_payload: Box<dyn std::any::Any + Send> = Box::new("panic-str");
        assert_eq!(panic_payload_message(str_payload.as_ref()), "panic-str");

        let string_payload: Box<dyn std::any::Any + Send> = Box::new("panic-string".to_string());
        assert_eq!(
            panic_payload_message(string_payload.as_ref()),
            "panic-string"
        );
    }

    #[test]
    fn panic_payload_message_handles_non_string_payload() {
        let int_payload: Box<dyn std::any::Any + Send> = Box::new(42_u64);
        assert_eq!(
            panic_payload_message(int_payload.as_ref()),
            "non-string panic payload"
        );
    }
}
