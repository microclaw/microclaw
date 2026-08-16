#![allow(unused_imports)]

pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::test_support::env_lock()
}
