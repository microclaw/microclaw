#![allow(unused_imports)]

use super::*;

pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::test_support::env_lock()
}
