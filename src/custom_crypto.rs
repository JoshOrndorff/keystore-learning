//! Simple demonstration of creating application-specific crypto types.
//! This is all it takes to use `app_crypto!`.

use crate::COMMS;
use sp_application_crypto::{app_crypto, sr25519};

// Declare our strongly typed custom crypto wrapper that just wraps sr25519 under the hood.
app_crypto!(sr25519, COMMS);