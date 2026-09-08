use age_plugin_phone_protocol::{FileReplayGuard, ReplayRole, ReplayScope, ReplayStore};
fn main() {
    let root = std::path::Path::new("/tmp/age-refactor-baseline");
    let mut requests = FileReplayGuard::create(root.join("requests.cbor"), ReplayScope::new(ReplayRole::PhoneRequests, [1;16], [2;16]), 4, 100).unwrap();
    requests.consume_request([1;16], [2;16], [3;16], [4;32], 200, 110).unwrap();
    let mut responses = FileReplayGuard::create(root.join("responses.cbor"), ReplayScope::new(ReplayRole::DesktopResponses, [1;16], [2;16]), 4, 100).unwrap();
    responses.consume_response([1;16], [2;16], [5;32], 200, 110).unwrap();
}
