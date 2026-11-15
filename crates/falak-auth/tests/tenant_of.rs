use falak_auth::identity::tenant_of;

#[test]
fn a_users_tenant_is_stable_distinct_and_a_uuid() {
    let a = tenant_of("00000000-0000-0000-0000-00000000000a");
    assert_eq!(a, tenant_of("00000000-0000-0000-0000-00000000000a"));
    assert_ne!(a, tenant_of("00000000-0000-0000-0000-00000000000b"));
    assert_eq!(a.len(), 36);
    assert!(a.bytes().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => c == b'-',
        _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
    }));
    // It is not the user id, so one cannot be guessed from the other.
    assert_ne!(a, "00000000-0000-0000-0000-00000000000a");
}
