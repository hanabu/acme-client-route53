#[test]
fn csr_decode_test() {
    let csr = acme_client_route53::X509Csr::from_pem_file("tests/example.csr").unwrap();
    let subjects = csr.subjects().collect::<Vec<_>>();

    assert_eq!(
        subjects.as_slice(),
        ["www.example.com", "alt1.example.com", "alt2.example.com",]
    );
}
