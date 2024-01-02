use crate::Error;

pub async fn new_account(
    config_file: &std::path::Path,
    endpoint: &str,
    contacts: impl Iterator<Item = &str>,
) -> Result<instant_acme::Account, Error> {
    use std::io::Write;

    // check if config already exists.
    if config_file.is_file() {
        return Err(Error::ConfigExists);
    }

    // Request ACME server to create new account
    let contacts_mailto = contacts
        .map(|ctct| format!("mailto:{}", ctct))
        .collect::<Vec<String>>();
    let contacts_str = contacts_mailto
        .iter()
        .map(|c| c.as_str())
        .collect::<Vec<&str>>();

    let (account, cred) = instant_acme::Account::create_with_http(
        &instant_acme::NewAccount {
            contact: &contacts_str,
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        endpoint,
        None,
        crate::http_client::HyperTlsClient::new_boxed(),
    )
    .await?;

    println!("Account created: {:?}", serde_json::to_string_pretty(&cred));

    let cfg = crate::config::Config::new_with_credentials(cred);
    let mut f = std::fs::File::create(config_file)?;

    #[cfg(unix)]
    {
        // set owner rw only
        use std::os::unix::fs::PermissionsExt;
        let mut perm = f.metadata()?.permissions();
        perm.set_mode(0o0600);
        f.set_permissions(perm)?;
    }

    // write to file
    let toml_str = toml::to_string_pretty(&cfg).unwrap();
    f.write_all(toml_str.as_bytes())?;

    Ok(account)
}
