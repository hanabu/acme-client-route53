use crate::Error;

pub async fn write_crt(
    crt_file_name: &str,
    certificate: &crate::AcmeIssuedCertificate,
    aws_sdk_config: &aws_config::SdkConfig,
) -> Result<(), Error> {
    let crt_bytes = certificate.server_certificate_pem().into_bytes();

    if let Ok(url) = url::Url::parse(crt_file_name) {
        if url.scheme() == "s3" {
            write_crt_s3(&url, crt_bytes, aws_sdk_config).await
        } else {
            Err(Error::InvalidOutCrtFile(crt_file_name.to_string()))
        }
    } else {
        write_crt_localfile(crt_file_name, &crt_bytes)
    }
}

fn write_crt_localfile(crt_file_name: &str, crt_bytes: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    let mut f = std::fs::File::create(crt_file_name)?;
    f.write_all(crt_bytes)?;
    Ok(())
}

async fn write_crt_s3(
    crt_file_url: &url::Url,
    crt_bytes: Vec<u8>,
    aws_sdk_config: &aws_config::SdkConfig,
) -> Result<(), Error> {
    let bucket = crt_file_url
        .host_str()
        .ok_or_else(|| Error::InvalidOutCrtFile(crt_file_url.to_string()))?;
    let key = crt_file_url.path().trim_start_matches('/');

    let client = aws_sdk_s3::Client::new(aws_sdk_config);

    let _resp = client
        .put_object()
        .bucket(bucket)
        .key(key)
        .content_type("application/pem-certificate-chain")
        .body(crt_bytes.into())
        .send()
        .await?;

    Ok(())
}
