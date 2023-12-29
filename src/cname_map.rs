use hickory_resolver::proto::rr::RecordData;

use crate::{config::DomainConfig, Error};

pub(crate) struct CnameMapped<'a> {
    config: &'a crate::config::DomainConfig,
    cname: Option<String>,
}

impl CnameMapped<'_> {
    //    async fn cname_map<'a>(domain_config: &'a crate::config::DomainConfig) -> Self<'a> {}

    /// If hostname is a CNAME record, resolve it to canonial name
    async fn resolv_cname(hostname: &str) -> Result<Option<String>, Error> {
        /*
        let resolver = hickory_resolver::Resolver::from_system_conf()?;

        let records = resolver.txt_lookup(hostname)?;
        let cname_record = records.as_lookup().record_iter().filter_map(|record|
            record.data().and_then(|rdata| hickory_resolver::proto::rr::rdata::CNAME::try_borrow(rdata))
        ).last();
        let txt_record = records.as_lookup().record_iter().find_map(|record|
            record.data().and_then(|rdata| hickory_resolver::proto::rr::rdata::TXT::try_borrow(rdata)));
            */
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hickory_cname_txt() {
        let resolver = hickory_resolver::Resolver::from_system_conf().unwrap();

        let records = resolver
            .txt_lookup("efcs4kiwgez5q6d7nhj6jx2dyn2hqgz4._domainkey.amazon.co.jp")
            .unwrap();
        for record in records.as_lookup().record_iter() {
            println!("{:?} : {:?}", record.record_type(), record.name());
            if let Some(rdata) = record.data() {
                use hickory_resolver::proto::rr::RecordData;
                if let Some(txt) = hickory_resolver::proto::rr::rdata::TXT::try_borrow(rdata) {
                    for txt_data in txt.iter() {
                        println!("TXT value: {:?}", std::str::from_utf8(txt_data));
                    }
                }
            }
        }
    }

    #[test]
    fn cname_not_exist() {
        use hickory_resolver::proto::rr::rdata;
        let resolver = hickory_resolver::Resolver::from_system_conf().unwrap();

        let records = resolver
            .txt_lookup("acme-client-test-cname-exist.hanabusa.info")
            .unwrap();

        let cname_record = records
            .as_lookup()
            .record_iter()
            .filter_map(|record| {
                record
                    .data()
                    .and_then(|rdata| rdata::CNAME::try_borrow(rdata))
                    .map(|cname| (record.name(), cname))
            })
            .last();
        println!("CNAME {:?}", cname_record);

        let txt_record = records.as_lookup().record_iter().find_map(|record| {
            record
                .data()
                .and_then(|rdata| rdata::TXT::try_borrow(rdata))
                .map(|txt| (record.name(), txt))
        });
        println!("TXT {:?}", txt_record);
    }
}
