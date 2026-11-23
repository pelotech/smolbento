//! A machine CA with no name constraint, for a machine whose decrypted hosts change while it runs.

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use smolvm_credentials::MachineCa;

/// A fresh CA for `machine` that can sign a leaf for any host. The interceptor still decrypts only its
/// `terminate_hosts`; this CA just never stops a newly ruled host from being one. `MachineCa::generate` always
/// name-constrains, so it is minted here and brought in through `MachineCa::import`, with no permitted hosts (which
/// the interceptor takes as covering every host).
pub fn broad_ca(machine: &str) -> Result<MachineCa> {
    let key = KeyPair::generate().context("generate CA key")?;
    // Subject and validity as smolvm-credentials' own `ca_params`: loading rebuilds the issuer from it, so a
    // different subject would issue leaves the guest can't chain.
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let mut dn = DistinguishedName::new();
    dn.push(DnType::OrganizationName, "smolvm machine credentials");
    dn.push(
        DnType::CommonName,
        format!("smolvm {machine} credential CA"),
    );
    params.distinguished_name = dn;
    params.not_before = rcgen::date_time_ymd(2024, 1, 1);
    params.not_after = rcgen::date_time_ymd(2099, 1, 1);
    let cert = params.self_signed(&key).context("self-sign CA")?;
    let document = zeroize::Zeroizing::new(
        serde_json::json!({
            "name": machine,
            "certificate": cert.pem(),
            "permitted": [],
            "key": *zeroize::Zeroizing::new(key.serialize_pem()),
        })
        .to_string(),
    );
    MachineCa::import(&document)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
    use smolvm_credentials::{CredentialPolicy, Interceptor, InterceptorConfig, StaticResolver};
    use std::sync::Arc;

    /// The DER encoding of the NameConstraints extension's OID, 2.5.29.30.
    const NAME_CONSTRAINTS_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x1e];

    fn der(ca: &MachineCa) -> Vec<u8> {
        rustls_pemfile::certs(&mut ca.certificate_pem().as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .to_vec()
    }

    fn has_name_constraints(der: &[u8]) -> bool {
        der.windows(NAME_CONSTRAINTS_OID.len())
            .any(|w| w == NAME_CONSTRAINTS_OID)
    }

    #[test]
    fn broad_ca_has_no_name_constraints() {
        let constrained = MachineCa::generate("m", &["example.com".into()]).unwrap();
        assert!(
            has_name_constraints(&der(&constrained)),
            "the probe finds one"
        );
        assert!(!has_name_constraints(&der(&broad_ca("m").unwrap())));
    }

    #[test]
    fn broad_ca_can_issue_for_any_host() {
        let ca = broad_ca("m").unwrap();
        // The leaf it issues chains to the certificate the guest trusts.
        let (chain, _) = ca.issue_leaf("anything.example").unwrap();
        let root = CertificateDer::from(der(&ca));
        let anchors = [webpki::anchor_from_trusted_cert(&root).unwrap()];
        let leaf = webpki::EndEntityCert::try_from(&chain[0]).unwrap();
        leaf.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &[],
            UnixTime::now(),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .unwrap();
        leaf.verify_is_valid_for_subject_name(&ServerName::try_from("anything.example").unwrap())
            .unwrap();

        let config = InterceptorConfig {
            machine: "m".into(),
            policy: CredentialPolicy::default(),
            placeholders: Default::default(),
            ca,
            extra_cas: vec![],
            upstream_roots_pem: vec![],
            terminate_hosts: vec!["anything.example".into()],
            request_filter: None,
        };
        Interceptor::spawn(config, Arc::new(StaticResolver::new())).unwrap();
    }
}
