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
