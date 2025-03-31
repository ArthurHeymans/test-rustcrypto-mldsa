mod cert_rustcrypto;
mod code_gen;
mod csr_rustcrypto;
mod tbs;

fn main() {
    // Call the test function directly
    //    test_gen_mldsa87_cert_template();
    //    test_gen_fmc_alias_cert_template();
}

#[test]
fn test_gen_init_devid_csr_mldsa87() {
    use crate::code_gen::CodeGen;
    use crate::csr_rustcrypto::CsrTemplateBuilder;
    use ml_dsa::MlDsa87;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

    // Create a temporary directory for output
    let temp_dir = std::env::temp_dir();
    let out_dir = temp_dir.to_str().unwrap();

    // Set up key usage for certificate signing
    let key_usage = KeyUsage(KeyUsages::KeyCertSign.into());

    // Create the CSR template builder with ML-DSA-87
    let bldr = CsrTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_ueid_ext(&[0xFF; 17])
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(key_usage);

    // Generate the template with a subject name
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 IDevID");

    // Generate code from the template
    CodeGen::gen_code("InitDevIdCsrTbsMlDsa87", template, out_dir);
}

#[test]
fn test_gen_fmc_alias_csr_mldsa87() {
    use crate::code_gen::CodeGen;
    use crate::csr_rustcrypto::CsrTemplateBuilder;
    use ml_dsa::MlDsa87;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

    // Create a temporary directory for output
    let temp_dir = std::env::temp_dir();
    let out_dir = temp_dir.to_str().unwrap();

    // Set up key usage for certificate signing
    let key_usage = KeyUsage(KeyUsages::KeyCertSign.into());

    // Create the CSR template builder with ML-DSA-87
    let bldr = CsrTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_ueid_ext(&[0xFF; 17])
        .add_basic_constraints_ext(true, 5)
        .add_key_usage_ext(key_usage);

    // Generate the template with a subject name
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 FMC Alias");

    // Generate code from the template
    CodeGen::gen_code("FmcAliasTbsMlDsa87", template, out_dir);
}

#[test]
fn test_gen_local_devid_cert_mldsa87() {
    use crate::cert_rustcrypto::CertTemplateBuilder;
    use crate::code_gen::CodeGen;
    use ml_dsa::MlDsa87;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

    // Create a temporary directory for output
    let temp_dir = std::env::temp_dir();
    let out_dir = temp_dir.to_str().unwrap();

    // Create KeyUsage with key_cert_sign set to true
    let key_usage = KeyUsage(KeyUsages::KeyCertSign.into());

    // Build the FMC Alias certificate template
    let bldr = CertTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_basic_constraints_ext(true, 3)
        .add_key_usage_ext(key_usage)
        .add_ueid_ext(&[0xFF; 17]);

    // Generate the template with subject and issuer CN
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 LDevID", "Caliptra 2.0 MlDsa87 IDevID");

    // Generate the code
    CodeGen::gen_code("LocalDevIdCsrTbsMlDsa87", template, out_dir);
}

#[test]
fn test_gen_fmc_alias_cert_mldsa87() {
    use crate::cert_rustcrypto::{CertTemplateBuilder, Fwid, FwidParam};
    use crate::code_gen::CodeGen;
    use const_oid::ObjectIdentifier;
    use ml_dsa::MlDsa87;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

    // Create a temporary directory for output
    let temp_dir = std::env::temp_dir();
    let out_dir = temp_dir.to_str().unwrap();

    // Create KeyUsage with key_cert_sign set to true
    let key_usage = KeyUsage(KeyUsages::KeyCertSign.into());

    // SHA-384 OID
    let sha384_oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

    // Create long-lived FWID parameters
    let device_fwids = [FwidParam {
        name: "TCB_INFO_DEVICE_INFO_HASH",
        fwid: Fwid {
            hash_alg: sha384_oid.clone(),
            digest: &[0xEF; 48],
        },
    }];

    let fmc_fwids = [FwidParam {
        name: "TCB_INFO_FMC_TCI",
        fwid: Fwid {
            hash_alg: sha384_oid,
            digest: &[0xCD; 48],
        },
    }];

    // Build the FMC Alias certificate template with TCB info
    let bldr = CertTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_basic_constraints_ext(true, 3)
        .add_key_usage_ext(key_usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_fmc_dice_tcb_info_ext(
            /*device_fwids=*/
            &device_fwids,
            /*fmc_fwids=*/
            &fmc_fwids,
        );

    // Generate the template with subject and issuer CN
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 FMC Alias", "Caliptra 2.0 MlDsa87 LDevID");

    // Generate the code
    CodeGen::gen_code("FmcAliasCertTbsMldDsa87", template, out_dir);
}

#[test]
fn test_gen_rt_alias_cert_mldsa87() {
    use crate::cert_rustcrypto::{CertTemplateBuilder, Fwid, FwidParam};
    use crate::code_gen::CodeGen;
    use const_oid::ObjectIdentifier;
    use ml_dsa::MlDsa87;
    use x509_cert::ext::pkix::{KeyUsage, KeyUsages};

    // Create a temporary directory for output
    let temp_dir = std::env::temp_dir();
    let out_dir = temp_dir.to_str().unwrap();

    // Create KeyUsage with key_cert_sign set to true and digital_signature set to true
    let key_usage = KeyUsage((KeyUsages::KeyCertSign | KeyUsages::DigitalSignature).into());

    // SHA-384 OID
    let sha384_oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");

    // Create RT FWID parameter
    let rt_fwids = [FwidParam {
        name: "TCB_INFO_RT_TCI",
        fwid: Fwid {
            hash_alg: sha384_oid,
            digest: &[0xCD; 48],
        },
    }];

    // Build the RT Alias certificate template with TCB info
    let bldr = CertTemplateBuilder::<ml_dsa::KeyPair<MlDsa87>>::new()
        .add_basic_constraints_ext(true, 2)
        .add_key_usage_ext(key_usage)
        .add_ueid_ext(&[0xFF; 17])
        .add_rt_dice_tcb_info_ext(0xC4, &rt_fwids);

    // Generate the template with subject and issuer CN
    let template = bldr.tbs_template("Caliptra 2.0 MlDsa87 RT Alias", "Caliptra 2.0 MlDsa87 FMC Alias");

    // Generate the code
    CodeGen::gen_code("RtAliasCertTbsMlDsa87", template, out_dir);
}

