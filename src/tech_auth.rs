//! Autenticación de técnico por firma Ed25519.
//!
//! Idea: el cliente instalado en la PC del cliente (lado que RECIBE la conexión)
//! solo acepta sesiones que traigan una firma válida hecha con la clave privada
//! del técnico. En el cliente solo vive la clave PÚBLICA, así que no hay ningún
//! secreto para robar: conocer el DNS, la clave del servidor o tener un
//! RustDesk común no sirve para entrar.
//!
//! - Se activa en tiempo de compilación definiendo la variable de entorno
//!   `TECH_PUBKEY` (base64, la imprime `tech-keygen`). Sin ella, este módulo
//!   queda desactivado y el cliente se comporta como el original.
//! - La clave privada vive en un archivo cifrado con contraseña (Argon2id +
//!   XSalsa20-Poly1305) que se guarda en el pendrive del técnico.
//!
//! Este archivo depende solo de `sodiumoxide` y `std`, para poder probarse solo.

use sodiumoxide::crypto::{
    pwhash::argon2id13 as pwhash,
    secretbox,
    sign::{self, PublicKey, SecretKey, Signature},
};

/// Clave pública del técnico, fijada al compilar. `None` = módulo desactivado.
pub const TECH_PUBKEY_B64: Option<&str> = option_env!("TECH_PUBKEY");

const DOMAIN: &[u8] = b"rustdesk-tech-auth-v1";
const SIG_LEN: usize = sign::SIGNATUREBYTES;

/// Largo mínimo del desafío para aceptar la firma (el original usa 6 y es corto).
pub const MIN_CHALLENGE_LEN: usize = 24;

/// ¿Está activada la verificación en este build?
pub fn enabled() -> bool {
    configured_pubkey().is_some()
}

/// Clave pública embebida, ya decodificada.
pub fn configured_pubkey() -> Option<PublicKey> {
    let b64 = TECH_PUBKEY_B64?.trim();
    if b64.is_empty() {
        return None;
    }
    pubkey_from_b64(b64)
}

pub fn pubkey_from_b64(b64: &str) -> Option<PublicKey> {
    let bytes = sodiumoxide::base64::decode(b64.trim(), sodiumoxide::base64::Variant::Original)
        .ok()?;
    PublicKey::from_slice(&bytes)
}

pub fn pubkey_to_b64(pk: &PublicKey) -> String {
    sodiumoxide::base64::encode(pk.0, sodiumoxide::base64::Variant::Original)
}

/// Mensaje que se firma. Incluye el desafío (aleatorio, lo genera el equipo
/// que recibe), la sal, el ID del equipo destino y el ID de quien se conecta,
/// con separadores de largo fijo para que no haya ambigüedad.
fn auth_message(challenge: &str, salt: &str, target_id: &str, controller_id: &str) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(DOMAIN);
    for part in [challenge, salt, target_id, controller_id] {
        m.extend_from_slice(&(part.len() as u32).to_le_bytes());
        m.extend_from_slice(part.as_bytes());
    }
    m
}

/// Lado técnico: firma el desafío recibido.
pub fn sign_login(
    sk: &SecretKey,
    challenge: &str,
    salt: &str,
    target_id: &str,
    controller_id: &str,
) -> Vec<u8> {
    let msg = auth_message(challenge, salt, target_id, controller_id);
    sign::sign_detached(&msg, sk).to_bytes().to_vec()
}

/// Lado cliente instalado: verifica la firma con la clave pública embebida.
pub fn verify_login(
    pk: &PublicKey,
    challenge: &str,
    salt: &str,
    target_id: &str,
    controller_id: &str,
    sig: &[u8],
) -> bool {
    if challenge.len() < MIN_CHALLENGE_LEN || sig.len() != SIG_LEN {
        return false;
    }
    let Ok(sig) = Signature::from_bytes(sig) else {
        return false;
    };
    let msg = auth_message(challenge, salt, target_id, controller_id);
    sign::verify_detached(&sig, &msg, pk)
}

/// Atajo para el cliente instalado: usa la clave embebida.
/// Si el módulo está desactivado devuelve `true` (comportamiento original).
pub fn verify_with_embedded_key(
    challenge: &str,
    salt: &str,
    target_id: &str,
    controller_id: &str,
    sig: &[u8],
) -> bool {
    match configured_pubkey() {
        None => true,
        Some(pk) => verify_login(&pk, challenge, salt, target_id, controller_id, sig),
    }
}

// ---------------------------------------------------------------------------
// Archivo de clave privada cifrado (para el pendrive del técnico)
// Formato: sal(32) | nonce(24) | texto cifrado
// ---------------------------------------------------------------------------

pub fn generate_keypair() -> (PublicKey, SecretKey) {
    sodiumoxide::init().ok();
    sign::gen_keypair()
}

pub fn encrypt_secret(sk: &SecretKey, passphrase: &str) -> Option<Vec<u8>> {
    sodiumoxide::init().ok()?;
    if passphrase.len() < 10 {
        return None; // contraseña demasiado corta
    }
    let salt = pwhash::gen_salt();
    let key = derive_key(passphrase, &salt)?;
    let nonce = secretbox::gen_nonce();
    let ct = secretbox::seal(&sk.0, &nonce, &key);
    let mut out = Vec::with_capacity(salt.0.len() + nonce.0.len() + ct.len());
    out.extend_from_slice(&salt.0);
    out.extend_from_slice(&nonce.0);
    out.extend_from_slice(&ct);
    Some(out)
}

pub fn decrypt_secret(blob: &[u8], passphrase: &str) -> Option<SecretKey> {
    sodiumoxide::init().ok()?;
    let sl = pwhash::SALTBYTES;
    let nl = secretbox::NONCEBYTES;
    if blob.len() <= sl + nl {
        return None;
    }
    let salt = pwhash::Salt::from_slice(&blob[..sl])?;
    let nonce = secretbox::Nonce::from_slice(&blob[sl..sl + nl])?;
    let key = derive_key(passphrase, &salt)?;
    let pt = secretbox::open(&blob[sl + nl..], &nonce, &key).ok()?;
    SecretKey::from_slice(&pt)
}

fn derive_key(passphrase: &str, salt: &pwhash::Salt) -> Option<secretbox::Key> {
    let mut k = secretbox::Key([0u8; secretbox::KEYBYTES]);
    pwhash::derive_key(
        &mut k.0,
        passphrase.as_bytes(),
        salt,
        pwhash::OPSLIMIT_MODERATE,
        pwhash::MEMLIMIT_MODERATE,
    )
    .ok()?;
    Some(k)
}


// ---------------------------------------------------------------------------
// Lado técnico: carga de la clave privada desde el pendrive
// ---------------------------------------------------------------------------

use std::sync::OnceLock;

static TECH_KEY: OnceLock<Option<SecretKey>> = OnceLock::new();

/// Lee y descifra el archivo de clave. Devuelve `None` si algo falla.
pub fn load_key_file(path: &str, passphrase: &str) -> Option<SecretKey> {
    let blob = std::fs::read(path).ok()?;
    decrypt_secret(&blob, passphrase)
}

/// Clave del técnico, cargada UNA vez desde las variables de entorno
/// `TECH_KEY_FILE` (ruta al archivo en el pendrive) y `TECH_KEY_PASS`
/// (contraseña). La contraseña se borra del entorno apenas se lee.
/// Sin estas variables (equipos de clientes) devuelve `None`: ese equipo
/// no puede firmar, por lo tanto no puede conectarse a otros equipos protegidos.
pub fn technician_key() -> Option<&'static SecretKey> {
    TECH_KEY
        .get_or_init(|| {
            let path = std::env::var("TECH_KEY_FILE").ok()?;
            let pass = std::env::var("TECH_KEY_PASS").ok()?;
            std::env::remove_var("TECH_KEY_PASS");
            load_key_file(&path, &pass)
        })
        .as_ref()
}

/// Firma para un login saliente. Vacío si este equipo no tiene la clave.
pub fn sign_for_login(
    challenge: &str,
    salt: &str,
    target_id: &str,
    controller_id: &str,
) -> Vec<u8> {
    match technician_key() {
        Some(sk) => sign_login(sk, challenge, salt, target_id, controller_id),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CH: &str = "abcdefghijklmnopqrstuvwxyzABCDEF"; // 32

    fn setup() -> (PublicKey, SecretKey) {
        generate_keypair()
    }

    #[test]
    fn firma_valida_pasa() {
        let (pk, sk) = setup();
        let sig = sign_login(&sk, CH, "salt1", "123456789", "987654321");
        assert!(verify_login(&pk, CH, "salt1", "123456789", "987654321", &sig));
    }

    #[test]
    fn otro_desafio_falla() {
        let (pk, sk) = setup();
        let sig = sign_login(&sk, CH, "salt1", "123456789", "987654321");
        let otro = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
        assert!(!verify_login(&pk, otro, "salt1", "123456789", "987654321", &sig));
    }

    #[test]
    fn otro_destino_falla() {
        // una firma hecha para la PC A no sirve en la PC B
        let (pk, sk) = setup();
        let sig = sign_login(&sk, CH, "salt1", "123456789", "987654321");
        assert!(!verify_login(&pk, CH, "salt1", "111111111", "987654321", &sig));
    }

    #[test]
    fn otro_controlador_falla() {
        let (pk, sk) = setup();
        let sig = sign_login(&sk, CH, "salt1", "123456789", "987654321");
        assert!(!verify_login(&pk, CH, "salt1", "123456789", "555555555", &sig));
    }

    #[test]
    fn otra_sal_falla() {
        let (pk, sk) = setup();
        let sig = sign_login(&sk, CH, "salt1", "123456789", "987654321");
        assert!(!verify_login(&pk, CH, "salt2", "123456789", "987654321", &sig));
    }

    #[test]
    fn clave_ajena_falla() {
        let (pk, _) = setup();
        let (_, sk_atacante) = setup();
        let sig = sign_login(&sk_atacante, CH, "salt1", "1", "2");
        assert!(!verify_login(&pk, CH, "salt1", "1", "2", &sig));
    }

    #[test]
    fn firma_vacia_o_corrupta_falla() {
        let (pk, sk) = setup();
        assert!(!verify_login(&pk, CH, "s", "1", "2", &[]));
        assert!(!verify_login(&pk, CH, "s", "1", "2", &[0u8; 64]));
        let mut sig = sign_login(&sk, CH, "s", "1", "2");
        sig[10] ^= 1;
        assert!(!verify_login(&pk, CH, "s", "1", "2", &sig));
        sig.truncate(63);
        assert!(!verify_login(&pk, CH, "s", "1", "2", &sig));
    }

    #[test]
    fn desafio_corto_se_rechaza_aunque_la_firma_sea_buena() {
        let (pk, sk) = setup();
        let corto = "abc123"; // el desafío original de 6 caracteres
        let sig = sign_login(&sk, corto, "s", "1", "2");
        assert!(!verify_login(&pk, corto, "s", "1", "2", &sig));
    }

    #[test]
    fn campos_no_se_pueden_mover_entre_si() {
        // ("ab","c") y ("a","bc") no deben dar el mismo mensaje
        let (pk, sk) = setup();
        let sig = sign_login(&sk, CH, "ab", "c", "x");
        assert!(!verify_login(&pk, CH, "a", "bc", "x", &sig));
    }

    #[test]
    fn archivo_de_clave_ida_y_vuelta() {
        let (pk, sk) = setup();
        let blob = encrypt_secret(&sk, "una-contraseña-larga").unwrap();
        let sk2 = decrypt_secret(&blob, "una-contraseña-larga").unwrap();
        let sig = sign_login(&sk2, CH, "s", "1", "2");
        assert!(verify_login(&pk, CH, "s", "1", "2", &sig));
    }

    #[test]
    fn archivo_de_clave_contrasena_incorrecta_falla() {
        let (_, sk) = setup();
        let blob = encrypt_secret(&sk, "una-contraseña-larga").unwrap();
        assert!(decrypt_secret(&blob, "otra-contraseña-larga").is_none());
    }

    #[test]
    fn archivo_de_clave_alterado_falla() {
        let (_, sk) = setup();
        let mut blob = encrypt_secret(&sk, "una-contraseña-larga").unwrap();
        let n = blob.len();
        blob[n - 1] ^= 1;
        assert!(decrypt_secret(&blob, "una-contraseña-larga").is_none());
    }

    #[test]
    fn carga_desde_archivo() {
        let (pk, sk) = setup();
        let blob = encrypt_secret(&sk, "una-contraseña-larga").unwrap();
        let path = std::env::temp_dir().join("tech_auth_test_key.enc");
        std::fs::write(&path, &blob).unwrap();
        let p = path.to_str().unwrap();
        let sk2 = load_key_file(p, "una-contraseña-larga").unwrap();
        let sig = sign_login(&sk2, CH, "s", "1", "2");
        assert!(verify_login(&pk, CH, "s", "1", "2", &sig));
        assert!(load_key_file(p, "mala-contraseña-larga").is_none());
        assert!(load_key_file("/no/existe.enc", "x").is_none());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn contrasena_corta_se_rechaza() {
        let (_, sk) = setup();
        assert!(encrypt_secret(&sk, "corta").is_none());
    }

    #[test]
    fn pubkey_base64_ida_y_vuelta() {
        let (pk, _) = setup();
        let s = pubkey_to_b64(&pk);
        assert_eq!(pubkey_from_b64(&s).unwrap(), pk);
        assert!(pubkey_from_b64("basura").is_none());
    }

    #[test]
    fn sin_clave_embebida_esta_desactivado() {
        // en los tests no se define TECH_PUBKEY
        if TECH_PUBKEY_B64.is_none() {
            assert!(!enabled());
            assert!(verify_with_embedded_key("x", "x", "x", "x", &[]));
        }
    }
}
