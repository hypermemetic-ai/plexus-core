//! MACRO-12 — the `auth` activation's parameters, as types.
//!
//! Every parameter of [`super::auth_activation`]'s methods is one of these
//! instead of a bare `String`, and the activation is compiled with
//! `#[plexus_macros::activation(typed_params)]`, so a bare string cannot come
//! back. Each type:
//!
//! - is validated once, at the wire: `Deserialize` goes through
//!   `TryFrom<String>`, so a bad value is `InvalidParams` naming the
//!   parameter (`role: `a.b` is not a role name …`) before the method runs;
//! - serializes as the same plain string it always was (`#[serde(transparent)]`),
//!   so the JSON on the wire does not change by a byte;
//! - is `$defs/<Name> { type: string }` behind a `$ref` in the schema (the
//!   shape ACCESS-6 / ACCESS-43 found synapse and hub-codegen read);
//! - has `Display`, `as_str()`, and no public field.
//!
//! The names are the parameters' own. They live in this module, not at
//! `plexus_core::plexus::*`, because `MethodPath`, `RoleName` and
//! `Principal` already name the identity layer's types there; reach them as
//! `plexus_core::plexus::auth_params::RoleName` and so on.

use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use plexus_auth_core::grants::{Grant, ScopeRef};
use plexus_auth_core::identity;

/// The common shape: a transparent `String` newtype whose `Deserialize`
/// goes through `TryFrom<String>`.
macro_rules! string_param {
    ($(#[$doc:meta])* $name:ident, $check:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// The text, as it goes on the wire.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume into the text.
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = String;
            fn try_from(text: String) -> Result<Self, String> {
                let check: fn(&str) -> Result<(), String> = $check;
                let trimmed = text.trim();
                check(trimmed)?;
                Ok(Self(trimmed.to_string()))
            }
        }

        impl TryFrom<&str> for $name {
            type Error = String;
            fn try_from(text: &str) -> Result<Self, String> {
                Self::try_from(text.to_string())
            }
        }

        impl std::str::FromStr for $name {
            type Err = String;
            fn from_str(text: &str) -> Result<Self, String> {
                Self::try_from(text.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Self::try_from(String::deserialize(d)?).map_err(serde::de::Error::custom)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

/// The longest name any of these accepts. Generous: it bounds a hostile
/// value, not a real one.
const MAX: usize = 512;

fn bounded(text: &str, what: &str) -> Result<(), String> {
    if text.is_empty() {
        return Err(format!("an empty {what}"));
    }
    if text.len() > MAX {
        return Err(format!("{what} longer than {MAX} bytes"));
    }
    if text.chars().any(char::is_control) {
        return Err(format!("`{}` holds a control character: not a {what}", text.escape_debug()));
    }
    Ok(())
}

fn word(text: &str, what: &str, shape: &str) -> Result<(), String> {
    bounded(text, what)?;
    if text.chars().any(char::is_whitespace) {
        return Err(format!("`{text}` is not a {what} ({shape})"));
    }
    Ok(())
}

string_param!(
    /// A method, as `<activation>.<method>` — `tickets.set_status`. Two
    /// or more dot-separated segments, none empty, no whitespace.
    MethodPath,
    |t| {
        word(t, "method path", "<activation>.<method>")?;
        if !t.contains('.') || t.split('.').any(str::is_empty) {
            return Err(format!("`{t}` is not a method path (<activation>.<method>)"));
        }
        Ok(())
    }
);

string_param!(
    /// A role's name — `editor`. One word: no `.` (that is a grant), no
    /// `@` (that is a ceiling entry), no whitespace.
    RoleName,
    |t| {
        word(t, "role name", "one word, no `.` or `@`")?;
        if t.contains('.') || t.contains('@') {
            return Err(format!("`{t}` is not a role name (one word, no `.` or `@`)"));
        }
        Ok(())
    }
);

string_param!(
    /// One entry of a role's grants: a grant (`tickets.get`) or a role
    /// whose grants it includes (`viewer`). No `@`, no whitespace.
    GrantName,
    |t| {
        word(t, "grant or role", "tickets.get, or a role")?;
        if t.contains('@') || t.split('.').any(str::is_empty) {
            return Err(format!("`{t}` is not a grant or a role (tickets.get, or a role)"));
        }
        Ok(())
    }
);

string_param!(
    /// Where a role is held: a scope name (`MENGER`) or `*`, everywhere.
    /// What a name means is the service's; it is not blank.
    ScopeName,
    |t| bounded(t, "scope")
);

string_param!(
    /// A sign-in provider's name, as `auth.providers` lists it
    /// (`workos`, `plexus-idp`). One word.
    ProviderName,
    |t| word(t, "provider name", "one word, as auth.providers lists it")
);

string_param!(
    /// A Plexus principal: `key:<hex>`, `oidc:<issuer>/<subject>`,
    /// `idp:<subject>`, … — the identity layer's grammar, checked here;
    /// [`Principal::principal`] is the parsed value.
    Principal,
    |t| {
        bounded(t, "principal")?;
        t.parse::<identity::Principal>().map(|_| ()).map_err(|e| format!("`{t}` is not a principal: {e}"))
    }
);

impl MethodPath {
    /// The method's grant (a method's grant is its path).
    pub fn grant(&self) -> Grant {
        Grant::new(self.0.clone())
    }
}

impl RoleName {
    /// The identity layer's role name.
    pub fn role(&self) -> plexus_auth_core::RoleName {
        plexus_auth_core::RoleName::new(self.0.clone())
    }
}

impl GrantName {
    /// A dotted entry is a grant; a bare one names a role.
    pub fn is_grant(&self) -> bool {
        self.0.contains('.')
    }
}

impl ScopeName {
    /// `*` → everywhere; anything else, that scope.
    pub fn scope(&self) -> ScopeRef {
        ScopeRef::parse(&self.0)
    }
}

impl Principal {
    /// The identity layer's principal. Infallible: the text was checked
    /// with the same parse when this value was made.
    pub fn principal(&self) -> identity::Principal {
        self.0.parse().expect("a Principal param holds a parsed principal")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn de<T: for<'de> Deserialize<'de>>(v: serde_json::Value) -> Result<T, String> {
        serde_json::from_value(v).map_err(|e| e.to_string())
    }

    #[test]
    fn the_json_is_unchanged() {
        let m: MethodPath = de(json!("tickets.set_status")).unwrap();
        assert_eq!(serde_json::to_value(&m).unwrap(), json!("tickets.set_status"));
        assert_eq!(m.as_str(), "tickets.set_status");
        assert_eq!(m.to_string(), "tickets.set_status");
        let s: ScopeName = de(json!("*")).unwrap();
        assert_eq!(serde_json::to_value(&s).unwrap(), json!("*"));
        assert_eq!(s.scope(), ScopeRef::Everywhere);
    }

    #[test]
    fn values_are_trimmed_once() {
        let r: RoleName = de(json!("  editor ")).unwrap();
        assert_eq!(r.as_str(), "editor");
        let m: MethodPath = de(json!(" tickets.get ")).unwrap();
        assert_eq!(m.as_str(), "tickets.get");
    }

    #[test]
    fn a_method_path_is_dotted() {
        assert!(de::<MethodPath>(json!("tickets")).unwrap_err().contains("is not a method path"));
        assert!(de::<MethodPath>(json!("tickets.")).is_err());
        assert!(de::<MethodPath>(json!(".get")).is_err());
        assert!(de::<MethodPath>(json!("tickets get")).is_err());
        assert!(de::<MethodPath>(json!("")).is_err());
        assert!(de::<MethodPath>(json!("tickets.inputs.answer")).is_ok());
    }

    #[test]
    fn a_role_name_is_one_word() {
        for bad in ["", "a.b", "editor@MENGER", "two words", "   "] {
            assert!(de::<RoleName>(json!(bad)).is_err(), "{bad:?}");
        }
        assert!(de::<RoleName>(json!("a.b")).unwrap_err().contains("`a.b` is not a role name"));
        assert_eq!(de::<RoleName>(json!("viewer")).unwrap().role().as_str(), "viewer");
    }

    #[test]
    fn a_grant_entry_is_a_grant_or_a_role() {
        let g: GrantName = de(json!("tickets.get")).unwrap();
        assert!(g.is_grant());
        let r: GrantName = de(json!("viewer")).unwrap();
        assert!(!r.is_grant());
        for bad in ["", "tickets.get@MENGER", "tickets..get", "a b"] {
            assert!(de::<GrantName>(json!(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_principal_parses() {
        let p: Principal = de(json!("idp:6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b")).unwrap();
        assert_eq!(p.principal().to_string(), p.as_str());
        assert!(de::<Principal>(json!("nobody")).unwrap_err().contains("`nobody` is not a principal"));
    }

    #[test]
    fn scopes_and_providers() {
        assert!(de::<ScopeName>(json!("")).is_err());
        assert_eq!(de::<ScopeName>(json!("MENGER")).unwrap().scope(), ScopeRef::named("MENGER"));
        assert!(de::<ProviderName>(json!("plexus-idp")).is_ok());
        assert!(de::<ProviderName>(json!("two words")).is_err());
    }

    #[test]
    fn the_schema_is_a_named_string() {
        let s = serde_json::to_value(schemars::schema_for!(RoleName)).unwrap();
        assert_eq!(s["type"], "string");
        assert!(s["description"].as_str().unwrap().contains("role"));
    }
}
