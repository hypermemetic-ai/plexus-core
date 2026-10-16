//! MACRO-20 — a hub sees through its activations' static children.
//!
//! A static `#[plexus_macros::child]` is reached as
//! `<activation>.<child>.<method>` (`tickets.commits.link`), but its schema
//! is its own: its namespace is `commits`, its methods' grants are
//! `commits.<method>` and its `roles(...)` list those. The macro that wrote
//! it cannot know where the child is mounted, so a child's grants are
//! **relative to its parent's path**, and the hub qualifies them by the path
//! it reaches the child through:
//!
//! | child at | its grant | the hub's grant |
//! |---|---|---|
//! | `tickets.commits` (namespace `commits`) | `commits.link` | `tickets.commits.link` |
//! | `tickets.mirror` (namespace `commits`) | `commits.link` | `tickets.mirror.link` |
//! | `tickets.commits` | `audit.read` (a grant of its own naming) | `tickets.audit.read` |
//! | `tickets.commits.audit` (namespace `audit`) | `audit.read` | `tickets.commits.audit.read` |
//!
//! A grant that starts with the child's namespace names the child: that
//! segment becomes the path. Any other grant is taken as written beside the
//! child, under its parent's path. The same rule qualifies the method's
//! grant and every grant in the child's roles, so the two always agree.
//!
//! [`qualified`] turns one activation's
//! [`Activation::static_child_schemas`](super::Activation::static_child_schemas)
//! into schemas the hub treats like a registered activation's — namespace
//! the whole path, every grant qualified — for the grant gate's index,
//! [`DynamicHub::declared_roles`](super::DynamicHub::declared_roles),
//! `auth.requires` and the caller's view.

use super::schema::PluginSchema;

/// The hub's grant for `grant`, declared by a child whose own namespace is
/// `ns`, reached at `path` (the whole dotted path, `tickets.commits`). See
/// the module docs for the rule.
pub fn qualify_grant(path: &str, ns: &str, grant: &str) -> String {
    match grant.strip_prefix(ns).and_then(|rest| rest.strip_prefix('.')) {
        Some(rest) => format!("{path}.{rest}"),
        None => match path.rsplit_once('.') {
            Some((parent, _)) => format!("{parent}.{grant}"),
            None => grant.to_string(),
        },
    }
}

/// `top`'s static children (`(path, schema)` relative to `top`, as
/// [`Activation::static_child_schemas`](super::Activation::static_child_schemas)
/// lists them), each as a schema whose namespace is its whole path
/// (`tickets.commits`) and whose methods' grants and roles are qualified by
/// it ([`qualify_grant`]). Every method's grant is set explicitly, so
/// `grant_or` answers the qualified grant whatever namespace it is asked
/// under.
pub fn qualified(top: &str, children: Vec<(String, PluginSchema)>) -> Vec<PluginSchema> {
    children
        .into_iter()
        .map(|(rel, mut schema)| {
            let path = format!("{top}.{rel}");
            let ns = std::mem::take(&mut schema.namespace);
            for m in schema.methods.iter_mut() {
                let own = m.grant_or(&ns);
                m.grant = Some(qualify_grant(&path, &ns, &own));
            }
            for grants in schema.roles.values_mut() {
                for g in grants.iter_mut() {
                    *g = qualify_grant(&path, &ns, g);
                }
            }
            schema.namespace = path;
            schema
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plexus::schema::{MethodSchema, PluginSchema};

    #[test]
    fn a_grant_naming_the_child_takes_its_path() {
        assert_eq!(qualify_grant("tickets.commits", "commits", "commits.link"), "tickets.commits.link");
        // Mounted under another name: the path wins, not the namespace.
        assert_eq!(qualify_grant("tickets.mirror", "commits", "commits.link"), "tickets.mirror.link");
        // A grandchild.
        assert_eq!(qualify_grant("tickets.commits.audit", "audit", "audit.read"), "tickets.commits.audit.read");
    }

    #[test]
    fn a_grant_of_its_own_naming_sits_beside_the_child() {
        assert_eq!(qualify_grant("tickets.commits", "commits", "audit.read"), "tickets.audit.read");
        // Only a whole segment names the child.
        assert_eq!(qualify_grant("tickets.commits", "commits", "commitsx.read"), "tickets.commitsx.read");
    }

    #[test]
    fn qualified_rewrites_namespace_grants_and_roles() {
        let mut child = PluginSchema::leaf(
            "commits",
            "1.0",
            "the commits",
            vec![
                MethodSchema::new("link", "d", "h").with_grant("commits.link"),
                // No grant: grant_or's default, then qualified.
                MethodSchema::new("unlink", "d", "h"),
            ],
        );
        child.roles.insert("editor".into(), vec!["commits.link".into(), "commits.unlink".into()]);
        let out = qualified("tickets", vec![("commits".into(), child)]);
        assert_eq!(out.len(), 1);
        let s = &out[0];
        assert_eq!(s.namespace, "tickets.commits");
        let grants: Vec<_> = s.methods.iter().map(|m| m.grant.clone().unwrap()).collect();
        assert_eq!(grants, ["tickets.commits.link", "tickets.commits.unlink"]);
        // grant_or answers the qualified grant whatever it is asked under.
        assert_eq!(s.methods[0].grant_or("anything"), "tickets.commits.link");
        assert_eq!(s.roles["editor"], ["tickets.commits.link", "tickets.commits.unlink"]);
    }
}
