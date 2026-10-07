# Hash System V2: Granular Cache Invalidation

## Problem Statement

Current hash system mixes method changes and child changes together:

```rust
pub struct PluginSchema {
    pub hash: String,  // hash(methods) + hash(children) mixed together
    // ...
}
```

**Issue:** Can't distinguish between:
- Changes to THIS plugin's methods
- Changes to child plugins below

This forces unnecessary cache invalidation when a deeply nested plugin changes.

## Proposed Solution: Two-Hash System

Split into two hashes plus a composite:

```rust
pub struct PluginSchema {
    /// Hash of ONLY this plugin's methods (ignores children)
    pub self_hash: String,

    /// Hash of ONLY child plugin hashes (None if leaf plugin)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children_hash: Option<String>,

    /// Composite hash = hash(self_hash + children_hash)
    /// Backward compatible, can be removed in future
    pub hash: String,

    // ... other fields
}
```

## Benefits

### 1. Granular Cache Invalidation

**Scenario 1: Method change**
```
hyperforge.workspace.sync() signature changes
↓
hyperforge.workspace.self_hash changes
hyperforge.workspace.hash changes
hyperforge.children_hash changes (workspace is a child)
hyperforge.hash changes
↓
Cache invalidation: only hyperforge.workspace + hyperforge IR
NOT invalidated: all sibling plugins
```

**Scenario 2: Deep nesting change**
```
solar.earth.moon.info() changes
↓
solar.earth.moon.self_hash changes
solar.earth.moon.hash changes
solar.earth.children_hash changes (moon is a child)
solar.earth.hash changes
solar.children_hash changes (earth is a child)
solar.hash changes
↓
Cache invalidation: moon, earth, solar
NOT invalidated: other solar children (mars, jupiter, etc.)
```

### 2. Selective Fetching

**Just want to know if methods changed?**
```rust
// Compare self_hash only
if cached_schema.self_hash != fresh_schema.self_hash {
    refetch_and_rebuild_methods();
}
// No need to check children at all
```

**Just want to know if children changed?**
```rust
// Compare children_hash only
if cached_schema.children_hash != fresh_schema.children_hash {
    refetch_child_schemas();
}
// No need to rebuild this plugin's IR
```

### 3. Lightweight Hash Queries

Add a new method that returns ONLY hashes (no full schema):

```rust
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct PluginHashes {
    pub namespace: String,
    pub self_hash: String,
    pub children_hash: Option<String>,
    pub hash: String,  // composite
}

// New method:
async fn hashes(&self) -> PluginHashes {
    let schema = Activation::plugin_schema(self);
    PluginHashes {
        namespace: schema.namespace,
        self_hash: schema.self_hash,
        children_hash: schema.children_hash,
        hash: schema.hash,
    }
}
```

**Benefits:**
- No need to fetch full schema just to check for changes
- Much smaller JSON payload
- Faster validation

## Implementation

### Step 1: Update PluginSchema struct

```rust
// plexus-core/src/plexus/schema.rs

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PluginSchema {
    pub namespace: String,
    pub version: String,
    pub description: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub long_description: Option<String>,

    /// Hash of ONLY this plugin's methods
    /// Changes when method signatures, names, or descriptions change
    pub self_hash: String,

    /// Hash of ONLY child plugin hashes (None for leaf plugins)
    /// Changes when any child's hash changes (recursively)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children_hash: Option<String>,

    /// Composite hash = hash(self_hash + children_hash)
    /// Use this if you want a single hash for the entire subtree
    pub hash: String,

    pub methods: Vec<MethodSchema>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<ChildSummary>>,
}
```

### Step 2: Update compute_hash implementation

```rust
impl PluginSchema {
    /// Compute all three hashes
    fn compute_hashes(
        methods: &[MethodSchema],
        children: Option<&[ChildSummary]>,
    ) -> (String, Option<String>, String) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        // Compute self_hash (methods only)
        let mut self_hasher = DefaultHasher::new();
        for m in methods {
            m.hash.hash(&mut self_hasher);
        }
        let self_hash = format!("{:016x}", self_hasher.finish());

        // Compute children_hash (children only)
        let children_hash = children.map(|kids| {
            let mut children_hasher = DefaultHasher::new();
            for c in kids {
                c.hash.hash(&mut children_hasher);
            }
            format!("{:016x}", children_hasher.finish())
        });

        // Compute composite hash (both)
        let mut composite_hasher = DefaultHasher::new();
        self_hash.hash(&mut composite_hasher);
        if let Some(ref ch) = children_hash {
            ch.hash(&mut composite_hasher);
        }
        let hash = format!("{:016x}", composite_hasher.finish());

        (self_hash, children_hash, hash)
    }

    // Update constructor usage
    pub fn new(
        namespace: String,
        version: String,
        description: String,
        long_description: Option<String>,
        methods: Vec<MethodSchema>,
        children: Option<Vec<ChildSummary>>,
    ) -> Self {
        Self::validate_no_collisions(&namespace, &methods, children.as_deref());

        let (self_hash, children_hash, hash) =
            Self::compute_hashes(&methods, children.as_deref());

        Self {
            namespace,
            version,
            description,
            long_description,
            self_hash,
            children_hash,
            hash,
            methods,
            children,
        }
    }
}
```

### Step 3: Add lightweight hash query method

```rust
// plexus-core/src/plexus/plexus.rs

/// Schema summary containing only hashes (for cache validation)
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PluginHashes {
    pub namespace: String,
    pub self_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children_hash: Option<String>,
    pub hash: String,
    /// Child plugin hashes (for recursive checking)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<ChildHashes>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ChildHashes {
    pub namespace: String,
    pub hash: String,
}

#[plexus_macros::hub_method(description = "Get plugin hashes for cache validation")]
async fn hashes(&self) -> PluginHashes {
    let schema = Activation::plugin_schema(self);

    PluginHashes {
        namespace: schema.namespace.clone(),
        self_hash: schema.self_hash.clone(),
        children_hash: schema.children_hash.clone(),
        hash: schema.hash.clone(),
        children: schema.children.as_ref().map(|kids| {
            kids.iter()
                .map(|c| ChildHashes {
                    namespace: c.namespace.clone(),
                    hash: c.hash.clone(),
                })
                .collect()
        }),
    }
}
```

### Step 4: Update cache invalidation logic

```rust
// Synapse cache invalidation

// Check if we need to refetch this plugin's schema
fn should_refetch_schema(
    cached: &PluginSchema,
    fresh_hashes: &PluginHashes,
) -> bool {
    // Method signature changed
    if cached.self_hash != fresh_hashes.self_hash {
        return true;
    }

    // Children changed (only matters if we care about the full tree)
    if cached.children_hash != fresh_hashes.children_hash {
        return true;
    }

    false
}

// More granular: only rebuild IR if methods changed
fn should_rebuild_ir(
    cached: &PluginSchema,
    fresh_hashes: &PluginHashes,
) -> RebuildDecision {
    if cached.self_hash != fresh_hashes.self_hash {
        // Methods changed, need full rebuild
        return RebuildDecision::Full;
    }

    if cached.children_hash != fresh_hashes.children_hash {
        // Only children changed, rebuild IR but methods are same
        return RebuildDecision::ChildrenOnly;
    }

    RebuildDecision::None
}
```

## Example JSON Schema

### Leaf Plugin (no children)
```json
{
  "namespace": "echo",
  "version": "1.0.0",
  "description": "Echo messages back",
  "self_hash": "a1b2c3d4e5f6g7h8",
  "children_hash": null,
  "hash": "a1b2c3d4e5f6g7h8",
  "methods": [
    {
      "name": "echo",
      "description": "Echo a message",
      "hash": "m123hash",
      "params": { /* ... */ },
      "returns": { /* ... */ },
      "cardinality": "many"
    }
  ],
  "children": null
}
```

### Hub Plugin (with children)
```json
{
  "namespace": "hyperforge",
  "version": "2.0.0",
  "description": "Multi-forge repository management",
  "self_hash": "x1y2z3a4b5c6d7e8",
  "children_hash": "p9q8r7s6t5u4v3w2",
  "hash": "composite1234567",
  "methods": [
    {
      "name": "status",
      "description": "Get hyperforge status",
      "hash": "status_hash",
      "returns": { /* ... */ },
      "cardinality": "one"
    }
  ],
  "children": [
    {
      "namespace": "workspace",
      "description": "Workspace operations",
      "hash": "workspace_hash"
    },
    {
      "namespace": "repos",
      "description": "Repository operations",
      "hash": "repos_hash"
    }
  ]
}
```

### Lightweight Hash Query Response
```json
{
  "namespace": "hyperforge",
  "self_hash": "x1y2z3a4b5c6d7e8",
  "children_hash": "p9q8r7s6t5u4v3w2",
  "hash": "composite1234567",
  "children": [
    {
      "namespace": "workspace",
      "hash": "workspace_hash"
    },
    {
      "namespace": "repos",
      "hash": "repos_hash"
    }
  ]
}
```

## Cache Usage Examples

### Example 1: Quick validation with hashes endpoint

```bash
# Fetch just hashes (lightweight)
synapse substrate hashes > current-hashes.json

# Compare with cached manifest
if jq '.self_hash' current-hashes.json != jq '.self_hash' cached-manifest.json
then
  echo "Methods changed, need full refetch"
  refetch_schema
else
  echo "Methods unchanged, check children"
  if jq '.children_hash' current-hashes.json != jq '.children_hash' cached-manifest.json
  then
    echo "Children changed, refetch child schemas only"
    refetch_children
  else
    echo "Nothing changed, use cache"
  fi
fi
```

### Example 2: Recursive hash checking

```rust
async fn check_tree_changes(
    root: &str,
    cached_hashes: &PluginHashes,
) -> Vec<String> {
    let mut changed = Vec::new();

    // Fetch current hashes
    let current = fetch_hashes(root).await;

    // Check self
    if current.self_hash != cached_hashes.self_hash {
        changed.push(format!("{} (methods)", root));
    }

    // Check children recursively
    if let (Some(current_children), Some(cached_children)) =
        (&current.children, &cached_hashes.children)
    {
        for current_child in current_children {
            let cached_child = cached_children
                .iter()
                .find(|c| c.namespace == current_child.namespace);

            if let Some(cc) = cached_child {
                if current_child.hash != cc.hash {
                    // Child changed, recurse
                    let child_path = format!("{}.{}", root, current_child.namespace);
                    let child_changes = check_tree_changes(&child_path, cc).await;
                    changed.extend(child_changes);
                }
            } else {
                // New child
                changed.push(format!("{} (new child)", current_child.namespace));
            }
        }
    }

    changed
}
```

## Migration Path

### Phase 1: Add new fields (backward compatible)
- Add `self_hash` and `children_hash` to `PluginSchema`
- Keep `hash` for backward compatibility
- All three hashes are computed

### Phase 2: Update clients to use new hashes
- Synapse uses `self_hash` for method-only checks
- Synapse uses `children_hash` for child-only checks
- hub-codegen uses `self_hash` for IR invalidation

### Phase 3: Deprecate composite hash (future)
- Mark `hash` as deprecated
- Eventually remove in breaking change

## Performance Impact

### Before (single hash)
```
Request 1: Fetch full schema (5-10 KB JSON)
Request 2: Parse schema
Request 3: Compare hash
```

### After (two-hash system + hashes endpoint)
```
Request 1: Fetch just hashes (500 bytes JSON)
Request 2: Compare self_hash and children_hash
Request 3: Only fetch full schema if changed
```

**Bandwidth savings:** 10-20x for cache hits
**Latency savings:** 5-10x for validation

## Testing

### Test 1: Method change detection
```rust
#[test]
fn test_self_hash_changes_on_method_change() {
    let schema1 = PluginSchema::new(
        "test".into(),
        "1.0".into(),
        "desc".into(),
        None,
        vec![method("foo", "bar")],
        None,
    );

    let schema2 = PluginSchema::new(
        "test".into(),
        "1.0".into(),
        "desc".into(),
        None,
        vec![method("foo", "baz")],  // Changed description
        None,
    );

    assert_ne!(schema1.self_hash, schema2.self_hash);
    assert_eq!(schema1.children_hash, schema2.children_hash);
    assert_ne!(schema1.hash, schema2.hash);
}
```

### Test 2: Child change detection
```rust
#[test]
fn test_children_hash_changes_on_child_change() {
    let child1 = ChildSummary {
        namespace: "child".into(),
        description: "desc".into(),
        hash: "old_hash".into(),
    };

    let child2 = ChildSummary {
        namespace: "child".into(),
        description: "desc".into(),
        hash: "new_hash".into(),
    };

    let schema1 = PluginSchema::new(
        "parent".into(),
        "1.0".into(),
        "desc".into(),
        None,
        vec![],
        Some(vec![child1]),
    );

    let schema2 = PluginSchema::new(
        "parent".into(),
        "1.0".into(),
        "desc".into(),
        None,
        vec![],
        Some(vec![child2]),
    );

    assert_eq!(schema1.self_hash, schema2.self_hash);  // Methods unchanged
    assert_ne!(schema1.children_hash, schema2.children_hash);  // Children changed
    assert_ne!(schema1.hash, schema2.hash);
}
```

## Summary

| Feature | Current | Proposed |
|---------|---------|----------|
| **Hash granularity** | Single hash | Three hashes (self, children, composite) |
| **Cache invalidation** | Coarse | Fine-grained |
| **Lightweight query** | Full schema only | New `hashes()` method |
| **Bandwidth** | 5-10 KB | 500 bytes for validation |
| **Breaking change** | N/A | No (backward compatible) |

This design enables precise cache invalidation while maintaining backward compatibility.
