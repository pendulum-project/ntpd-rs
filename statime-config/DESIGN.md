# `statime-config` design

## Purpose

`statime-config` parses and combines layered TOML configuration while preserving predictable precedence and enough provenance for useful diagnostics.

Configuration is loaded in this order:

1. Built-in defaults from the Rust code.
2. Optional system configuration fragments supplied by the distribution.
3. The main `ntp.toml` configuration.

System fragments must be disjoint: two fragments may contribute different fields to the same section, but may not define the same setting. The main configuration may override system configuration.

## Configuration representations

Parsing, merging, and default resolution are separate phases.

- **Partial configuration** represents exactly what a document specified. Missing values remain unset.
- **Effective configuration** is the merged partial tree.
- **Resolved configuration** has built-in defaults applied and required values validated.

Serde defaults on partial structs mean “unset”, not the final runtime default. Runtime defaults are applied only after all files have been merged.

## Tree nodes

The current implementation distinguishes two node types.

### `Setting<T>`

`Setting<T>` is an atomic merge boundary:

```rust
Setting::Unset
Setting::Set(value)
```

Examples include booleans, strings, enums, durations, and complete arrays. When both sides define a setting:

- `RejectOverlap` reports an error.
- `Override` replaces the complete existing value.

An explicitly set empty array is meaningful and must not be treated as unset: it clears an inherited array.

### `Section<T>`

`Section<T>` contains a recursively mergeable struct:

```rust
Section::Unset
Section::Set(partial_struct)
```

When both sides define a section, their children are recursively merged. Merely mentioning the same table in two system fragments is not a conflict; defining the same leaf setting is.

A section does not have one meaningful origin after merging because its children may come from different files.

## Vectors

Vectors have deliberately different merge and provenance granularities.

At their containing field, vectors are atomic:

```rust
Setting<Vec<PartialSourceConfig>>
```

The main configuration replaces the complete system-provided vector, and two system fragments defining the vector conflict.

Structured vector elements may still contain partial settings. This permits per-field defaults and provenance:

```text
sources                         main ntp.toml
sources[0].address              main ntp.toml
sources[0].ntp-version          built-in default
```

Replacing a vector also replaces all nested values and provenance belonging to the old vector. Arrays of scalar values normally need only the outer array origin because their elements cannot be independently merged.

## Serialization

Unset settings are omitted from serialized TOML. Set values serialize exactly as their contained value; provenance is never serialized.

Sections are also omitted when recursively empty. A section is effectively unset when it is either:

- `Section::Unset`, or
- `Section::Set(value)` where every descendant setting is unset.

This requires an emptiness trait implemented recursively by partial structs. Atomic values, including an explicitly empty vector, are never recursively empty once set.

Omitting a set-but-empty section canonicalizes it to an unset section. Consequently, serialization preserves semantic rather than exact structural equality unless the tree is normalized before comparison.

The current code implements omission of `Unset` nodes. Recursive empty-section detection remains to be completed.

## Merge model

`MergePolicy` defines the two operations:

- `RejectOverlap` combines system fragments and rejects duplicate settings.
- `Override` overlays the main configuration onto the merged system configuration.

Every node exposes the same merge operation:

```rust
node.merge(incoming, context)
```

`Setting<T>` implements atomic behavior, while `Section<T>` delegates recursively to `T`. Generated struct implementations only call `merge` on each field and do not need separate leaf and section functions.

`MergeContext` contains only operation-scoped state:

- the merge policy;
- the current `ConfigPath` cursor.

`ConfigPath` consists of structured segments:

```rust
PathSegment::Field(&'static str)
PathSegment::Index(usize)
```

This supports diagnostics such as `observability.log-level` and `sources[2].address`. Field names are static schema data, while vector indexes are dynamic.

## Provenance

An `Origin` identifies where a value came from:

```rust
Origin::MainConfig(path)
Origin::SystemConfig(path)
Origin::BuiltInDefault
```

`OriginId` allows many settings to refer cheaply to an origin interned by `ProvenanceTracker`. The tracker is an origin registry; provenance itself belongs to each atomic setting rather than to `MergeContext`.

The intended setting representation is conceptually:

```rust
Setting::Set {
    value,
    origin: OriginId,
}
```

Serde cannot know the filename supplied to the loader. A document is therefore parsed first and then recursively attributed with the `OriginId` registered for that document. Only explicitly set nodes are attributed.

Origin attachment follows tree structure independently of merge behavior:

- `Setting<T>` records its own origin and visits nested values.
- `Section<T>` records no origin and visits its children.
- `Vec<T>` visits its elements.
- Atomic values have no nested values to visit.

This distinction allows a vector to be atomic for merging but recursive for provenance attachment.

During default resolution, every newly supplied default receives the `BuiltInDefault` origin. Required values that remain unset produce a path-aware error.

The current merge scaffold still stores `ProvenanceTracker` in `MergeContext`, and `Setting<T>` does not yet carry an `OriginId`. Completing embedded setting provenance will remove the tracker reference from `MergeContext`; `ConfigMerger` or the loader will retain the tracker so IDs can be registered and resolved for diagnostics.

## Loading sequence

The intended loading process is:

1. Parse the main document sufficiently to inspect `use-system-config`.
2. If enabled, enumerate system fragment files in deterministic order.
3. Parse each system fragment as a partial configuration.
4. Register and recursively attach its `SystemConfig` origin.
5. Merge it using `RejectOverlap`.
6. Register and recursively attach the main file origin.
7. Merge the main partial configuration using `Override`.
8. Resolve built-in defaults and assign their origin.
9. Validate required values and cross-setting constraints.
10. Return the resolved configuration together with the origin registry if runtime provenance inspection is needed.

`use-system-config` is a loader directive. It is read from the main document and should be rejected in system fragments rather than merged like an ordinary runtime setting.

## Errors

A duplicate system setting error should contain:

- the complete `ConfigPath`;
- the existing setting's `OriginId`;
- the incoming setting's `OriginId`.

Resolving the IDs through the origin registry should produce diagnostics naming both files. Parse and validation errors should similarly include their path and origin where available.

Source spans and line/column reporting may be added later. They are separate from file-level origin tracking.

## Macro direction

The repetitive partial-struct behavior is expected to be generated eventually. Before introducing a macro, the traits and semantics should be proven manually across several real sections.

A generated struct should provide, for each field:

- Serde omission using one generic “effectively unset” predicate;
- recursive emptiness evaluation;
- `merge` delegation with a field path segment;
- recursive origin attachment;
- optionally default resolution.

The generated calls should be identical for settings and sections. Their wrapper implementations determine atomic versus recursive behavior. A `macro_rules!` macro can generate complete struct declarations and implementations; a procedural macro is only necessary if normal struct declarations must be inspected or augmented in place.
