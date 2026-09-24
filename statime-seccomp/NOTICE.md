# Licensing notice

This crate is a binding for, and links to [libseccomp](https://github.com/seccomp/libseccomp).

The license on these Rust bindings themselves are covered by the same license as the other statime crates.

`seccomp` is licensed in the Lesser GPL 2.1, the text is which is included in `lgpl-2.1.txt`.

Using this crate as a dependency in your code require us (and you) to comply with the LGPL-2.1 conditions, section 6.
If you use this crate as presented here, that is easily accomplished since it will make an application link dynamically to `libseccomp`.

But if you change the `build.rs` to link statically to `libseccomp`, distributing the resulting binary without doing anything else would be a violation of the `libseccomp` license.
You will in that case have to make arrangements to comply with condition 6 of the LGPL version 2.1.

Read the relevant documentation on complying with the LGPL if for some reason you want to go down this path.
