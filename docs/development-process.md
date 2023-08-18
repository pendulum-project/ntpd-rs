# Development processes

## Releasing

Before creating a release make sure that the changelog is up to date and that
any changes in the readme and other documentation were made.

New releases are created by using `cargo-release`. To create a new release make
sure you have it installed and then run `cargo release [level]` with level being
one of `alpha`, `beta`, `rc`, `patch`, `minor` or `major`. To make a new release
make sure you have access to publish new releases and make sure that you are on
the `main` branch and have access to push new commits to that branch. Make sure
to pick the correct release level depending on the contents of the release. Also
make sure that the changelog is up-to-date with the most recent changes. By
default `cargo release` will run in dry-run mode and run some checks to make
sure that things probably work as expected. You are required to sign the commit
and tag you will make, so make sure that gpg is working as intended. Once ready,
you can run `cargo release [level] --execute` to actually build and commit.

Once this command completes, new releases should have been published to
crates.io, but please verify manually that everything is where it is supposed to
be. A new commit and tag will also have been pushed to the repository. This
should also trigger a release build on github.

Once a release build finished, go to the `Actions` tab in GitHub and find the
run of the pkg workflow for the release commit. At the bottom of the page you
can download the release artifacts to upload them to a new release.

Next, go to the releases page on GitHub and create a new release from the tag
previously uploaded by `cargo release`. Make sure to include the release notes
and the binaries you previously downloaded from the `Actions` page.
