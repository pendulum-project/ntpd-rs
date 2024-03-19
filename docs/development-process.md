# Development processes

## Releasing

New releases are created by starting at either the most recent commit on main,
or by backporting fixes on top of an existing tag. Some things to take note of
before starting the release process:

- Have all dependencies recently been updated using `cargo update`?
- Does the changelog contain all recent additions, removals, changes and fixes?
- Are there still any open issues in any related milestone on GitHub?

To determine what version to release we keep to semantic versioning:

- If there are any (major) breaking changes, we always release a new major
  version.
- Patch versions are generally only released for tiny fix-only releases.
- Minor versions are released when large fixes or new features are introduced.
- At any time a new dev release can be made, if unknown what version the next
  release will be you should always assume a patch version change and only
  increase minor or major versions if any new features or breaking changes are
  happening respectively.
- Before big releases or if testing is required, a beta or release candidate
  can be released.

### Checklist

- [ ] Run `utils/update-version.sh [version]`
- [ ] Update `CHANGELOG.md` with the new version, remove any `Unreleased`
      section in the changelog. Make sure the to release version is the top most
      section of the changelog. Also make sure the diff link is updated at the
      bottom of the document.
- [ ] `git switch -c release/[version]` (the branch name must match this format)
- [ ] `git commit -a -S -m "Release [version]"` (a signed commit is required)
- [ ] `git push -u origin release/[version]`
- [ ] Wait for the github actions pipelines to complete, take special care of
      the packaging pipeline
- [ ] Go to the releases page on Github and find the draft release, check if the
      binaries have been properly generated.
- [ ] Let somebody review the branch
- [ ] WARNING: only merge the branch to main if it is fully up to date compared
      to main, don't let any other branches on the merge queue in the mean time.
      You could also store the release on a non-main branch, but make sure to
      sync the main branch at a later time in that case to update the changelog
      on main.
- [ ] Go to the releases page on GitHub and find the draft release, edit the
      draft release and make it public, this should also create a tag on the
      repository.
- [ ] On your local computer, checkout the specific commit that was tagged by
      GitHub (i.e. `git fetch && git switch --detach v[version]`)
- [ ] Run `utils/release.sh` to publish the crates.io packages

