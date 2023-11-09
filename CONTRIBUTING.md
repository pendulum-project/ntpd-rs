# How to contribute
Thank you for taking the time to read this contribution guide. We always welcome
new contributions!

#### Did you find a bug?
* If your bug is a security issue, make sure to read our [security policy] and
  do not report a normal issue in our issue tracker!
* Search the issue tracker on GitHub for existing bugs
* If you were unable to find an existing issue, please open a new issue in our
  issue tracker with a clear description of the problem and steps on how to
  reproduce it.
* For very small bugs (such as typos), consider directly opening a pull request
  with the patched fix instead.

#### Want to write a patch that fixes a bug?
* If the patch is very small (such as a typo), you may directly open a pull
  request with your fix, no accompanying bug report is needed. Please combine
  multiple typos into a single pull request as much as possible.
* For other bugs, please open a bug report first, this allows us to discuss the
  best way to solve the problem and prevents and duplicated effort.

#### Want to write a new feature?
* Check if there is an existing issue on our issue tracker that already concerns
  the feature you would like to add, add your voice in the discussion there to
  see if nobody else has started working on it.
* If there is no existing issue, open a new one so we can discuss how to
  proceed.

#### Do you have any questions about ntpd-rs?
* See our discussions page instead and avoid the issue tracker

## Developing and building
Our project mostly is a standard rust project so you should be able to use the
normal Rust tooling. One thing to consider though is that the ntp daemon uses
port 123 by default for its server and needs to be able to adjust the clock when
used as a client. You may need root (or the correct Linux capabilities) to do
those two things.

## Dependencies and MSRV
As ntpd-rs is intended to be packaged for multiple operating systems, we try to
be conservative in our minimum supported rust version and the versions of our
dependencies. Only add a new dependency if absolutely necessary. Please refrain
from using newer compiler features or using the latest crate features. If that
would however result in lots of duplicated effort, let us know so we can see if
incrementing a crate version or increasing the MSRV is justified.

## Documentation
Our end-user documentation is written in mkdocs and can be ran locally using the
`utils/mkdocs.sh` script (this uses docker, so make sure that is available). The
man page source files are additionally converted to the man format using pandoc.
These converted man pages are committed to the repository, you can run
`utils/generate-man.sh` to update them whenever a change was made to the source
man files (also requires docker).

## Testing
When adding a contribution we ask that you add tests to validate your work. We
try and keep our code coverage at about the same level or higher than it
currently is. A bot will notify you of the coverage changes that your pull
request resulted in.

Tests can be written using the standard rust testing framework (ran using
`cargo test`) and should mostly be unit-level tests. If you want to write
integration tests (which would be encouraged) you can do so in the `tests`
folder in the ntpd crate.

Additionally we have a few fuzz testing targets. If you can think of any new
targets let us know or add them!

## Coding conventions
Every pull request will go through rustfmt and as such we require all
contributions to adhere to this coding standard. It is recommended to run
rustfmt (i.e. using `cargo fmt`) before you create a pull request. For non-Rust
files (such as our documentation) we ask that you follow the conventions from
other files, but we have no strict requirements.

[security policy]: ./SECURITY.md
