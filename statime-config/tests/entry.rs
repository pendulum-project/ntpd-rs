use statime_config::{Config, RootConfig};

#[test]
fn the_entry_point_is_an_associated_function() {
    // no such file, but it proves `Config::load` resolves and typechecks
    // from outside the crate, returning a `Config`
    let outcome: Result<Config, _> = Config::load("/nonexistent/ntp.toml");

    assert!(outcome.is_err());
}
