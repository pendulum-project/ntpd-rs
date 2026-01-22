use std::{net::SocketAddr, process::exit, sync::OnceLock};

use hickory_resolver::{IntoName, Name, ResolveError, TokioResolver, proto::dnssec::Proof};
use rand::Rng;
use tokio::net::lookup_host;

use crate::daemon::{config::NormalizedAddress, exitcode};

// We keep the resolver globally to avoid reloading its configuration constantly.
static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();

pub(crate) struct KeResolutionResult {
    pub(crate) addr: SocketAddr,
    pub(crate) srv_record_name: Option<String>,
}

pub(crate) async fn resolve_ke(
    addr: &NormalizedAddress,
) -> Result<impl Iterator<Item = KeResolutionResult>, std::io::Error> {
    // Kludge allowing us to return two types of iterator.
    enum Either<A, B> {
        A(A),
        B(B),
    }
    impl<A: Iterator<Item = KeResolutionResult>, B: Iterator<Item = KeResolutionResult>> Iterator
        for Either<A, B>
    {
        type Item = KeResolutionResult;

        fn next(&mut self) -> Option<Self::Item> {
            match self {
                Either::A(a) => a.next(),
                Either::B(b) => b.next(),
            }
        }
    }

    // First try looking up SRV records
    if let Ok(srv_names) = resolve_srv(format!("_ntske._tcp.{}", addr.server_name)).await {
        let mut result = vec![];
        for name in srv_names.into_iter().map(|v| v.to_ascii()) {
            if let Ok(lookup) = lookup_host((name.as_str(), 4460)).await {
                result.extend(lookup.map(|addr| KeResolutionResult {
                    addr,
                    srv_record_name: Some(name.clone()),
                }));
            }
        }
        if !result.is_empty() {
            return Ok(Either::A(result.into_iter()));
        }
    }

    // Otherwise do a direct name lookup
    Ok(Either::B(
        lookup_host((addr.server_name.as_str(), addr.port))
            .await?
            .map(|addr| KeResolutionResult {
                addr,
                srv_record_name: None,
            }),
    ))
}

async fn resolve_srv<N: IntoName>(name: N) -> Result<Vec<Name>, ResolveError> {
    let resolver = RESOLVER.get_or_init(|| {
        let mut builder = match TokioResolver::builder_tokio() {
            Ok(builder) => builder,
            Err(e) => {
                // Abort when the resolver configuration cannot be loaded
                // trying anything else is madness when the system we run
                // on is this broken.
                tracing::error!("Could not load resolver configuration, aborting: {e}.");
                exit(exitcode::CONFIG);
            }
        };
        builder.options_mut().validate = true;
        builder.build()
    });

    let lookup_result = resolver.srv_lookup(name).await?;

    // Unfortunately, hickory doesn't order the results for us apropriately, so we need
    // to do this ourselves. See also https://github.com/hickory-dns/hickory-dns/issues/3440
    //
    // For this, we generate a list of all valid results, augmented by a value equal to
    // T^(1/w) where w is the weight of the entry, and T a uniform random variable
    // between 0 and 1. Sorting by these values in increasing order gives a random order
    // respecting the weighting, since indepdent uniform random X and Y both between 0
    // and 1, the probability X^(1/n) > Y^(1/m) is m/(n+m), which is exactly the chance
    // that the item with weight m should appear before the item with weight n. (Note,
    // this can quickly be checked by calculating the area under the implicit curve
    // x=t^(1/n), y=t^(1/m) in the unit square)
    let mut items: Vec<_> = lookup_result
        .as_lookup()
        .dnssec_iter()
        .filter_map(|v| v.require(Proof::Secure).ok()?.as_srv())
        .map(|v| {
            (
                if v.weight() != 0 {
                    rand::thread_rng()
                        .r#gen::<f64>()
                        .powf(1.0 / (f64::from(v.weight())))
                } else {
                    // Guarantee 0 weight items end up last within their priority group
                    2.0 + rand::thread_rng().r#gen::<f64>()
                },
                v,
            )
        })
        .collect();

    // Now all that remains to be done is sorting the items by first priority and then
    // the generated random value, and we get an ordering respecting RFC2782.
    items.sort_by(|a, b| {
        a.1.priority()
            .cmp(&b.1.priority())
            .then(f64::total_cmp(&a.0, &b.0))
    });

    Ok(items.into_iter().map(|v| v.1.target()).cloned().collect())
}
