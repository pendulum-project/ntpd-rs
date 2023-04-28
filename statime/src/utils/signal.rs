#[derive(Debug)]
pub struct SignalInner {
    signalled: bool,
    waker: Option<core::task::Waker>,
}

#[derive(Debug)]
pub struct SignalContext {
    inner: core::cell::RefCell<SignalInner>,
}

#[derive(Debug)]
pub struct Signal<'a> {
    inner: &'a core::cell::RefCell<SignalInner>,
}

#[derive(Debug, Clone)]
pub struct Signaller<'a> {
    inner: &'a core::cell::RefCell<SignalInner>,
}

impl SignalContext {
    pub fn new() -> Self {
        SignalContext {
            inner: core::cell::RefCell::new(SignalInner {
                signalled: false,
                waker: None,
            }),
        }
    }

    pub fn signal(&mut self) -> (Signal<'_>, Signaller<'_>) {
        let inner = self.inner.get_mut();
        inner.signalled = false;
        inner.waker = None;

        (
            Signal { inner: &self.inner },
            Signaller { inner: &self.inner },
        )
    }
}

impl<'a> Signaller<'a> {
    pub fn raise(&self) {
        let mut inner = self.inner.borrow_mut();
        inner.signalled = true;
        if let Some(waker) = inner.waker.take() {
            waker.wake()
        }
    }
}

impl<'a> Signal<'a> {
    pub fn wait_for<'b>(&mut self) -> impl core::future::Future<Output = ()> + 'b
    where
        'a: 'b,
    {
        struct Fut<'a> {
            inner: &'a core::cell::RefCell<SignalInner>,
        }

        impl<'a> core::future::Future for Fut<'a> {
            type Output = ();

            fn poll(
                self: core::pin::Pin<&mut Self>,
                cx: &mut core::task::Context<'_>,
            ) -> core::task::Poll<Self::Output> {
                let mut inner = self.inner.borrow_mut();
                if inner.signalled {
                    core::task::Poll::Ready(())
                } else {
                    inner.waker = Some(cx.waker().clone());
                    core::task::Poll::Pending
                }
            }
        }

        Fut { inner: self.inner }
    }
}
