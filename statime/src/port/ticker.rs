use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::Stream;
use pin_project::pin_project;

use crate::time::Duration;

#[pin_project]
pub struct Ticker<T, R> {
    #[pin]
    timer: T,
    reset: R,
    interval: Duration,
}

impl<T, R> Ticker<T, R>
where
    R: FnMut(Duration) -> T,
{
    pub fn new(mut reset: R, interval: Duration) -> Self {
        Self {
            timer: reset(interval),
            reset,
            interval,
        }
    }

    pub fn reset(self: &mut Pin<&mut Self>) {
        let interval = self.interval;
        let mut this = self.as_mut().project();
        this.timer.set((this.reset)(interval));
        log::trace!("Timer reset");
    }
}

impl<F, R> Stream for Ticker<F, R>
where
    F: Future,
    R: FnMut(Duration) -> F,
{
    type Item = F::Output;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        log::trace!("Ticker polled");
        let this = self.as_mut().project();
        match this.timer.poll(cx) {
            Poll::Ready(output) => {
                log::trace!("Timer expired");
                self.reset();
                Poll::Ready(Some(output))
            }
            Poll::Pending => {
                log::trace!("Timer pending");
                Poll::Pending
            }
        }
    }
}
