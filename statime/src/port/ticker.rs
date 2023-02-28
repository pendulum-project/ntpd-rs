use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures::Stream;

use crate::time::Duration;
use pin_project::pin_project;

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
    }
}

impl<T, R> Stream for Ticker<T, R>
where
    T: Future,
    R: FnMut(Duration) -> T,
{
    type Item = T::Output;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().project();
        match this.timer.poll(cx) {
            Poll::Ready(output) => {
                self.reset();
                Poll::Ready(Some(output))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
