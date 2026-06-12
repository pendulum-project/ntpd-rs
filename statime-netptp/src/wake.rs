use std::{
    sync::{Arc, Mutex},
    task::{Wake, Waker},
};

#[derive(Default)]
pub(crate) struct ListWaker(Mutex<Vec<Waker>>);

impl ListWaker {
    pub fn add_waker(&self, waker: Waker) {
        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads.
        let mut wakers = self.0.lock().unwrap();
        wakers.push(waker);
    }
}

impl Wake for ListWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        // The mutex can only be poisoned from an earlier panic. It is ok for
        // us to propagate that to all the threads.
        let mut wakers = self.0.lock().unwrap();
        for waker in wakers.drain(..) {
            waker.wake();
        }
    }
}
