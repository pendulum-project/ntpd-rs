use crate::time::OffsetTime;

trait Clock {
    type W: Watch;
    fn get_watch(&mut self) -> Self::W;
    fn steer(&mut self, time_offset: OffsetTime, frequency_multiplier: f64);
}

trait Watch {
    type WatchId: Eq;
    fn now(&self) -> OffsetTime;
    fn set_alarm(&mut self, from_now: OffsetTime);
    fn id(&self) -> Self::WatchId;
}