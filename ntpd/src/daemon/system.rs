#[cfg(target_os = "linux")]
use std::{
    cell::OnceCell,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Mutex,
};
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll, Waker},
};

use ntp_proto::{NtpManager, SynchronizationConfig};
use statime_base::{ActiveLinkData, ClockId, Link, LinkId, SourceType, StdController};
#[cfg(target_os = "linux")]
use statime_csptp::CsptpConfig;
use tokio::{
    task::JoinHandle,
    time::{Instant, Sleep},
};

use crate::daemon::{
    clock::NtpClockWrapper,
    spawn::{
        CreationParameters, LinkTerminationReason, SpawnFailureReason, Spawner, SpawnerId,
        TrySpawnFuture,
    },
};

pub struct SystemConfig {
    pub minimum_retry_timeout: std::time::Duration,
    pub maximum_retry_timeout: std::time::Duration,
}

pub struct System<TimeController: StdController> {
    state: RwLock<SystemState<TimeController>>,
    managers: SystemManagers,
    controller: Arc<TimeController>,
    #[expect(
        clippy::struct_field_names,
        reason = "The system clock is a special clock separate from the fact that it is part of the system struct."
    )]
    system_clock_id: ClockId,
    #[expect(
        clippy::struct_field_names,
        reason = "The system clock is a special clock separate from the fact that it is part of the system struct."
    )]
    system_clock: NtpClockWrapper,
    config: SystemConfig,
}

struct SystemState<TimeController: StdController> {
    waker: Option<Waker>,
    driven_links: HashMap<LinkId, LinkData>,
    spawners: HashMap<SpawnerId, SpawnerData<TimeController>>,
}

impl<TimeController: StdController> Default for SystemState<TimeController> {
    fn default() -> Self {
        Self {
            waker: None,
            driven_links: HashMap::new(),
            spawners: HashMap::new(),
        }
    }
}

struct LinkData {
    spawner: SpawnerId,
    stype: SourceType,
    task: JoinHandle<LinkTerminationReason>,
}

enum SpawnState<TimeController: StdController> {
    TryingSpawn(Pin<TrySpawnFuture<TimeController>>),
    Timeout(Pin<Box<Sleep>>),
    Inactive,
}

struct SpawnerData<TimeController: StdController> {
    spawner: Box<dyn Spawner<TimeController> + Sync + Send>,
    spawn_state: SpawnState<TimeController>,
    current_timeout: std::time::Duration,
    last_spawn: tokio::time::Instant,
}

impl<TimeController: StdController> SpawnerData<TimeController> {
    /// Try to run the spawner forward.
    // TODO: Check waiting during errors.
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        config: &SystemConfig,
    ) -> Poll<CreationParameters<TimeController>> {
        loop {
            match &mut self.spawn_state {
                SpawnState::TryingSpawn(pin) => match pin.as_mut().poll(cx) {
                    std::task::Poll::Ready(Ok(parameters)) => {
                        self.last_spawn = tokio::time::Instant::now();
                        self.current_timeout = config.minimum_retry_timeout;
                        // Restart via trivial timeout.
                        self.spawn_state = SpawnState::Timeout(Box::pin(tokio::time::sleep(
                            std::time::Duration::ZERO,
                        )));
                        break Poll::Ready(parameters);
                    }
                    std::task::Poll::Ready(Err(error)) => {
                        self.spawn_state =
                            SpawnState::Timeout(Box::pin(tokio::time::sleep(self.current_timeout)));
                        if error == SpawnFailureReason::RetryableFailure {
                            self.current_timeout = (2 * self.current_timeout)
                                .clamp(config.minimum_retry_timeout, config.maximum_retry_timeout);
                        }
                    }
                    std::task::Poll::Pending => break Poll::Pending,
                },
                SpawnState::Timeout(pin) => match pin.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        if self.spawner.needs_spawn() {
                            self.spawn_state =
                                SpawnState::TryingSpawn(Box::into_pin(self.spawner.try_spawn()));
                        } else {
                            self.spawn_state = SpawnState::Inactive;
                            break Poll::Pending;
                        }
                    }
                    Poll::Pending => break Poll::Pending,
                },
                SpawnState::Inactive => break Poll::Pending,
            }
        }
    }

    fn report_cancel(&mut self, id: LinkId, reason: LinkTerminationReason) {
        self.spawner.source_terminated(id, reason);
        if matches!(self.spawn_state, SpawnState::Inactive) {
            if reason != LinkTerminationReason::Deleted {
                self.spawn_state = SpawnState::Timeout(Box::pin(tokio::time::sleep_until(
                    self.last_spawn + self.current_timeout,
                )));
            } else {
                self.spawn_state =
                    SpawnState::Timeout(Box::pin(tokio::time::sleep(std::time::Duration::ZERO)));
            }
        }
    }
}

pub struct SystemManagers {
    ntp_manager: Arc<NtpManager>,
    // FIXME: switch to oncecells once https://github.com/rust-lang/rust/issues/109737 is resolved.
    #[cfg(target_os = "linux")]
    ptp_networking_ipv4: Mutex<Option<statime_netptp::NetworkManager<Ipv4Addr>>>,
    #[cfg(target_os = "linux")]
    ptp_networking_ipv6: Mutex<Option<statime_netptp::NetworkManager<Ipv6Addr>>>,
    #[cfg(target_os = "linux")]
    csptp_manager:
        &'static statime_csptp::CsptpManager<std::sync::RwLock<statime_csptp::InternalState>>,
}

impl SystemManagers {
    #[cfg(test)]
    pub fn test_managers() -> Self {
        SystemManagers {
            ntp_manager: Arc::new(NtpManager::new(
                SynchronizationConfig::default(),
                Arc::default(),
            )),
            #[cfg(target_os = "linux")]
            ptp_networking_ipv4: Mutex::new(None),
            #[cfg(target_os = "linux")]
            ptp_networking_ipv6: Mutex::new(None),
            #[cfg(target_os = "linux")]
            csptp_manager: Box::leak(Box::new(statime_csptp::CsptpManager::new(
                CsptpConfig::default(),
            ))),
        }
    }

    pub fn ntp_manager(&self) -> Arc<NtpManager> {
        self.ntp_manager.clone()
    }

    #[cfg(target_os = "linux")]
    pub fn netptp_ipv4(&self) -> std::io::Result<statime_netptp::NetworkManager<Ipv4Addr>> {
        let mut ptp_networking_ipv4 = self.ptp_networking_ipv4.lock().unwrap();

        if let Some(network) = &*ptp_networking_ipv4 {
            Ok(network.clone())
        } else {
            let manager = statime_netptp::NetworkManager::new()?;
            *ptp_networking_ipv4 = Some(manager.clone());
            Ok(manager)
        }
    }

    #[cfg(target_os = "linux")]
    pub fn netptp_ipv6(&self) -> std::io::Result<statime_netptp::NetworkManager<Ipv6Addr>> {
        let mut ptp_networking_ipv6 = self.ptp_networking_ipv6.lock().unwrap();

        if let Some(network) = &*ptp_networking_ipv6 {
            Ok(network.clone())
        } else {
            let manager = statime_netptp::NetworkManager::new()?;
            *ptp_networking_ipv6 = Some(manager.clone());
            Ok(manager)
        }
    }

    #[cfg(target_os = "linux")]
    pub fn csptp_manager(
        &self,
    ) -> &'static statime_csptp::CsptpManager<std::sync::RwLock<statime_csptp::InternalState>> {
        self.csptp_manager
    }
}

impl<TimeController: StdController + Sync + Send> System<TimeController> {
    pub fn new(
        system_clock: NtpClockWrapper,
        controller: TimeController,
        system_clock_id: ClockId,
        system_config: SystemConfig,
        ntp_config: SynchronizationConfig,
        #[cfg(target_os = "linux")] csptp_config: CsptpConfig,
    ) -> Self {
        let ntp_manager = Arc::new(NtpManager::new(ntp_config, Arc::default()));

        #[cfg(target_os = "linux")]
        let csptp_manager = Box::leak(Box::new(statime_csptp::CsptpManager::new(csptp_config)));

        Self {
            state: RwLock::default(),
            managers: SystemManagers {
                ntp_manager,
                #[cfg(target_os = "linux")]
                ptp_networking_ipv4: Mutex::new(None),
                #[cfg(target_os = "linux")]
                ptp_networking_ipv6: Mutex::new(None),
                #[cfg(target_os = "linux")]
                csptp_manager,
            },
            controller: Arc::new(controller),
            system_clock,
            system_clock_id,
            config: system_config,
        }
    }

    fn run_self(&self) -> impl Future<Output = Result<(), Box<dyn std::error::Error + Send>>> {
        std::future::poll_fn(|cx| {
            let mut state = self.state.write().unwrap();
            // Making the mutable reference explicit here makes the borrow
            // checker able to separate mutable borrows of the driven links
            // and spawner lists.
            let state = &mut *state;
            state.waker = Some(cx.waker().clone());
            'restart_polling: loop {
                // Check for sources that have gone.
                state.driven_links.retain(|&link_id, driven_link| {
                    match Pin::new(&mut driven_link.task).poll(cx) {
                        Poll::Ready(reason) => {
                            let reason = match reason {
                                Ok(reason) => reason,
                                Err(error) => {
                                    if error.is_panic() {
                                        LinkTerminationReason::Failed
                                    } else {
                                        LinkTerminationReason::Deleted
                                    }
                                }
                            };

                            if let Some(spawner) = state.spawners.get_mut(&driven_link.spawner) {
                                spawner.report_cancel(link_id, reason);
                            }
                            false
                        }
                        Poll::Pending => true,
                    }
                });

                // Drive the spawners
                for (&spawner_id, spawner) in &mut state.spawners {
                    if let Poll::Ready(parameters) = spawner.poll(cx, &self.config) {
                        let link = if let Some(tracked_link_config) = parameters.tracked_link_config
                        {
                            TimeController::create_tracked_link(
                                self.controller.clone(),
                                self.system_clock_id,
                                None,
                                parameters.link_config,
                                tracked_link_config,
                            )
                        } else {
                            TimeController::create_untracked_link(
                                self.controller.clone(),
                                self.system_clock_id,
                                None,
                                parameters.link_config,
                            )
                        };
                        let link = match link {
                            Ok(link) => link,
                            Err(error) => todo!(),
                        };
                        let link_id = link.id();
                        let driven_link =
                            (parameters.creator)(link, self.system_clock, &self.managers);
                        state.driven_links.insert(
                            link_id,
                            LinkData {
                                spawner: spawner_id,
                                stype: parameters.stype,
                                task: driven_link,
                            },
                        );

                        continue 'restart_polling;
                    }
                }

                break;
            }
            Poll::Pending
        })
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send>> {
        let timer_loop = async move {
            loop {
                // Scope is needed to keep the future send.
                {
                    let time_snapshot = self
                        .controller
                        .clock_snapshot(self.system_clock_id)
                        .expect("Unable to get system clock time snapshot");
                    let mut used_sources = self.controller.active_links();
                    used_sources.sort_by(|a, b| b.importance.total_cmp(&a.importance));
                    self.managers
                        .ntp_manager
                        .update_time_snapshot(time_snapshot);

                    let state = self.state.read().unwrap();

                    if let Some(used_sources) = used_sources
                        .into_iter()
                        .map(|ActiveLinkData { id, .. }| {
                            state.driven_links.get(&id).map(|state| (id, state.stype))
                        })
                        .collect::<Option<Vec<_>>>()
                    {
                        #[cfg(target_os = "linux")]
                        self.managers
                            .csptp_manager
                            .update_used_sources(used_sources.iter().copied());
                        let ntp_snapshot = self
                            .managers
                            .ntp_manager
                            .update_used_sources(used_sources.into_iter());
                    }
                }

                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
            }

            #[expect(unreachable_code, reason = "Needed for type inference.")]
            Ok(())
        };

        let controller_run = TimeController::run(self.controller.clone(), tokio::time::sleep);
        let controller_run = async {
            controller_run.await.map_err(|e| {
                Box::new(std::io::Error::other(format!("{e:?}")))
                    as Box<dyn std::error::Error + Send>
            })
        };

        let self_run = self.run_self();

        tokio::try_join!(controller_run, timer_loop, self_run)?;
        Ok(())
    }

    pub fn add_spawner(&self, spawner: Box<dyn Spawner<TimeController> + Sync + Send>) {
        let mut state = self.state.write().unwrap();
        state.spawners.insert(
            SpawnerId::new(),
            SpawnerData {
                spawner,
                spawn_state: SpawnState::Timeout(Box::pin(tokio::time::sleep(
                    std::time::Duration::ZERO,
                ))),
                current_timeout: self.config.minimum_retry_timeout,
                last_spawn: tokio::time::Instant::now(),
            },
        );
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
}
