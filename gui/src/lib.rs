use std::future::Future;

use eframe::egui;
use memory::types::*;
use tokio::{runtime::Handle, sync::MutexGuard, time::Instant};

use launchable::{Launchable, Status};
use tracing::{instrument, trace, info};
mod launchable {
    use std::future::Future;

    use crate::do_async;

    enum InnerStatus<T> {
        None,
        Pending(tokio::task::JoinHandle<T>),
        Launched(T),
    }
    impl<T> InnerStatus<T> {
        fn update(&mut self) {
            if let InnerStatus::Pending(handle) = self {
                if handle.is_finished() {
                    *self = InnerStatus::Launched(do_async(async move { handle.await.unwrap() }));
                }
            }
        }
    }

    #[derive(Default, Debug)]
    pub enum Status<'a, T> {
        #[default]
        Offline,
        Pending,
        Launched(&'a T),
    }

    pub struct Launchable<T> {
        status: InnerStatus<T>,
    }
    impl<T: Send + 'static> Launchable<T> {
        pub fn launch<F, Fut>(&mut self, func: F)
        where
            F: Fn() -> Fut + Send + 'static,
            Fut: Future<Output = T> + Send + 'static,
        {
            *self = Self {
                status: InnerStatus::Pending(tokio::task::spawn(async move { func().await })),
            };
        }
    }
    impl<T> Default for Launchable<T> {
        fn default() -> Self {
            Self {
                status: InnerStatus::None,
            }
        }
    }
    impl<T> Launchable<T> {
        fn update(&mut self) {
            self.status.update();
        }
        pub fn status(&mut self) -> Status<T> {
            self.update();
            match &self.status {
                InnerStatus::None => Status::Offline,
                InnerStatus::Pending(_) => Status::Pending,
                InnerStatus::Launched(t) => Status::Launched(t),
            }
        }
    }
}

pub struct YamatoGui {
    last_tick_time: Instant,
    process_id: Option<u32>,
    menu: Launchable<MutexGuard<'static, memory::MemoryMenu>>,
}
impl YamatoGui {
    // fn process_each(&mut self, delay: u128, mut f: impl FnMut()) {
    //     if self.last_tick_time.elapsed().as_millis() > delay {
    //         f();
    //         self.last_tick_time = Instant::now();
    //     }
    // }
    fn is_period_honored(&mut self, delay: u128) -> bool {
        if self.last_tick_time.elapsed().as_millis() > delay {
            self.last_tick_time = Instant::now();
            true
        } else {
            false
        }
    }
}
impl Default for YamatoGui {
    fn default() -> Self {
        info!("Initializing GUI");
        Self {
            last_tick_time: Instant::now(),
            process_id: None,
            menu: Default::default(),
        }
    }
}
impl eframe::App for YamatoGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.process_id.is_none() {
                ui.heading("Waiting for process...");
                ui.spinner();

                if self.is_period_honored(500) {
                    if let Ok(process_id) = memory::process_id() {
                        info!("Process found: {}", process_id);
                        self.process_id = Some(process_id);
                    }
                }
            } else {
                match &self.menu.status() {
                    Status::Offline => {
                        ui.heading("Initialization...");
                        ui.spinner();

                        do_async(async move {
                            info!("Initializing memory");
                            self.menu.launch(memory::menu);
                        });
                    }
                    Status::Pending => {
                        ui.heading("Calculating offsets, please wait...");
                        ui.spinner();

                        // self.process_each(200, || {
                        //     if self.menu.is_pending() {
                        //         self.menu = InnerStatus::Launched(self.menu.unwrap());
                        //     }
                        // });
                    }
                    Status::Launched(_) => {
                        info!("Memory initialized");
                    },
                }
            }
        });
    }
}

/// Executes an asynchronous function synchronously.
///
/// This function takes an asynchronous function `future` as input and blocks the current thread
/// until the future completes. It uses the Tokio runtime to handle the asynchronous execution.
/// The return type of the function matches the output type of the future.
///
/// # Warning
/// All captures will be captured until out of scope.
pub fn do_async<F: core::future::Future>(future: F) -> F::Output {
    // Block the current thread in place using Tokio's `block_in_place` function.
    tokio::task::block_in_place(|| {
        // Use the Tokio runtime's handle to block on the given future.
        Handle::current().block_on(future)
    })
}
