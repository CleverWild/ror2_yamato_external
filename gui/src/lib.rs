use eframe::egui;
use memory::types::*;
use tokio::{runtime::Handle, time::Instant};

struct YamatoMenuConfig {
    no_skill_cooldown: bool,
    god_mode: bool,
    health: Option<u32>,
    money: Option<u32>,
    // luck: Option<u32>,
}
impl YamatoMenuConfig {
    async fn init() -> Self {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;// todo!

        Self {
            no_skill_cooldown: false,
            god_mode: false,
            health: None,
            money: None,
        }
    }
}

pub struct YamatoGui {
    time: Instant,
    process_id: Option<u32>,
    menu: Option<YamatoMenuConfig>,
}
impl Default for YamatoGui {
    fn default() -> Self {
        Self {
            time: Instant::now(),
            process_id: None,
            menu: None,
        }
    }
}
impl eframe::App for YamatoGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.process_id.is_none() {
                ui.heading("Waiting for process...");
                ui.spinner();
                
                if self.time.elapsed().as_millis() > 500 {
                    do_async(async move {
                        if let Ok(process_id) = memory::menu().await.process_id().await {
                            self.process_id = Some(process_id);
                        }
                        self.time = Instant::now();
                    });
                }
            } else if self.menu.is_none() {
                ui.heading("Calculating offsets, please wait...");
                ui.spinner();

                do_async(async move {
                    self.menu = Some(YamatoMenuConfig::init().await);
                });
            } else {
                todo!()
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
fn do_async<F: core::future::Future>(future: F) -> F::Output {
    // Block the current thread in place using Tokio's `block_in_place` function.
    tokio::task::block_in_place(|| {
        // Use the Tokio runtime's handle to block on the given future.
        Handle::current().block_on(async move {
            future.await
        })
    })
}