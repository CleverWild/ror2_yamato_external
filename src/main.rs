use tokio::time::{sleep, Duration};

#[tokio::main]
async fn main() {

    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(tracing::Level::TRACE)
            .with_line_number(true)
            .finish(),
    )
    .unwrap();

    hack::run().unwrap();
}

mod hack {
    use eframe::egui;
    use gui::YamatoGui;

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([320.0, 240.0])
                .with_always_on_top(),
            ..Default::default()
        };
        eframe::run_native(
            "RoR2 Yamato External",
            options,
            Box::new(|_cc| Box::<YamatoGui>::default()),
        )?;
        Ok(())
    }
}