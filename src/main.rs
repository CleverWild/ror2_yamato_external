use tokio::time::{sleep, Duration}; 
use toy_arms::external::{read, write};

 
#[tokio::main]
async fn main() {
    env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).
    hack::run().unwrap();
}

mod hack {
    use eframe::egui;
    use gui::YamatoGui;

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let options = eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([320.0, 240.0]),
            ..Default::default()
        };
        eframe::run_native(
            "My egui App",
            options,
            Box::new(|_cc| {
                Box::<YamatoGui>::default()
            }),
        )?;
        Ok(())
    }
}





// pub fn show_ui(&mut self, ctx: &egui::Context) {
//     egui::Window::new("Settings").show(ctx, |ui| {
//         ui.checkbox(&mut self.bones_enabled, "Bones");
//         ui.checkbox(&mut self.box2d_enabled, "2D Box");
//         ui.checkbox(&mut self.hp_enabled, "Hp");
//         ui.checkbox(&mut self.tracers_enabled, "Tracers");
//         ui.checkbox(&mut self.ice_enabled, "Ice Walls");
//         ui.checkbox(&mut self.bomb_enabled, "Bomb");
//         ui.checkbox(&mut self.dropped_items_enabled, "Dropped Items");

//         ui.label("Visible color");
//         ui.color_edit_button_srgba(&mut self.visible_color);
//         ui.label("Regular color");
//         ui.color_edit_button_srgba(&mut self.regular_color);
//         ui.label("Tracer color");
//         ui.color_edit_button_srgba(&mut self.tracers_color);
//     });
// }