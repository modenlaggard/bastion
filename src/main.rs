use eframe::egui;
use std::fs::{self, File};
use std::io::Read;
use std::process::Command;

#[derive(PartialEq)]
enum AppState {
    Login,
    Dashboard,
}

#[derive(PartialEq)]
enum DashboardTab {
    Websites,
    Applications,
    Guide,
    Settings,
}

#[derive(Clone)]
enum PendingAction {
    HostRule { domain: String, enabled: bool },
    FirewallRule { app_name: String, block: bool },
}

struct RuleItem {
    name: String,
    group: String,
    enabled: bool,
}

struct AppFirewallItem {
    name: String,
    blocked: bool,
}

struct BastionApp {
    state: AppState,
    
    // Login State
    login_error: String,
    
    // Dashboard State
    active_tab: DashboardTab,
    selected_group: String,
    domain_rules: Vec<RuleItem>,
    new_domain_input: String,
    new_group_input: String,
    app_firewall_rules: Vec<AppFirewallItem>,
    
    // Settings State
    require_auth_for_toggles: bool,
    
    // Confirmation Dialog State
    show_confirmation: bool,
    pending_action: Option<PendingAction>,
}

impl Default for BastionApp {
    fn default() -> Self {
        Self {
            state: AppState::Login,
            login_error: String::new(),
            
            active_tab: DashboardTab::Websites,
            selected_group: "All".into(),
            domain_rules: vec![
                RuleItem { name: "distracting-site.com".into(), group: "Productivity".into(), enabled: false },
                RuleItem { name: "ads.annoyingtracker.com".into(), group: "Ad Blocking".into(), enabled: true },
            ],
            new_domain_input: String::new(),
            new_group_input: "Productivity".into(),
            app_firewall_rules: vec![
                AppFirewallItem { name: "unwanted-telemetry-client".into(), blocked: false },
            ],
            
            require_auth_for_toggles: true,
            show_confirmation: false,
            pending_action: None,
        }
    }
}

// System Helper to update /etc/hosts using pkexec for root privileges
fn apply_host_rule(domain: &str, enabled: bool) -> Result<(), String> {
    let hosts_path = "/etc/hosts";
    
    let mut content = String::new();
    let mut file = File::open(hosts_path)
        .map_err(|e| format!("Failed to open /etc/hosts: {}", e))?;
    file.read_to_string(&mut content)
        .map_err(|e| format!("Failed to read /etc/hosts: {}", e))?;

    let marker_line = format!("127.0.0.1 {}", domain);
    
    let new_content = if enabled {
        if !content.contains(&marker_line) {
            format!("{}\n# Bastion Rule\n127.0.0.1 {}\n", content, domain)
        } else {
            content
        }
    } else {
        content
            .lines()
            .filter(|line| !line.contains(domain))
            .collect::<Vec<&str>>()
            .join("\n") + "\n"
    };

    let temp_path = "/tmp/bastion_hosts_tmp";
    fs::write(temp_path, new_content)
        .map_err(|e| format!("Failed to write temp file: {}", e))?;

    let status = Command::new("pkexec")
        .args(["mv", temp_path, hosts_path])
        .status()
        .map_err(|e| format!("Failed to execute pkexec: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err("Authentication cancelled or command failed.".into())
    }
}

// System Helper to toggle app firewall rules using iptables via pkexec
fn apply_firewall_rule(app_name: &str, block: bool) -> Result<(), String> {
    let action = if block { "-A" } else { "-D" };
    
    let status = Command::new("pkexec")
        .args(["iptables", action, "OUTPUT", "-p", "tcp", "-m", "comment", "--comment", app_name, "-j", "DROP"])
        .status()
        .map_err(|e| format!("Failed to execute pkexec iptables: {}", e))?;

    if status.success() {
        Ok(())
    } else {
        Err("Firewall modification cancelled or failed.".into())
    }
}

impl eframe::App for BastionApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut visuals = egui::Visuals::dark();
        visuals.window_fill = egui::Color32::from_rgb(0x33, 0x33, 0x33);
        visuals.panel_fill = egui::Color32::from_rgb(0x33, 0x33, 0x33);
        ctx.set_visuals(visuals);

        match self.state {
            AppState::Login => self.render_login_screen(ctx),
            AppState::Dashboard => {
                self.render_dashboard(ctx);
                self.render_confirmation_dialog(ctx);
            }
        }
    }
}

impl BastionApp {
    fn render_login_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(100.0);
                ui.heading("Bastion Security");
                ui.label("Secure Local-First System Utility for MX Linux");
                ui.add_space(40.0);

                let max_width = 300.0;
                
                if ui.add_sized([max_width, 45.0], egui::Button::new("🔐 Unlock with Linux Password")).clicked() {
                    let status = Command::new("pkexec")
                        .arg("true")
                        .status();

                    match status {
                        Ok(s) if s.success() => {
                            self.login_error.clear();
                            self.state = AppState::Dashboard;
                        }
                        _ => {
                            self.login_error = "Authentication cancelled or failed.".into();
                        }
                    }
                }

                if !self.login_error.is_empty() {
                    ui.add_space(15.0);
                    ui.colored_label(egui::Color32::from_rgb(239, 68, 68), &self.login_error);
                }
            });
        });
    }

    fn render_dashboard(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Bastion");
                
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let (rect, _response) = ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                    ui.painter().circle_filled(rect.center(), 4.0, egui::Color32::from_rgb(34, 197, 94));
                    ui.colored_label(egui::Color32::from_rgb(34, 197, 94), "Protected");
                });
                
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.selectable_label(self.active_tab == DashboardTab::Settings, "Settings").clicked() {
                        self.active_tab = DashboardTab::Settings;
                    }
                    if ui.selectable_label(self.active_tab == DashboardTab::Guide, "Guide").clicked() {
                        self.active_tab = DashboardTab::Guide;
                    }
                    if ui.selectable_label(self.active_tab == DashboardTab::Applications, "Applications").clicked() {
                        self.active_tab = DashboardTab::Applications;
                    }
                    if ui.selectable_label(self.active_tab == DashboardTab::Websites, "Websites").clicked() {
                        self.active_tab = DashboardTab::Websites;
                    }
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            match self.active_tab {
                DashboardTab::Websites => self.render_websites_tab(ui),
                DashboardTab::Applications => self.render_apps_tab(ui),
                DashboardTab::Guide => self.render_guide_tab(ui),
                DashboardTab::Settings => self.render_settings_tab(ui),
            }
        });
    }

    fn render_websites_tab(&mut self, ui: &mut egui::Ui) {
        let mut groups: Vec<String> = self.domain_rules.iter().map(|r| r.group.clone()).collect();
        groups.dedup();
        groups.insert(0, "All".into());

        let current_group = &mut self.selected_group;
        let mut add_group_input = self.new_group_input.clone();
        
        egui::SidePanel::left("groups_sidebar")
            .exact_width(170.0)
            .show_inside(ui, |ui| {
                ui.add_space(5.0);
                ui.strong("Rule Groups");
                ui.add_space(10.0);

                let mut group_to_delete = None;

                for group in &groups {
                    if group == "All" {
                        let is_selected = current_group == group;
                        if ui.selectable_label(is_selected, "📂 All").clicked() {
                            *current_group = group.clone();
                        }
                    } else {
                        ui.horizontal(|ui| {
                            let is_selected = current_group == group;
                            if ui.selectable_label(is_selected, format!("📂 {}", group)).clicked() {
                                *current_group = group.clone();
                            }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.small_button("❌").clicked() {
                                    group_to_delete = Some(group.clone());
                                }
                            });
                        });
                    }
                }

                if let Some(g_del) = group_to_delete {
                    for rule in &mut self.domain_rules {
                        if rule.group == g_del {
                            rule.group = "General".into();
                        }
                    }
                    if *current_group == g_del {
                        *current_group = "All".into();
                    }
                }

                ui.add_space(20.0);
                ui.separator();
                ui.add_space(10.0);
                ui.label("Target Group for New Domains:");
                ui.text_edit_singleline(&mut add_group_input);
            });
        
        self.new_group_input = add_group_input;

        ui.horizontal(|ui| {
            ui.heading(format!("Domains ({})", self.selected_group));
        });
        ui.label("Manage domain blocks by group. Routed via /etc/hosts.");
        ui.add_space(15.0);

        ui.horizontal(|ui| {
            ui.label("Domain:");
            ui.text_edit_singleline(&mut self.new_domain_input);
            
            if ui.button("Add Domain").clicked() && !self.new_domain_input.is_empty() {
                let domain = self.new_domain_input.clone();
                let group = if self.new_group_input.is_empty() { "General".into() } else { self.new_group_input.clone() };
                
                if self.require_auth_for_toggles {
                    self.pending_action = Some(PendingAction::HostRule { domain, enabled: true });
                    self.show_confirmation = true;
                } else {
                    if let Ok(_) = apply_host_rule(&domain, true) {
                        self.domain_rules.push(RuleItem { name: domain, group, enabled: true });
                    }
                }
                self.new_domain_input.clear();
            }
        });

        ui.add_space(15.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            let mut toggled_index = None;
            let mut new_state = false;

            for (index, rule) in self.domain_rules.iter_mut().enumerate() {
                if self.selected_group == "All" || rule.group == self.selected_group {
                    ui.horizontal(|ui| {
                        let mut temp_checked = rule.enabled;
                        let response = ui.checkbox(&mut temp_checked, &rule.name);
                        if response.changed() {
                            toggled_index = Some(index);
                            new_state = temp_checked;
                        }
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.colored_label(egui::Color32::from_rgb(150, 150, 150), format!("[{}]", rule.group));
                        });
                    });
                }
            }

            if let Some(index) = toggled_index {
                let domain = self.domain_rules[index].name.clone();
                if self.require_auth_for_toggles {
                    self.domain_rules[index].enabled = !new_state;
                    self.pending_action = Some(PendingAction::HostRule { domain, enabled: new_state });
                    self.show_confirmation = true;
                } else {
                    if let Err(err) = apply_host_rule(&domain, new_state) {
                        self.domain_rules[index].enabled = !new_state;
                        eprintln!("Rule update failed: {}", err);
                    }
                }
            }
        });
    }

    fn render_apps_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Application Firewall");
        ui.label("Control outbound network sockets for installed system binaries via iptables.");
        ui.add_space(15.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            let mut triggered_index = None;
            let mut target_state = false;

            for (index, app) in self.app_firewall_rules.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(&app.name);
                    let button_text = if app.blocked { "Unblock Traffic" } else { "Block Outbound" };
                    if ui.button(button_text).clicked() {
                        triggered_index = Some(index);
                        target_state = !app.blocked;
                    }
                });
            }

            if let Some(index) = triggered_index {
                let name = self.app_firewall_rules[index].name.clone();
                if self.require_auth_for_toggles {
                    self.pending_action = Some(PendingAction::FirewallRule { app_name: name, block: target_state });
                    self.show_confirmation = true;
                } else {
                    if let Ok(_) = apply_firewall_rule(&name, target_state) {
                        self.app_firewall_rules[index].blocked = target_state;
                    }
                }
            }
        });
    }

    fn render_guide_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Bastion Quick Guide");
        ui.label("Learn how to manage your local security rules in 3 simple steps.");
        ui.add_space(20.0);

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.group(|ui| {
                ui.strong("Step 1: Organize with the Left Sidebar");
                ui.add_space(4.0);
                ui.label("Select category groups from the sidebar to filter active rules, click the ❌ button next to any custom group to remove it, or create custom groups for new items.");
            });
            ui.add_space(12.0);

            ui.group(|ui| {
                ui.strong("Step 2: Manage Website and App Rules");
                ui.add_space(4.0);
                ui.label("• Websites: Type a domain into the input field, assign it to a group, and click Add Domain to route it locally via /etc/hosts. Toggle checkboxes to enable or disable blocks.");
                ui.add_space(4.0);
                ui.label("• Applications: Navigate to the Applications tab to view system binaries and click Block Outbound to drop network sockets via iptables.");
            });
            ui.add_space(12.0);

            ui.group(|ui| {
                ui.strong("Step 3: Customize Settings and Security");
                ui.add_space(4.0);
                ui.label("Open the Settings tab to toggle confirmation prompts on or off when modifying rules, or click Lock Dashboard to return to the secure startup screen whenever you step away.");
            });
        });
    }

    fn render_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Bastion Settings");
        ui.label("Bastion Security Utility for MX Linux");
        ui.add_space(20.0);

        ui.checkbox(&mut self.require_auth_for_toggles, "Require confirmation & authentication prompts when toggling rules");
        ui.label("When disabled, clicking toggles or adding rules applies system updates instantly without confirmation dialogs.");
        
        ui.add_space(25.0);
        ui.separator();
        ui.add_space(15.0);
        
        ui.heading("Backup & Restore Rules");
        ui.label("Export your rules and custom groups to a JSON file, or restore them from a backup.");
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            if ui.button("📥 Export Rules to JSON").clicked() {
                let backup_path = "bastion_backup.json";
                let mut json_data = String::from("{\n  \"domains\": [\n");
                
                let domain_lines: Vec<String> = self.domain_rules.iter().map(|r| {
                    format!("    {{\"name\": \"{}\", \"group\": \"{}\", \"enabled\": {}}}", r.name, r.group, r.enabled)
                }).collect();
                
                json_data.push_str(&domain_lines.join(",\n"));
                json_data.push_str("\n  ]\n}");

                if let Err(err) = fs::write(backup_path, json_data) {
                    eprintln!("Failed to export backup: {}", err);
                }
            }

            if ui.button("📤 Import Rules from JSON").clicked() {
                let backup_path = "bastion_backup.json";
                if let Ok(content) = fs::read_to_string(backup_path) {
                    let mut imported_rules = Vec::new();
                    for line in content.lines() {
                        if line.contains("\"name\":") {
                            let parts: Vec<&str> = line.split('"').collect();
                            if parts.len() >= 8 {
                                let name = parts[3].to_string();
                                let group = parts[7].to_string();
                                let enabled = line.contains("true");
                                imported_rules.push(RuleItem { name, group, enabled });
                            }
                        }
                    }
                    if !imported_rules.is_empty() {
                        self.domain_rules = imported_rules;
                    }
                }
            }
        });

        ui.add_space(30.0);
        if ui.button("Lock Dashboard").clicked() {
            self.state = AppState::Login;
        }
    }

    fn render_confirmation_dialog(&mut self, ctx: &egui::Context) {
        if !self.show_confirmation {
            return;
        }

        egui::Window::new("Confirm System Modification")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.label("Are you sure you want to apply this system rule change?");
                ui.label("This will invoke root authentication via pkexec.");
                ui.add_space(15.0);

                ui.horizontal(|ui| {
                    if ui.button("Confirm & Authenticate").clicked() {
                        if let Some(action) = self.pending_action.take() {
                            match action {
                                PendingAction::HostRule { domain, enabled } => {
                                    match apply_host_rule(&domain, enabled) {
                                        Ok(_) => {
                                            if let Some(existing) = self.domain_rules.iter_mut().find(|r| r.name == domain) {
                                                existing.enabled = enabled;
                                            } else {
                                                let group = if self.new_group_input.is_empty() { "General".into() } else { self.new_group_input.clone() };
                                                self.domain_rules.push(RuleItem { name: domain, group, enabled });
                                            }
                                        }
                                        Err(err) => eprintln!("Host rule failed: {}", err),
                                    }
                                }
                                PendingAction::FirewallRule { app_name, block } => {
                                    match apply_firewall_rule(&app_name, block) {
                                        Ok(_) => {
                                            if let Some(app) = self.app_firewall_rules.iter_mut().find(|a| a.name == app_name) {
                                                app.blocked = block;
                                            }
                                        }
                                        Err(err) => eprintln!("Firewall rule failed: {}", err),
                                    }
                                }
                            }
                        }
                        self.show_confirmation = false;
                    }

                    if ui.button("Cancel").clicked() {
                        self.pending_action = None;
                        self.show_confirmation = false;
                    }
                });
                ui.add_space(8.0);
            });
    }
}

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Bastion Security Manager",
        options,
        Box::new(|_| Ok(Box::new(BastionApp::default()))),
    )
}
