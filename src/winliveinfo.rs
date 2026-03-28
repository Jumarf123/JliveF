use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::Utc;
use eframe::{
    App, CreationContext, Frame, NativeOptions,
    egui::{
        self, ComboBox, Context, RichText, ScrollArea, TextEdit, TextStyle, ViewportBuilder,
        ViewportCommand,
    },
};
use html_escape::encode_safe;

type ActionResult = (String, Result<String, String>);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Category {
    System,
    Security,
    Apps,
    Explorer,
    History,
    Devices,
    Network,
}

impl Category {
    fn label(&self) -> &'static str {
        match self {
            Category::System => "System",
            Category::Security => "Security",
            Category::Apps => "Applications",
            Category::Explorer => "Explorer",
            Category::History => "History",
            Category::Devices => "Devices",
            Category::Network => "Network",
        }
    }
}

#[derive(Clone, Copy)]
struct Action {
    id: &'static str,
    label: &'static str,
    category: Category,
    script: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ThemeChoice {
    Light,
    Dark,
    Lime,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    RawText,
    HtmlStyle,
}

impl ThemeChoice {
    fn label(&self) -> &'static str {
        match self {
            ThemeChoice::Light => "Light",
            ThemeChoice::Dark => "Dark",
            ThemeChoice::Lime => "Lime",
        }
    }

    fn apply(&self, ctx: &Context) {
        let visuals = match self {
            ThemeChoice::Light => egui::Visuals::light(),
            ThemeChoice::Dark => egui::Visuals::dark(),
            ThemeChoice::Lime => {
                let mut v = egui::Visuals::dark();
                v.override_text_color = Some(egui::Color32::from_rgb(200, 255, 200));
                v.selection.bg_fill = egui::Color32::from_rgb(60, 120, 60);
                v.selection.stroke.color = egui::Color32::from_rgb(180, 255, 180);
                v.hyperlink_color = egui::Color32::from_rgb(120, 200, 120);
                v.widgets.inactive.bg_fill = egui::Color32::from_rgb(16, 28, 16);
                v.widgets.active.bg_fill = egui::Color32::from_rgb(24, 48, 24);
                v.widgets.hovered.bg_fill = egui::Color32::from_rgb(24, 60, 24);
                v
            }
        };
        ctx.set_visuals(visuals);
    }
}

struct WinLiveInfoApp {
    output: String,
    status: String,
    search: String,
    font_size: f32,
    theme: ThemeChoice,
    pending: Option<String>,
    rx: mpsc::Receiver<ActionResult>,
    tx: mpsc::Sender<ActionResult>,
    last_html_path: Option<PathBuf>,
    last_html_title: Option<String>,
    last_generated_at: Option<String>,
    auto_open_html: bool,
    auto_open_in_app: bool,
    view_mode: ViewMode,
}

impl WinLiveInfoApp {
    fn new(cc: &CreationContext<'_>) -> Self {
        let (tx, rx) = mpsc::channel();
        let theme = ThemeChoice::Dark;
        theme.apply(&cc.egui_ctx);
        apply_font_size(&cc.egui_ctx, 14.0);

        Self {
            output: String::from("Select a function from the menu to gather live information."),
            status: String::from("Ready"),
            search: String::new(),
            font_size: 14.0,
            theme,
            pending: None,
            rx,
            tx,
            last_html_path: None,
            last_html_title: None,
            last_generated_at: None,
            auto_open_html: false,
            auto_open_in_app: false,
            view_mode: ViewMode::RawText,
        }
    }

    fn filtered_output(&self) -> String {
        let query = self.search.trim().to_lowercase();
        if query.is_empty() {
            return self.output.clone();
        }

        let filtered = self
            .output
            .lines()
            .filter(|line| line.to_lowercase().contains(&query))
            .collect::<Vec<_>>()
            .join("\n");

        if filtered.is_empty() {
            format!("(no matches for \"{query}\")\n\n{}", self.output)
        } else {
            format!(
                "Matches for \"{query}\":\n{filtered}\n\n--- Full Output ---\n{}",
                self.output
            )
        }
    }

    fn trigger_action(&mut self, action: &'static Action) {
        if self.pending.is_some() {
            self.status = "Another action is already running...".into();
            return;
        }

        self.pending = Some(action.id.to_string());
        self.status = format!("Running {} ...", action.label);

        let tx = self.tx.clone();
        let id = action.id.to_string();
        let script = action.script.to_string();

        thread::spawn(move || {
            let result = run_powershell_script(&script);
            let _ = tx.send((id, result));
        });
    }

    fn handle_results(&mut self) {
        while let Ok((id, result)) = self.rx.try_recv() {
            if self.pending.as_deref() == Some(&id) {
                self.pending = None;
            }

            match result {
                Ok(text) => {
                    self.output = text.clone();
                    let mut status = "Completed".to_string();

                    if let Some(action) = action_by_id(&id) {
                        match write_html_report(&action, &text) {
                            Ok(report) => {
                                if self.auto_open_html {
                                    let _ = open_html_file(&report.path);
                                }
                                if self.auto_open_in_app {
                                    let _ = open_html_in_app(&report.path);
                                }
                                status = "Completed".into();
                                self.last_html_path = Some(report.path.clone());
                                self.last_html_title = Some(action.label.to_string());
                                self.last_generated_at = Some(report.generated_at);
                            }
                            Err(err) => {
                                status = format!("Completed (HTML generation failed: {err})")
                            }
                        }
                    }

                    self.status = status;
                }
                Err(err) => {
                    self.output = err.clone();
                    self.last_html_path = None;
                    self.last_html_title = None;
                    self.last_generated_at = None;
                    self.status = format!("Failed: {err}");
                }
            }
        }
    }
}

impl App for WinLiveInfoApp {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        self.handle_results();

        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            egui::menu::bar(ui, |ui| {
                ui.menu_button("File", |ui| {
                    if ui.button("Save output to file").clicked() {
                        match save_output(&self.output, "txt") {
                            Ok(path) => self.status = format!("Saved to {path}"),
                            Err(err) => self.status = format!("Save failed: {err}"),
                        }
                        ui.close_menu();
                    }
                    if ui.button("Save output as CSV (raw text)").clicked() {
                        match save_output(&self.output, "csv") {
                            Ok(path) => self.status = format!("Saved to {path}"),
                            Err(err) => self.status = format!("Save failed: {err}"),
                        }
                        ui.close_menu();
                    }
                    if ui.button("Clear output").clicked() {
                        self.output.clear();
                        self.status = "Cleared output".into();
                        ui.close_menu();
                    }
                    if ui.button("Exit").clicked() {
                        ctx.send_viewport_cmd(ViewportCommand::Close);
                    }
                });

                ui.menu_button("Functions", |ui| {
                    ScrollArea::vertical().max_height(500.0).show(ui, |ui| {
                        render_functions_menu(ui, self);
                    });
                });

                ui.menu_button("Actions", |ui| {
                    if ui.button("Copy output to clipboard").clicked() {
                        ctx.copy_text(self.output.clone());
                        self.status = "Copied to clipboard".into();
                        ui.close_menu();
                    }
                    if ui.button("Open report in-app viewer").clicked() {
                        if let Some(path) = self.last_html_path.clone() {
                            match open_html_in_app(&path) {
                                Ok(_) => self.status = "Opened in embedded viewer".into(),
                                Err(err) => self.status = err,
                            }
                        } else {
                            self.status = "No HTML report yet.".into();
                        }
                        ui.close_menu();
                    }
                    if ui.button("Open in browser (last HTML)").clicked() {
                        if let Some(path) = self.last_html_path.clone() {
                            match open_html_file(&path) {
                                Ok(_) => self.status = format!("Opened {}", path.display()),
                                Err(err) => self.status = err,
                            }
                        } else {
                            self.status = "No HTML report yet.".into();
                        }
                        ui.close_menu();
                    }
                    ui.separator();
                    ui.checkbox(
                        &mut self.auto_open_html,
                        "Auto-open in browser after run (off = in-app only)",
                    );
                    ui.checkbox(
                        &mut self.auto_open_in_app,
                        "Auto-open in app viewer after run",
                    );
                });

                ui.menu_button("Help", |ui| {
                    ui.label("Windows 10 Live Information viewer - Rust rewrite");
                    ui.label("Source: Win10LiveInfo scripts reused via PowerShell");
                });

                ui.separator();

                ui.label(RichText::new("Search:").monospace());
                ui.add(
                    TextEdit::singleline(&mut self.search)
                        .hint_text("Type here to search")
                        .desired_width(200.0),
                );

                ui.separator();
                ui.label("Font");
                ComboBox::from_id_source("font_size")
                    .selected_text(format!("{:.0}", self.font_size))
                    .show_ui(ui, |ui| {
                        for size in [12.0_f32, 13.0, 14.0, 15.0, 16.0, 18.0, 20.0] {
                            if ui
                                .selectable_value(&mut self.font_size, size, format!("{:.0}", size))
                                .clicked()
                            {
                                apply_font_size(ctx, size);
                            }
                        }
                    });

                ui.separator();
                ui.label("Theme");
                ComboBox::from_id_source("theme_choice")
                    .selected_text(self.theme.label())
                    .show_ui(ui, |ui| {
                        for theme in [ThemeChoice::Dark, ThemeChoice::Light, ThemeChoice::Lime] {
                            if ui
                                .selectable_value(&mut self.theme, theme, theme.label())
                                .clicked()
                            {
                                self.theme.apply(ctx);
                            }
                        }
                    });

                ui.separator();
                ui.label("View");
                ComboBox::from_id_source("view_mode")
                    .selected_text(match self.view_mode {
                        ViewMode::RawText => "Raw",
                        ViewMode::HtmlStyle => "Styled",
                    })
                    .show_ui(ui, |ui| {
                        if ui
                            .selectable_value(&mut self.view_mode, ViewMode::HtmlStyle, "Styled")
                            .clicked()
                        {
                            self.view_mode = ViewMode::HtmlStyle;
                        }
                        if ui
                            .selectable_value(&mut self.view_mode, ViewMode::RawText, "Raw")
                            .clicked()
                        {
                            self.view_mode = ViewMode::RawText;
                        }
                    });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(RichText::new(&self.status).italics());
                });
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.view_mode {
            ViewMode::RawText => {
                let mut view_text = self.filtered_output();
                ScrollArea::vertical()
                    .auto_shrink([false; 2])
                    .show(ui, |ui| {
                        ui.add(
                            TextEdit::multiline(&mut view_text)
                                .code_editor()
                                .desired_width(f32::INFINITY)
                                .desired_rows(40)
                                .font(TextStyle::Monospace)
                                .lock_focus(false)
                                .interactive(true),
                        );
                    });
            }
            ViewMode::HtmlStyle => render_html_like_preview(ui, self),
        });
    }
}

fn apply_font_size(ctx: &Context, size: f32) {
    let mut style: egui::Style = (*ctx.style()).clone();
    style
        .text_styles
        .insert(TextStyle::Body, egui::FontId::proportional(size));
    style
        .text_styles
        .insert(TextStyle::Monospace, egui::FontId::monospace(size));
    ctx.set_style(style);
}

fn render_html_like_preview(ui: &mut egui::Ui, app: &mut WinLiveInfoApp) {
    let gradient_top = egui::Color32::from_rgb(12, 18, 28);
    let card_fill = egui::Color32::from_rgb(18, 26, 38);
    let accent = egui::Color32::from_rgb(45, 212, 191);
    let muted = egui::Color32::from_rgb(156, 163, 175);

    let heading = app
        .last_html_title
        .clone()
        .unwrap_or_else(|| "Latest Output".to_string());
    let generated_at = app
        .last_generated_at
        .clone()
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d %H:%M:%SZ").to_string());
    let body = app.filtered_output();

    ui.vertical_centered(|ui| {
        let header_frame = egui::Frame::none()
            .fill(gradient_top)
            .outer_margin(egui::Margin::symmetric(0.0, 8.0))
            .inner_margin(egui::Margin::symmetric(16.0, 12.0));
        header_frame.show(ui, |ui| {
            ui.label(
                RichText::new("Windows 10 Live Information")
                    .size(22.0)
                    .strong(),
            );
            ui.label(
                RichText::new(&generated_at)
                    .color(muted)
                    .size(14.0)
                    .family(egui::FontFamily::Monospace),
            );
            ui.add_space(4.0);
            let pill = egui::Frame::none()
                .fill(egui::Color32::from_rgb(18, 61, 55))
                .stroke(egui::Stroke::new(1.0, accent))
                .rounding(egui::Rounding::same(999.0))
                .inner_margin(egui::Margin::symmetric(10.0, 6.0));
            pill.show(ui, |ui| {
                ui.label(
                    RichText::new(format!("Action: {heading}"))
                        .color(egui::Color32::from_rgb(165, 243, 252))
                        .family(egui::FontFamily::Monospace),
                );
            });
        });
    });

    ui.add_space(6.0);

    let card = egui::Frame::none()
        .fill(card_fill)
        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(31, 41, 55)))
        .rounding(egui::Rounding::same(12.0))
        .inner_margin(egui::Margin::same(12.0))
        .outer_margin(egui::Margin::symmetric(8.0, 0.0));

    card.show(ui, |ui| {
        ui.label(
            RichText::new(&heading)
                .color(egui::Color32::from_rgb(224, 242, 254))
                .strong()
                .size(18.0),
        );
        ui.add_space(8.0);
        let mut scroll_body = body.clone();
        ScrollArea::vertical()
            .auto_shrink([false; 2])
            .show(ui, |ui| {
                ui.add(
                    TextEdit::multiline(&mut scroll_body)
                        .code_editor()
                        .desired_width(f32::INFINITY)
                        .desired_rows(28)
                        .font(TextStyle::Monospace)
                        .lock_focus(true)
                        .interactive(false),
                );
            });

        if let Some(path) = &app.last_html_path {
            ui.add_space(8.0);
            ui.label(
                RichText::new(format!("Saved to {}", path.display()))
                    .color(muted)
                    .family(egui::FontFamily::Monospace),
            );
        }
    });
}

fn render_functions_menu(ui: &mut egui::Ui, app: &mut WinLiveInfoApp) {
    let mut grouped: BTreeMap<Category, Vec<&Action>> = BTreeMap::new();
    for action in ACTIONS {
        grouped.entry(action.category).or_default().push(action);
    }

    for (category, actions) in grouped {
        ui.heading(category.label());
        for action in actions {
            if ui.button(action.label).clicked() {
                app.trigger_action(action);
                ui.close_menu();
            }
        }
        ui.separator();
    }
}

fn save_output(text: &str, ext: &str) -> Result<String, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let filename = format!("winliveinfo-output-{ts}.{ext}");
    let path = std::env::current_dir()
        .map_err(|e| e.to_string())?
        .join(filename);
    std::fs::write(&path, text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}

fn action_by_id(id: &str) -> Option<Action> {
    ACTIONS.iter().copied().find(|a| a.id == id)
}

struct HtmlReport {
    path: PathBuf,
    generated_at: String,
}

fn write_html_report(action: &Action, output: &str) -> Result<HtmlReport, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?;
    let safe_output = encode_safe(output);
    let safe_title = encode_safe(action.label);
    let dir = std::env::temp_dir().join("winliveinfo-html");
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let filename = format!("winliveinfo-{}-{}.html", action.id, ts.as_secs());
    let path = dir.join(filename);
    let path_string = path.display().to_string();
    let safe_path = encode_safe(&path_string);
    let generated_at = Utc::now().format("%Y-%m-%d %H:%M:%SZ");

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows 10 Live Info - {title}</title>
    <style>
        :root {{
            --bg: #0c1224;
            --panel: #0f172a;
            --accent: #1fbfa3;
            --muted: #cbd5e1;
            --text: #e9edf7;
            --border: #1f2937;
        }}
        * {{ box-sizing: border-box; }}
        body {{
            margin: 0;
            background: linear-gradient(135deg, #0b1221, #11182d);
            color: var(--text);
            font-family: "Cascadia Code", "Fira Code", Consolas, "Segoe UI", sans-serif;
            line-height: 1.6;
        }}
        header {{
            padding: 18px 22px;
            background: linear-gradient(90deg, rgba(31,191,163,0.14), rgba(12,18,36,0.9));
            border-bottom: 1px solid rgba(31,191,163,0.25);
            backdrop-filter: blur(6px);
        }}
        .title {{ font-size: 22px; font-weight: 700; letter-spacing: 0.3px; color: #f8fbff; text-shadow: 0 1px 8px rgba(0,0,0,0.35); }}
        .meta {{ color: #f8fbff; font-size: 13px; text-shadow: 0 1px 6px rgba(0,0,0,0.25); }}
        .pill {{
            display: inline-block;
            margin-top: 8px;
            padding: 6px 10px;
            border-radius: 999px;
            background: rgba(45, 212, 191, 0.12);
            color: #c1f0ff;
            border: 1px solid rgba(45, 212, 191, 0.55);
            font-size: 12px;
        }}
        main {{
            padding: 18px;
        }}
        .card {{
            background: var(--panel);
            border: 1px solid rgba(31, 191, 163, 0.15);
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.35);
            overflow: hidden;
        }}
        .card-header {{
            padding: 14px 16px;
            border-bottom: 1px solid rgba(31,191,163,0.25);
            background: linear-gradient(90deg, rgba(31,191,163,0.15), rgba(17,24,39,0.9));
            font-weight: 600;
            letter-spacing: 0.25px;
            color: #f8fbff;
            text-shadow: 0 1px 6px rgba(0,0,0,0.25);
        }}
        pre {{
            margin: 0;
            padding: 18px;
            background: #0c1530;
            color: #f4f7ff;
            font-size: 14px;
            line-height: 1.5;
            border-top: 1px solid rgba(31,191,163,0.12);
            white-space: pre-wrap;
            word-break: break-word;
        }}
        code {{ font-family: "Cascadia Code", "Fira Code", Consolas, monospace; }}
        .footer {{
            padding: 12px 16px;
            color: #f8fbff;
            font-size: 12px;
            border-top: 1px solid var(--border);
            background: #0c1423;
        }}
    </style>
</head>
<body>
    <header>
        <div class="title">Windows 10 Live Information</div>
        <div class="meta">{generated_at}</div>
        <div class="pill">Action: {action_label}</div>
    </header>
    <main>
        <div class="card">
            <div class="card-header">{title}</div>
            <pre><code>{safe_output}</code></pre>
            <div class="footer">Saved to {path}</div>
        </div>
    </main>
</body>
</html>
"#,
        title = safe_title,
        action_label = safe_title,
        generated_at = generated_at,
        safe_output = safe_output,
        path = safe_path
    );

    fs::write(&path, html.as_bytes()).map_err(|e| e.to_string())?;
    Ok(HtmlReport {
        path,
        generated_at: generated_at.to_string(),
    })
}

fn open_html_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err("HTML file not found".to_string());
    }
    let mut url = String::from("file:///");
    url.push_str(&path.to_string_lossy().replace('\\', "/"));
    webbrowser::open(&url).map_err(|e| format!("Failed to open HTML viewer: {e}"))
}

fn open_html_in_app(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err("HTML file not found".to_string());
    }
    open_html_file(path)
}

fn run_powershell_script(script: &str) -> Result<String, String> {
    let prelude = r#"
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
[void](chcp 65001)
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new()
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$OutputEncoding = [Console]::OutputEncoding
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['Format-Table:Wrap'] = $true
$PSDefaultParameterValues['Format-Table:AutoSize'] = $true
$PSDefaultParameterValues['Out-String:Width'] = 4096
$PSDefaultParameterValues['Out-File:Width'] = 4096
if ($PSVersionTable.PSVersion.Major -ge 7 -and $PSStyle -and $PSStyle.PSObject.Properties['OutputRendering']) {
    $PSStyle.OutputRendering = 'PlainText'
}
$global:LASTEXITCODE = 0
"#;

    let full_script = format!("{prelude}\n{script}");
    let mut utf16 = Vec::with_capacity(full_script.len() * 2);
    for unit in full_script.encode_utf16() {
        utf16.push((unit & 0xFF) as u8);
        utf16.push((unit >> 8) as u8);
    }
    let encoded = BASE64_STANDARD.encode(&utf16);

    let mut cmd = Command::new("powershell");
    cmd.args([
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Sta",
        "-WindowStyle",
        "Hidden",
        "-EncodedCommand",
        &encoded,
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let output = cmd
        .output()
        .map_err(|e| format!("Failed to start PowerShell: {e}"))?;

    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    if text.trim().is_empty() {
        text = String::from_utf8_lossy(&output.stderr).to_string();
    } else if !output.stderr.is_empty() {
        text.push_str("\n--- STDERR ---\n");
        text.push_str(&String::from_utf8_lossy(&output.stderr));
    }

    if output.status.success() {
        Ok(text)
    } else if text.trim().is_empty() {
        Err(format!(
            "PowerShell exited with status {:#?}",
            output.status.code()
        ))
    } else {
        Err(format!("{text}\n\n(Exit code: {:?})", output.status.code()))
    }
}

const COMPUTER_INFO: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "DATE & TIMEZONE"
Get-Date
Get-CimInstance -ClassName win32_timezone | Select Caption, StandardName, Bias, DaylightBias | Format-List
Write-Output "`nCOMPUTER SYSTEM"
Get-CimInstance -ClassName Win32_ComputerSystem | Format-List *
Write-Output "`nComputer"
Get-CimInstance -ClassName Win32_ComputerSystemProduct | Format-List *
Write-Output "`nMotherboard Info"
Get-CimInstance -ClassName Win32_BaseBoard | Format-List *
Write-Output "`nMemory Banks"
Get-CimInstance -ClassName Win32_PhysicalMemory | Select BankLabel, DeviceLocator, SerialNumber, PartNumber, Capacity, Manufacturer | Format-Table -AutoSize
$memory = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum
Write-Output ("Total installed physical RAM: {0:N2} GB" -f ($memory/1GB))
"#;

const OS_INFO: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "OPERATING SYSTEM"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, SerialNumber, RegisteredUser | Format-List
Write-Output "`nLicense Info"
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ProductId
Write-Output "`nHotfixes (latest 30)"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 30 | Format-Table -AutoSize HotFixID, Description, InstalledOn
Write-Output "`nStartup Time"
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
"#;

const USER_INFO: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "Local Users"
Get-LocalUser | Sort-Object Name | Format-Table -AutoSize Name, Enabled, LastLogon, PasswordLastSet, Description
Write-Output "`nGroups"
Get-LocalGroup | Sort-Object Name | ForEach-Object {
    Write-Output "`nGroup: $($_.Name)"
    Get-LocalGroupMember -Group $_.Name | Select-Object Name, ObjectClass | Format-Table -AutoSize
}
Write-Output "`nProfiles"
Get-CimInstance Win32_UserProfile | Select-Object LocalPath, Loaded, Special, LastUseTime | Sort-Object LocalPath | Format-Table -AutoSize
"#;

const ENV_INFO: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "Environment Variables"
Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize
Write-Output "`nUser Shell Folders"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" | Format-List
Write-Output "`nShell Folders"
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" | Format-List
Write-Output "`nCommon Shell Folders"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" | Format-List
"#;

const BITLOCKER_STATUS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "BITLOCKER STATUS"
Write-Output ""
try { manage-bde -status } catch { Write-Output "manage-bde not available: $_" }
Write-Output ""
Write-Output "EVENT LOG 'Microsoft-Windows-BitLocker-API' (Ids 768, 782, 796, 853)"
try {
    $events = Get-WinEvent -FilterHashtable @{ ProviderName = "Microsoft-Windows-BitLocker-API" } -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in 768,782,796,853 }
    $events | Sort-Object TimeCreated -Descending |
        Format-Table -AutoSize Id, TimeCreated, Message
} catch { Write-Output "Failed to read BitLocker events: $_" }
Write-Output ""
if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
    Write-Output "Key Protectors:"
    Get-BitLockerVolume | ForEach-Object {
        [pscustomobject]@{
            MountPoint = $_.MountPoint
            Protection = $_.ProtectionStatus
            Status     = $_.VolumeStatus
            Method     = $_.EncryptionMethod
            AutoUnlock = $_.AutoUnlockEnabled
            Recovery   = [string]($_.KeyProtector.RecoveryPassword)
        }
    } | Format-Table -AutoSize
} else {
    Write-Output "BitLocker module not available on this system."
}
"#;

const SERVICES: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Get-Service | Sort-Object Status, DisplayName | Format-Table -AutoSize Name, DisplayName, Status, StartType
"#;

const RUNNING_PROCESSES: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$procs = Get-Process | Sort-Object CPU -Descending | Select-Object -First 200 -Property Id, ProcessName, CPU, PM, StartTime, Path
foreach ($p in $procs) {
    "{0,-6} {1}" -f "Id:", $p.Id
    "{0,-6} {1}" -f "Name:", $p.ProcessName
    "{0,-6} {1:N3}" -f "CPU:", $p.CPU
    "{0,-6} {1:N1} MB" -f "PM:", ($p.PM / 1MB)
    "{0,-6} {1:yyyy-MM-dd HH:mm:ss}" -f "Start:", $p.StartTime
    "{0,-6} {1}" -f "Path:", ($p.Path -join '')
    "------------------------------------------------------------"
}
"#;

const CLOUD_APPS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$apps = 'OneDrive','Dropbox','GoogleDrive','Drive','Box','iCloud','Nextcloud','owncloud','Mega','Steam','OneDriveSetup'
Write-Output "Cloud storage process scan"
Write-Output ("Targets: " + ($apps -join ', '))
Write-Output ""
$procs = Get-Process | Where-Object { $apps -contains $_.ProcessName } | Sort-Object ProcessName
if ($procs) {
    foreach ($p in $procs) {
        "{0,-6} {1}" -f "Id:", $p.Id
        "{0,-6} {1}" -f "Name:", $p.ProcessName
        "{0,-6} {1:N3}" -f "CPU:", $p.CPU
        "{0,-6} {1:yyyy-MM-dd HH:mm:ss}" -f "Start:", $p.StartTime
        "{0,-6} {1}" -f "Path:", ($p.Path -join '')
        "------------------------------------------------------------"
    }
} else {
    Write-Output "No known cloud storage processes are currently running."
}
"#;

const ENCRYPTION_APPS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$apps = @(
 'veracrypt','truecrypt','diskcryptor','crypt','cipher','cloudfogger','folderlock','kruptos',
 'bitlocker','safehouse','sensiguard','privacydrive','rohos','sophos','securstick','mcshield','axcrypt',
 'pgp','symantec','checkpoint','kaspersky','emc','mcafee','trend','bromium','crowdstrike'
)
Write-Output "Searching running processes for encryption keywords:"
Write-Output ($apps -join ', ')
Write-Output ""
$procs = Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
    Select-Object Id, ProcessName, Path, UserName, StartTime, CPU
$hits = foreach ($p in $procs) {
    foreach ($k in $apps) {
        if ($p.ProcessName -match [regex]::Escape($k)) { $p; break }
    }
}
if ($hits) {
    foreach ($p in ($hits | Sort-Object Id)) {
        "{0,-6} {1}" -f "Id:", $p.Id
        "{0,-6} {1}" -f "Name:", $p.ProcessName
        "{0,-6} {1}" -f "User:", $p.UserName
        "{0,-6} {1:N3}" -f "CPU:", $p.CPU
        "{0,-6} {1:yyyy-MM-dd HH:mm:ss}" -f "Start:", $p.StartTime
        "{0,-6} {1}" -f "Path:", ($p.Path -join '')
        "------------------------------------------------------------"
    }
} else {
    Write-Output "No matching processes."
}
"#;

const SCHEDULED_TASKS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "SCHEDULED TASKS"
$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
if ($tasks) {
    $tasks | Sort-Object TaskPath, TaskName | ForEach-Object {
        $info = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath
        $triggers = ($_.Triggers | ForEach-Object { $_.ToString() }) -join '; '
        [pscustomobject]@{
            TaskPath = $_.TaskPath
            TaskName = $_.TaskName
            State    = $_.State
            Author   = $_.Author
            LastRun  = $info.LastRunTime
            NextRun  = $info.NextRunTime
            Triggers = $triggers
        }
    } | Format-Table -AutoSize -Wrap
} else {
    Write-Output "Get-ScheduledTask unavailable, using schtasks.exe /V"
    schtasks /Query /V /FO LIST
}
"#;

const STARTUP_AUTORUNS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "Startup (All Users)"
Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue |
    Select-Object Name, FullName, LastWriteTime | Format-Table -AutoSize
Write-Output "`nStartup (Current User)"
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" -ErrorAction SilentlyContinue |
    Select-Object Name, FullName, LastWriteTime | Format-Table -AutoSize
Write-Output "`nRegistry Run/Autorun Keys"
$runKeys = @(
 "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
 "HKCU:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
 "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows\Run",
 "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
 "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
 "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices",
 "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
 "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
 "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
 "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
 "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx",
 "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices",
 "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
 "HKLM:\System\CurrentControlSet\Services",
 "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components",
 "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components",
 "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
 "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
 "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects",
 "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects",
 "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad",
 "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
)
foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Write-Output "`n$key"
        Get-ItemProperty $key |
            Select-Object * -ExcludeProperty PS* |
            Where-Object { $_ } | Format-List
    }
}
Write-Output "`nWin32_StartupCommand"
Get-CimInstance Win32_StartupCommand | Sort-Object Name |
    Format-Table -Wrap -AutoSize Name, Command, Location, User
"#;

const STORAGE_INFO: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "Executed on: $(Get-Date -Format s)`n"
if (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager\Defrag" -ErrorAction SilentlyContinue) {
    $defrag = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager\Defrag"
    if ($defrag.LastRun) { Write-Output "Last 'Defrag' run: $($defrag.LastRun)" }
}
Write-Output "`nPHYSICAL MEDIA"
Get-CimInstance -ClassName Win32_PhysicalMedia | Sort-Object Tag |
    Format-Table -AutoSize Tag, SerialNumber
Write-Output "`nDISK DRIVES"
Get-CimInstance -ClassName Win32_DiskDrive | Sort-Object DeviceID |
    Format-Table -AutoSize Model, DeviceID, Partitions, Size
Write-Output "`nPARTITIONS"
Get-CimInstance -ClassName Win32_DiskPartition | Sort-Object Name |
    Format-Table -AutoSize Name, Description, BootPartition, Size
Write-Output "`nVOLUMES"
Get-CimInstance -ClassName Win32_Volume |
    Format-Table -AutoSize DriveLetter, Label, FileSystem, Capacity, FreeSpace
Write-Output "`nMAPPED/NETWORK DRIVES"
Get-CimInstance -ClassName Win32_NetworkConnection |
    Format-Table -AutoSize Name, LocalName, RemoteName, ProviderName
Write-Output "`nLOGICAL DISKS"
$types = @{
    "0" = "Unknown"; "1" = "No Root";
    "2" = "Removable"; "3" = "Local";
    "4" = "Network"; "5" = "CD/DVD"; "6" = "RAM"
}
$ldisks = Get-CimInstance Win32_LogicalDisk |
    Select-Object deviceid, drivetype, description, mediatype, size, volumename, volumeserialnumber, filesystem, providername
$ldisks | ForEach-Object {
    [pscustomobject]@{
        DeviceId    = $_.deviceid
        FileSystem  = $_.filesystem
        SerialNr    = $_.volumeserialnumber
        VolumeName  = $_.volumename
        SizeGB      = if ($_.size) { "{0:N0}" -f ($_.size/1GB) } else { "" }
        DriveType   = $types["$($_.drivetype)"]
        Description = $_.description
        Provider    = $_.providername
    }
} | Format-Table -AutoSize
"#;

const START_MENU_APPS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
if (Get-Command Get-StartApps -ErrorAction SilentlyContinue) {
    Get-StartApps | Sort-Object Name | Format-Table -AutoSize Name, AppId
} else {
    Write-Output "Get-StartApps cmdlet is not available on this build. Enumerating Start Menu shortcuts instead."
    $paths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    )
    foreach ($p in $paths) {
        if (Test-Path $p) {
            Write-Output "`n$p"
            Get-ChildItem $p -Filter *.lnk -Recurse -ErrorAction SilentlyContinue |
                Select-Object Name, FullName, LastWriteTime |
                Format-Table -AutoSize
        }
    }
}
"#;

const INSTALLED_PROGRAMS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "INSTALLED SOFTWARE (Registry, sorted by InstallDate)"
Write-Output "Sources:"
Write-Output "  HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
Write-Output "  HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
Write-Output "  HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
$paths = @(
 "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
 "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
 "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
)
$entries = foreach ($path in $paths) {
    Get-ItemProperty $path | Select-Object DisplayName, DisplayVersion, InstallDate, Publisher, InstallLocation, UninstallString
}
$entries = $entries | Where-Object { $_.DisplayName }
$normalized = foreach ($un in $entries) {
    $installDate = $null
    if ($un.InstallDate -and $un.InstallDate.Length -eq 8) {
        try { $installDate = [datetime]::ParseExact($un.InstallDate, "yyyyMMdd", $null) } catch { $installDate = $un.InstallDate }
    } elseif ($un.InstallDate -and $un.InstallDate.Length -eq 10) {
        try { $installDate = (Get-Date 01.01.1970).AddSeconds($un.InstallDate) } catch { $installDate = $un.InstallDate }
    }
    [pscustomobject]@{
        InstallDate     = $installDate
        DisplayName     = "$($un.DisplayName) (v.$($un.DisplayVersion))"
        Publisher       = $un.Publisher
        InstallLocation = $un.InstallLocation
        Uninstall       = $un.UninstallString
    }
}
$normalized | Sort-Object InstallDate -Descending | Format-Table -AutoSize InstallDate, DisplayName, Publisher, InstallLocation
"#;

const INSTALLED_APPS_UWP: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Get-AppxPackage | Sort-Object Name | Format-Table -AutoSize Name, Version, Architecture, InstallLocation, Publisher
"#;

const EXPLORER_FEATURE_USAGE: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "EXPLORER FEATURE USAGE"
Write-Output "(Source: HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage)"
Write-Output ""
$Launch = Get-Item -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppLaunch" -ErrorAction SilentlyContinue
$Jump   = Get-Item -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\AppSwitched" -ErrorAction SilentlyContinue
$Show   = Get-Item -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\ShowJumpView" -ErrorAction SilentlyContinue
$Tray   = Get-Item -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage\TrayButtonClicked" -ErrorAction SilentlyContinue

Write-Output "TrayButtonClicked (taskbar clicks)"
if ($Tray) {
    $Tray.Property |
        Where-Object { $_ -notlike "*PID*" } |
        ForEach-Object {
            [pscustomobject]@{ Button = $_; Clicked = $Tray.GetValue($_) }
        } | Sort-Object Clicked -Descending | Format-Table -AutoSize Clicked, Button
} else { Write-Output "No data." }
Write-Output ""

Write-Output "AppLaunch (pinned taskbar app launches)"
if ($Launch) {
    $Launch.Property |
        Where-Object { $_ -notlike "*PID*" } |
        ForEach-Object {
            [pscustomobject]@{ Application = $_; Launched = $Launch.GetValue($_) }
        } | Sort-Object Launched -Descending | Format-Table -AutoSize Launched, Application
} else { Write-Output "No data." }
Write-Output ""

Write-Output "AppSwitched (left-click switches)"
if ($Jump) {
    $Jump.Property |
        Where-Object { $_ -notlike "*PID*" } |
        ForEach-Object {
            [pscustomobject]@{ Application = $_; Switched = $Jump.GetValue($_) }
        } | Sort-Object Switched -Descending | Format-Table -AutoSize Switched, Application
} else { Write-Output "No data." }
Write-Output ""

Write-Output "ShowJumpView (right-clicks on taskbar icons)"
if ($Show) {
    $Show.Property |
        Where-Object { $_ -notlike "*PID*" } |
        ForEach-Object {
            [pscustomobject]@{ Application = $_; Viewed = $Show.GetValue($_) }
        } | Sort-Object Viewed -Descending | Format-Table -AutoSize Viewed, Application
} else { Write-Output "No data." }
"#;

const RUN_MRU: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
if (Test-Path $key) {
    $mru = Get-Item -Path $key -Force
    $list = $mru.GetValue("MruList")
    if ($list) {
        Write-Output "Entries sorted per MruList: $list"
        $order = $list.ToCharArray()
        $order | ForEach-Object {
            [pscustomobject]@{ Item = $_; Value = $mru.GetValue($_) }
        } | Format-Table -AutoSize
    } else {
        Write-Output "RunMRU key exists but no entries."
    }
} else { Write-Output "RunMRU key not found." }
"#;

const SEARCH_CORTANA: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery"
if (Test-Path $key) {
    Write-Output "Search/Cortana WordWheelQuery history"
    Get-ItemProperty $key | Format-List
} else { Write-Output "WordWheelQuery key not found." }
"#;

const BAM_ENTRIES: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
Write-Output "Current User's Background activity Moderator (BAM) entries"
Write-Output "(Related source: https://github.com/kacos2000/Win10/blob/master/Bam/readme.md)"
Write-Output "$($env:USERNAME) SID is $($sid)"
Write-Output ""

$bamKeys = @(
    "HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\${Sid}",
    "HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\UserSettings\${Sid}"
)

$bamEntries = @()
$failedKeys = @()

foreach ($bamKey in $bamKeys) {
    try {
        $bam = Get-Item -Path $bamKey -ErrorAction SilentlyContinue
        if (-not $bam) { $failedKeys += $bamKey; continue }
        Write-Output "(Source $($bamKeys.indexof($bamKey) + 1): '$($bamKey)')"
        Write-Output "BAM Version $($bam.getvalue('Version'))"
        Write-Output "BAM Sequence Number $($bam.getvalue('SequenceNumber'))"
        Write-Output "Entries: $($bam.ValueCount)"
        Write-Output ""
    } catch {
        $failedKeys += $bamKey
        continue
    }

    $bamEntries += foreach ($bamItem in $bam.GetValueNames()) {
        if ($bamItem -in ("Version", "SequenceNumber")) { continue }
        $hex = [System.BitConverter]::ToString($bam.getvalue($bamItem)[7..0]) -replace "-", ""
        $timeLocal = Get-Date ([DateTime]::FromFileTime([Convert]::ToInt64($hex, 16))) -Format o
        $typeH = [System.BitConverter]::ToString($bam.getvalue($bamItem)[19..16]) -replace "-", ""
        $type = [Convert]::ToInt64($typeH, 16)

        $d = if ((((split-path -path $bamItem) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
            ((Split-path -path $bamItem).Remove(23)).Trimstart("\Device\HarddiskVolume")
        } else { "" }

        $f = if ((((split-path -path $bamItem) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
            Split-path -leaf ($bamItem).TrimStart()
        } else { $bamItem }

        $cp = if ((((split-path -path $bamItem) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
            ($bamItem).Remove(1,23)
        } else { "" }

        $bpath = if ((((split-path -path $bamItem) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
            "(Vol$($d)) $cp"
        } else { "" }

        [pscustomobject]@{
            LastRun     = $timeLocal
            Application = $f
            Type        = $type
            Full_Path   = if ($type -eq 0) { $bpath } elseif ($type -eq 1) { "-(UWP) " + $bamItem } else { $bamItem }
        }
    }
}

if ($bamEntries) {
    $bamEntries | Sort-Object LastRun -Descending | Format-Table -AutoSize -Wrap
} elseif ($failedKeys.Count -gt 0) {
    Write-Output "Failed to read BAM keys (try running as Administrator):"
    $failedKeys | ForEach-Object { Write-Output "  $_" }
} else {
    Write-Output "No BAM entries for current user."
}
"#;

const PRIVACY_ACCESS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$base = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
if (-not (Test-Path $base)) {
    Write-Output "CapabilityAccessManager ConsentStore not found."
    return
}

function Convert-Time($t) {
    if (-not $t) { return "" }
    if ($t -is [string] -and $t -match '^\d+$') {
        try { return ([DateTime]::FromFileTimeUtc([int64]$t)).ToString("yyyy-MM-ddTHH:mm:ss") } catch {}
    }
    if ($t -is [int64]) {
        try { return ([DateTime]::FromFileTimeUtc($t)).ToString("yyyy-MM-ddTHH:mm:ss") } catch {}
    }
    return $t.ToString()
}

function Normalize-ExeName {
    param([string]$name)
    if (-not $name) { return "" }
    $clean = $name -replace '#','\' -replace '\|','\' -replace '"','' -replace "'",""
    $clean = $clean.TrimStart('\')
    if ($clean -like '*.exe') { return $clean }
    $parts = $clean -split '\\'
    $exePart = $parts | Where-Object { $_ -like '*.exe' } | Select-Object -Last 1
    if ($exePart) { return $exePart }
    return $clean
}

Write-Output "PRIVACY (Consent) Settings & Access Info"
Write-Output "User (HKCU) Consent Times & Apps"
Write-Output ""

$collectConsent = {
    param($root, $label)
    if (-not (Test-Path $root)) { return @() }
    $entries = foreach ($cap in Get-ChildItem $root) {
        foreach ($app in Get-ChildItem $cap.PSPath -Recurse) {
            $raw = $app.PSChildName
            $normalized = Normalize-ExeName $raw
            $sanitized = $raw -replace '#','\' -replace '\|','\'
            if ($normalized -notmatch '\.exe' -and $sanitized -notmatch '\.exe') { continue }
            $p = Get-ItemProperty $app.PSPath
            $start = $p.LastUsedTimeStart
            if (-not $start) { $start = $p.LastUsedTime }
            $stop = $p.LastUsedTimeStop
            if (-not $stop) { $stop = $p.LastUsedTime }
            [pscustomobject]@{
                Scope    = $label
                Parent   = $cap.PSChildName
                Name     = if ($sanitized) { $sanitized } else { $normalized }
                Setting  = $p.Value
                LastStart= Convert-Time $start
                LastStop = Convert-Time $stop
            }
        }
    }
    return $entries
}

$hkcu_rows = & $collectConsent $base "HKCU"
$hklm_base = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
$hklm_rows = & $collectConsent $hklm_base "HKLM"

if ($hkcu_rows) {
    $hkcu_rows | Sort-Object Parent, Name | Format-Table -AutoSize Parent, Name, Setting, LastStart, LastStop
} else {
    Write-Output "No .exe entries found in HKCU ConsentStore."
}

Write-Output "`nLocal Machine (HKLM) Consent Times & Apps`n"
if ($hklm_rows) {
    $hklm_rows | Sort-Object Parent, Name | Format-Table -AutoSize Parent, Name, Setting, LastStart, LastStop
} else {
    Write-Output "No .exe entries found in HKLM ConsentStore."
}

Write-Output "`nUser (HKCU) Privacy Settings`n"
$hkcuSettings = foreach ($cap in Get-ChildItem $base -ErrorAction SilentlyContinue) {
    $val = (Get-ItemProperty $cap.PSPath -ErrorAction SilentlyContinue).Value
    if ($null -ne $val) { [pscustomobject]@{ Name = $cap.PSChildName; Setting = $val } }
}
if ($hkcuSettings) {
    $hkcuSettings | Sort-Object Name | Format-Table -AutoSize
} else { Write-Output "No HKCU settings." }

Write-Output "`nLocal Machine (HKLM) Privacy Settings`n"
$hklmSettings = foreach ($cap in Get-ChildItem $hklm_base -ErrorAction SilentlyContinue) {
    $val = (Get-ItemProperty $cap.PSPath -ErrorAction SilentlyContinue).Value
    if ($null -ne $val) { [pscustomobject]@{ Name = $cap.PSChildName; Setting = $val } }
}
if ($hklmSettings) {
    $hklmSettings | Sort-Object Name | Format-Table -AutoSize
} else { Write-Output "No HKLM settings." }
"#;

const RECENT_FILES: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$path = "$env:USERPROFILE\Recent"
try {
    if (Test-Path $path) {
        Write-Output "RECENT FILES LIST from '$path'"
        $obj = New-Object -ComObject WScript.Shell -ErrorAction Stop
        Get-ChildItem $path -Filter *.lnk -File -Force -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 200 |
            ForEach-Object {
                try {
                    $shortcut = $obj.CreateShortcut($_.FullName)
                    [pscustomobject]@{
                        Name         = $_.Name
                        Target       = $shortcut.TargetPath
                        Arguments    = $shortcut.Arguments
                        LastWriteTime= $_.LastWriteTime
                        FullName     = $_.FullName
                    }
                } catch {
                    [pscustomobject]@{
                        Name         = $_.Name
                        Target       = ""
                        Arguments    = ""
                        LastWriteTime= $_.LastWriteTime
                        FullName     = $_.FullName
                    }
                }
            } | Format-Table -AutoSize -Wrap
    } else {
        Write-Output "Recent folder not found."
    }
} catch {
    Write-Output "Error enumerating Recent items: $_"
}
exit 0
"#;

const RECENT_DOCS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
if (Test-Path $key) {
    Write-Output "RECENT DOCS (Registry)"
    $ASCIIEncoding = New-Object System.Text.ASCIIEncoding
    $UnicodeEncoding = New-Object System.Text.UnicodeEncoding
    $ResultArray = @()
    Get-Item -Path $key -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty Property |
        ForEach-Object {
            $BinaryValue = Get-ItemProperty -Path $key -Name $_ | Select-Object -ExpandProperty $_
            $ASCIIValue = $ASCIIEncoding.GetString($BinaryValue)
            $HexValue = [System.BitConverter]::ToString($BinaryValue) -replace "-", ""
            $RecentDocs = [pscustomobject]@{ Name = $_; ASCII_Link_Name = ""; Unicode_Link_Name = "" }
            if ($HexValue -match "(([A-F0-9]{2}0{2}(?!0000))+[A-F0-9]{2}0{2})(0000..00320+)(([A-F0-9]{2}(?!00))+[A-F0-9]{2})(([A-F0-9](?!EFBE))+[A-F0-9]EFBE0+2E0+)(([A-F0-9]{2}0{2}(?!0000))+[A-F0-9]{2}0{2})(.*)") {
                $RecentDocs | Add-Member -NotePropertyName "NameDecoded" -NotePropertyValue ($UnicodeEncoding.GetString(($matches[1] -split "(..)" | Where-Object { $_ } | ForEach-Object { [byte]([convert]::ToInt16($_,16)) })))
                $RecentDocs.ASCII_Link_Name = ($ASCIIEncoding.GetString(($matches[4] -split "(..)" | Where-Object { $_ } | ForEach-Object { [byte]([convert]::ToInt16($_,16)) })))
                $RecentDocs.Unicode_Link_Name = ($UnicodeEncoding.GetString(($matches[8] -split "(..)" | Where-Object { $_ } | ForEach-Object { [byte]([convert]::ToInt16($_,16)) })))
            } elseif ($ASCIIValue -match "(([^\x00]\x00)+)\x00\x00.\x00\x32\x00+([^\x00]+)\x00\x00.+\x3F\x3F\x00+\x2E\x00+(([^\x00]\x00)+)") {
                $RecentDocs | Add-Member -NotePropertyName "NameDecoded" -NotePropertyValue $UnicodeEncoding.GetString($ASCIIEncoding.GetBytes($matches[1]))
                $RecentDocs.ASCII_Link_Name = $matches[3]
                $RecentDocs.Unicode_Link_Name = $UnicodeEncoding.GetString($ASCIIEncoding.GetBytes($matches[4]))
            }
            $ResultArray += $RecentDocs
        }
    $ResultArray | Sort-Object Name | Format-Table -AutoSize
} else { Write-Output "RecentDocs key not found." }
"#;

const POWERSHELL_HISTORY: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
if (Get-Command Get-PSReadlineOption -ErrorAction SilentlyContinue) {
    $path = (Get-PSReadlineOption).HistorySavePath
    Write-Output "PSReadLine history file: $path"
    if (Test-Path $path) {
        Get-Content $path -Tail 500
    } else {
        Write-Output "History file not found."
    }
} else {
    Write-Output "PSReadLine module not available."
}
"#;

const LIST_FAVOURITES: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$path = "$env:USERPROFILE\Favorites"
if (Test-Path $path) {
    Write-Output "Favorites for $path"
    Get-ChildItem $path -Recurse | Sort-Object FullName |
        Format-Table -AutoSize Name, LastWriteTime, FullName
} else {
    Write-Output "Favorites folder not found."
}
"#;

const USB_HISTORY: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "USBSTOR"
$usbStor = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
if (Test-Path $usbStor) {
    Get-ChildItem $usbStor | ForEach-Object {
        Write-Output "`nDevice: $($_.PSChildName)"
        Get-ChildItem $_.PSPath | ForEach-Object {
            Get-ItemProperty $_.PSPath |
                Select-Object FriendlyName, Service, Class, Driver, Mfg, InstallDate, ParentIdPrefix, ContainerID, CompatibleIDs |
                Format-List
        }
    }
} else {
    Write-Output "USBSTOR key not found."
}
Write-Output "`nMounted Volumes"
$mountPoints = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2"
if (Test-Path $mountPoints) {
    Get-ChildItem $mountPoints | ForEach-Object {
        Write-Output "`nMount: $($_.PSChildName)"
        Get-ItemProperty $_.PSPath | Format-List
    }
} else {
    Write-Output "MountPoints2 not found."
}
"#;

const NETWORK_INFO: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Write-Output "Adapters"
try {
    Get-NetAdapter | Sort-Object Name |
        Format-Table -AutoSize Name, InterfaceDescription, Status, LinkSpeed, MacAddress
} catch {
    Write-Output "Get-NetAdapter failed: $_"
}
Write-Output "`nIP Configuration"
try { Get-NetIPConfiguration | Format-List } catch { Write-Output "Get-NetIPConfiguration failed: $_" }
Write-Output "`nRoutes"
try {
    Get-NetRoute | Sort-Object InterfaceAlias, DestinationPrefix |
        Format-Table -AutoSize InterfaceAlias, DestinationPrefix, NextHop, RouteMetric
} catch {
    Write-Output "Get-NetRoute failed: $_"
}
Write-Output "`nDNS Servers"
try {
    Get-DnsClientServerAddress | Sort-Object InterfaceAlias |
        Format-Table -AutoSize InterfaceAlias, AddressFamily, ServerAddresses
} catch {
    Write-Output "Get-DnsClientServerAddress failed: $_"
}
Write-Output "`nARP Cache"
try {
    Get-NetNeighbor | Sort-Object InterfaceAlias, IPAddress |
        Format-Table -AutoSize InterfaceAlias, IPAddress, LinkLayerAddress, State
} catch {
    Write-Output "Get-NetNeighbor failed: $_"
}
Write-Output "`nFallback: ipconfig /all"
ipconfig /all
Write-Output "`nFallback: route print"
route print
Write-Output "`nFallback: arp -a"
arp -a
"#;

const PNP_DEVICES: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
Get-PnpDevice | Sort-Object Class, FriendlyName |
    Format-Table -AutoSize Status, Class, FriendlyName, Service, InstanceId
"#;

const PRINTERS: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
if (Get-Command Get-Printer -ErrorAction SilentlyContinue) {
    Get-Printer |
        Format-Table -AutoSize Name, DriverName, PortName, Shared, PrinterStatus, Comment, Location
} else {
    Write-Output "Get-Printer cmdlet not available on this system. Falling back to Win32_Printer."
    $printerstates = @{
        "0"  = "Other"; "1"  = "Unknown"; "2"  = "Idle"; "3"  = "Printing"; "4"  = "Warmup";
        "5"  = "Stopped Printing"; "6"  = "Offline"; "7"  = "Paused"; "8"  = "Error"; "9"  = "Busy";
        "10" = "Not Available"; "11" = "Waiting"; "12" = "Processing"; "13" = "Initialization";
        "14" = "Power Save"; "15" = "Pending Deletion"; "16" = "I/O Active"; "17" = "Manual Feed"
    }
    $printers = Get-CimInstance -ClassName Win32_Printer | Sort-Object -Property Name
    $printers | ForEach-Object {
        [pscustomobject]@{
            Name        = $_.Name
            Local       = $_.Local
            ShareName   = $_.ShareName
            System      = $_.SystemName
            State       = $printerstates["$($_.PrinterState)"]
            Status      = $_.PrinterStatus
            Location    = $_.Location
            KeepJobs    = if ($_.KeepPrintedJobs) { "Y" } else { "N" }
        }
    } | Format-Table -AutoSize
    Write-Output ""
    Get-CimInstance -ClassName Win32_PnPEntity | Where-Object { $_.PNPDeviceID -match "print" } |
        Sort-Object | Format-Table -Property Caption, Description, InstallDate, PNPDeviceID -AutoSize
}
"#;

const ACTIONS: &[Action] = &[
    Action {
        id: "computer_info",
        label: "Computer Information",
        category: Category::System,
        script: COMPUTER_INFO,
    },
    Action {
        id: "os_info",
        label: "Operating System Info",
        category: Category::System,
        script: OS_INFO,
    },
    Action {
        id: "users",
        label: "Users",
        category: Category::System,
        script: USER_INFO,
    },
    Action {
        id: "environment",
        label: "Environment + User Shell Folders",
        category: Category::System,
        script: ENV_INFO,
    },
    Action {
        id: "bitlocker",
        label: "BitLocker Status",
        category: Category::Security,
        script: BITLOCKER_STATUS,
    },
    Action {
        id: "services",
        label: "Services",
        category: Category::System,
        script: SERVICES,
    },
    Action {
        id: "running_processes",
        label: "Running Processes",
        category: Category::System,
        script: RUNNING_PROCESSES,
    },
    Action {
        id: "cloud_storage",
        label: "Cloud Storage Apps (Running)",
        category: Category::System,
        script: CLOUD_APPS,
    },
    Action {
        id: "encryption_apps",
        label: "Encryption Apps (Running)",
        category: Category::Security,
        script: ENCRYPTION_APPS,
    },
    Action {
        id: "scheduled_tasks",
        label: "Scheduled Tasks",
        category: Category::System,
        script: SCHEDULED_TASKS,
    },
    Action {
        id: "startup_autoruns",
        label: "Startup + Autoruns",
        category: Category::System,
        script: STARTUP_AUTORUNS,
    },
    Action {
        id: "storage_information",
        label: "Storage Information",
        category: Category::System,
        script: STORAGE_INFO,
    },
    Action {
        id: "start_menu",
        label: "Start Menu Applications",
        category: Category::Apps,
        script: START_MENU_APPS,
    },
    Action {
        id: "installed_programs",
        label: "Installed Programs (Registry)",
        category: Category::Apps,
        script: INSTALLED_PROGRAMS,
    },
    Action {
        id: "installed_apps",
        label: "Installed Windows Apps (UWP)",
        category: Category::Apps,
        script: INSTALLED_APPS_UWP,
    },
    Action {
        id: "explorer_feature_usage",
        label: "Explorer Feature Usage",
        category: Category::Explorer,
        script: EXPLORER_FEATURE_USAGE,
    },
    Action {
        id: "run_mru",
        label: "Explorer RunMru",
        category: Category::Explorer,
        script: RUN_MRU,
    },
    Action {
        id: "search_cortana",
        label: "Search/Cortana Mru",
        category: Category::Explorer,
        script: SEARCH_CORTANA,
    },
    Action {
        id: "bam_entries",
        label: "BAM Entries",
        category: Category::Security,
        script: BAM_ENTRIES,
    },
    Action {
        id: "privacy_access",
        label: "Privacy Info + Access Times",
        category: Category::Security,
        script: PRIVACY_ACCESS,
    },
    Action {
        id: "recent_files",
        label: "Recent Files (UserProfile)",
        category: Category::History,
        script: RECENT_FILES,
    },
    Action {
        id: "recent_docs",
        label: "RecentDocs",
        category: Category::History,
        script: RECENT_DOCS,
    },
    Action {
        id: "powershell_history",
        label: "PowerShell History",
        category: Category::History,
        script: POWERSHELL_HISTORY,
    },
    Action {
        id: "list_favourites",
        label: "List Favourites",
        category: Category::History,
        script: LIST_FAVOURITES,
    },
    Action {
        id: "usb_history",
        label: "USB /Mounted Device History",
        category: Category::History,
        script: USB_HISTORY,
    },
    Action {
        id: "network_information",
        label: "Network Information",
        category: Category::Network,
        script: NETWORK_INFO,
    },
    Action {
        id: "pnp_devices",
        label: "Plug'n'Play Devices",
        category: Category::Devices,
        script: PNP_DEVICES,
    },
    Action {
        id: "printers",
        label: "Printers",
        category: Category::Devices,
        script: PRINTERS,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_actions_return_text() {
        let mut failures = Vec::new();

        for action in ACTIONS {
            let result = run_powershell_script(action.script);
            match result {
                Ok(text) => {
                    let preview = text.lines().take(3).collect::<Vec<_>>().join(" | ");
                    println!(
                        "{}: {} bytes; preview -> {}",
                        action.id,
                        text.len(),
                        preview
                    );
                    if text.trim().is_empty() {
                        failures.push((action.id, "empty output".to_string()));
                    }
                }
                Err(err) => failures.push((action.id, err)),
            }
        }

        if !failures.is_empty() {
            let details = failures
                .into_iter()
                .map(|(id, err)| format!("{id}: {err}"))
                .collect::<Vec<_>>()
                .join("\n");
            panic!("Some actions failed:\n{details}");
        }
    }
}

pub fn run_winliveinfo() -> Result<(), eframe::Error> {
    let native_options = NativeOptions {
        viewport: ViewportBuilder::default().with_inner_size([1200.0, 720.0]),
        event_loop_builder: Some(Box::new(|builder| {
            // Allow event loop on a non-main thread so the CLI can keep running.
            #[cfg(windows)]
            {
                use winit::platform::windows::EventLoopBuilderExtWindows;
                builder.with_any_thread(true);
            }
        })),
        ..Default::default()
    };

    eframe::run_native(
        "Windows 10 Live Information viewer (Rust)",
        native_options,
        Box::new(|cc| Box::new(WinLiveInfoApp::new(cc))),
    )
}
