use std::path::Path;
use url::Url;
use winit::event::{Event, WindowEvent};
use winit::event_loop::EventLoopBuilder;
use winit::platform::windows::EventLoopBuilderExtWindows;
use winit::window::WindowBuilder;
use wry::WebViewBuilder;

use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize};

pub fn open_report(path: &Path) -> anyhow::Result<()> {
    unsafe {
        let hr = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        if hr == RPC_E_CHANGED_MODE {
            return Err(anyhow::anyhow!(
                "COM already initialized as MTA; cannot start WebView2 (STA required)"
            ));
        } else if hr.is_err() {
            return Err(anyhow::anyhow!(
                "Failed to initialize COM for WebView2: {:?}",
                hr
            ));
        }
    }
    struct ComGuard;
    impl Drop for ComGuard {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }
    let _com_guard = ComGuard;

    let event_loop = EventLoopBuilder::new().with_any_thread(true).build()?;
    let window = WindowBuilder::new()
        .with_title("Found Faker Report")
        .build(&event_loop)?;

    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let url = Url::from_file_path(&canonical)
        .map_err(|_| anyhow::anyhow!("Failed to convert report path to file URL"))?
        .to_string();

    let _webview = WebViewBuilder::new(&window).with_url(&url).build()?;

    event_loop.run(move |event, target| {
        if let Event::WindowEvent {
            event: WindowEvent::CloseRequested,
            ..
        } = event
        {
            target.exit();
        }
    })?;

    Ok(())
}
