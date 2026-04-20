use windows::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_PROCESSED_OUTPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode,
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleCP,
    SetConsoleMode, SetConsoleOutputCP,
};

const UTF8_CODE_PAGE: u32 = 65001;

pub fn configure() {
    unsafe {
        let _ = SetConsoleCP(UTF8_CODE_PAGE);
        let _ = SetConsoleOutputCP(UTF8_CODE_PAGE);
    }
    configure_stream(STD_OUTPUT_HANDLE);
    configure_stream(STD_ERROR_HANDLE);
}

fn configure_stream(stream: windows::Win32::System::Console::STD_HANDLE) {
    let Ok(handle) = (unsafe { GetStdHandle(stream) }) else {
        return;
    };

    let mut mode = CONSOLE_MODE(0);
    if unsafe { GetConsoleMode(handle, &mut mode) }.is_err() {
        return;
    }

    let desired = mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    let _ = unsafe { SetConsoleMode(handle, desired) };
}

pub fn has_interactive_console() -> bool {
    stream_has_console(STD_INPUT_HANDLE) && stream_has_console(STD_OUTPUT_HANDLE)
}

fn stream_has_console(stream: windows::Win32::System::Console::STD_HANDLE) -> bool {
    let Ok(handle) = (unsafe { GetStdHandle(stream) }) else {
        return false;
    };

    let mut mode = CONSOLE_MODE(0);
    unsafe { GetConsoleMode(handle, &mut mode) }.is_ok()
}
