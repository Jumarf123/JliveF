use std::ffi::{CString, OsStr, c_char, c_void};
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

type HandleRaw = *mut c_void;
type ModuleRaw = *mut c_void;
type Bool = i32;
type Dword = u32;
type Word = u16;
type Byte = u8;

const DONT_RESOLVE_DLL_REFERENCES: Dword = 0x0000_0001;
const INVALID_HANDLE_VALUE: HandleRaw = -1isize as HandleRaw;
const MAX_MODULE_NAME32: usize = 255;
const MAX_PATH: usize = 260;
const PROCESS_QUERY_INFORMATION: Dword = 0x0400;
const PROCESS_QUERY_LIMITED_INFORMATION: Dword = 0x1000;
const PROCESS_VM_READ: Dword = 0x0010;
const TH32CS_SNAPMODULE: Dword = 0x0000_0008;
const TH32CS_SNAPMODULE32: Dword = 0x0000_0010;

const IMAGE_FILE_MACHINE_AMD64: Word = 0x8664;
const IMAGE_FILE_MACHINE_UNKNOWN: Word = 0;

#[repr(C)]
struct ModuleEntry32W {
    dw_size: Dword,
    th32_module_id: Dword,
    th32_process_id: Dword,
    glblcnt_usage: Dword,
    proccnt_usage: Dword,
    mod_base_addr: *mut Byte,
    mod_base_size: Dword,
    h_module: ModuleRaw,
    sz_module: [u16; MAX_MODULE_NAME32 + 1],
    sz_exe_path: [u16; MAX_PATH],
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn OpenProcess(desired_access: Dword, inherit_handle: Bool, process_id: Dword) -> HandleRaw;
    fn CloseHandle(handle: HandleRaw) -> Bool;
    fn ReadProcessMemory(
        process: HandleRaw,
        base_address: *const c_void,
        buffer: *mut c_void,
        size: usize,
        bytes_read: *mut usize,
    ) -> Bool;
    fn CreateToolhelp32Snapshot(flags: Dword, process_id: Dword) -> HandleRaw;
    fn Module32FirstW(snapshot: HandleRaw, entry: *mut ModuleEntry32W) -> Bool;
    fn Module32NextW(snapshot: HandleRaw, entry: *mut ModuleEntry32W) -> Bool;
    fn LoadLibraryExW(path: *const u16, file: HandleRaw, flags: Dword) -> ModuleRaw;
    fn FreeLibrary(module: ModuleRaw) -> Bool;
    fn GetProcAddress(module: ModuleRaw, name: *const c_char) -> *mut c_void;
    fn GetCurrentProcess() -> HandleRaw;
    fn IsWow64Process2(
        process: HandleRaw,
        process_machine: *mut Word,
        native_machine: *mut Word,
    ) -> Bool;
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub path: PathBuf,
    pub base: usize,
}

#[derive(Debug)]
pub struct ProcessHandle {
    pid: u32,
    handle: Handle,
}

#[derive(Debug)]
pub struct LocalLibrary {
    handle: ModuleRaw,
}

#[derive(Debug)]
struct Handle(HandleRaw);

impl ProcessHandle {
    pub fn open(pid: u32) -> io::Result<Self> {
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                0,
                pid,
            )
        };
        if handle.is_null() {
            return Err(last_error(format!("OpenProcess({pid})")));
        }

        let process = Self {
            pid,
            handle: Handle(handle),
        };
        process.ensure_x64()?;
        Ok(process)
    }

    pub fn read_bytes(&self, address: usize, len: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; len];
        self.read_exact(address, &mut buffer)?;
        Ok(buffer)
    }

    pub fn read_exact(&self, address: usize, buffer: &mut [u8]) -> io::Result<()> {
        if buffer.is_empty() {
            return Ok(());
        }
        if address == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "attempted to read from null address",
            ));
        }

        let mut bytes_read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle.0,
                address as *const c_void,
                buffer.as_mut_ptr() as *mut c_void,
                buffer.len(),
                &mut bytes_read,
            )
        };

        if ok == 0 {
            return Err(last_error(format!(
                "ReadProcessMemory(0x{address:016X}, {})",
                buffer.len()
            )));
        }
        if bytes_read != buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "short read at 0x{address:016X}: expected {}, got {bytes_read}",
                    buffer.len()
                ),
            ));
        }

        Ok(())
    }

    pub fn read_value<T: Copy>(&self, address: usize) -> io::Result<T> {
        let mut value = MaybeUninit::<T>::uninit();
        let slice = unsafe {
            std::slice::from_raw_parts_mut(value.as_mut_ptr() as *mut u8, size_of::<T>())
        };
        self.read_exact(address, slice)?;
        Ok(unsafe { value.assume_init() })
    }

    pub fn read_ptr(&self, address: usize) -> io::Result<usize> {
        self.read_value(address)
    }

    pub fn read_c_string(&self, address: usize, max_len: usize) -> io::Result<String> {
        if address == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "null C string pointer",
            ));
        }

        let mut bytes = Vec::with_capacity(max_len.min(128));
        let mut cursor = address;

        while bytes.len() < max_len {
            let chunk_len = (max_len - bytes.len()).min(64);
            let chunk = self.read_bytes(cursor, chunk_len)?;
            if let Some(pos) = chunk.iter().position(|&value| value == 0) {
                bytes.extend_from_slice(&chunk[..pos]);
                return Ok(String::from_utf8_lossy(&bytes).into_owned());
            }
            bytes.extend_from_slice(&chunk);
            cursor += chunk_len;
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unterminated C string at 0x{address:016X}"),
        ))
    }

    pub fn find_module(&self, module_name: &str) -> io::Result<ModuleInfo> {
        let snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(last_error("CreateToolhelp32Snapshot"));
        }
        let snapshot = Handle(snapshot);

        let mut entry = ModuleEntry32W {
            dw_size: size_of::<ModuleEntry32W>() as Dword,
            th32_module_id: 0,
            th32_process_id: 0,
            glblcnt_usage: 0,
            proccnt_usage: 0,
            mod_base_addr: null_mut(),
            mod_base_size: 0,
            h_module: null_mut(),
            sz_module: [0; MAX_MODULE_NAME32 + 1],
            sz_exe_path: [0; MAX_PATH],
        };

        let mut ok = unsafe { Module32FirstW(snapshot.0, &mut entry) };
        while ok != 0 {
            let name = utf16z_to_string(&entry.sz_module);
            if name.eq_ignore_ascii_case(module_name) {
                return Ok(ModuleInfo {
                    path: PathBuf::from(utf16z_to_string(&entry.sz_exe_path)),
                    base: entry.mod_base_addr as usize,
                });
            }

            ok = unsafe { Module32NextW(snapshot.0, &mut entry) };
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("module {module_name} not found in pid {}", self.pid),
        ))
    }

    fn ensure_x64(&self) -> io::Result<()> {
        if size_of::<usize>() != 8 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "this build must run as x86_64",
            ));
        }

        let current = MachineInfo::query(unsafe { GetCurrentProcess() })?;
        let target = MachineInfo::query(self.handle.0)?;
        if !current.is_x64() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "current process is not x64",
            ));
        }
        if !target.is_x64() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("target pid {} is not x64", self.pid),
            ));
        }

        Ok(())
    }
}

impl LocalLibrary {
    pub fn map_exports_only(path: &Path) -> io::Result<Self> {
        let wide = os_str_to_wide(path.as_os_str());
        let handle =
            unsafe { LoadLibraryExW(wide.as_ptr(), null_mut(), DONT_RESOLVE_DLL_REFERENCES) };
        if handle.is_null() {
            return Err(last_error(format!("LoadLibraryExW({})", path.display())));
        }
        Ok(Self { handle })
    }

    pub fn base_address(&self) -> usize {
        self.handle as usize
    }

    pub fn export_address(&self, name: &str) -> io::Result<usize> {
        let name = CString::new(name).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("export name contains NUL: {name:?}"),
            )
        })?;
        let address = unsafe { GetProcAddress(self.handle, name.as_ptr()) };
        if address.is_null() {
            return Err(last_error("GetProcAddress"));
        }
        Ok(address as usize)
    }

    pub fn export_rva(&self, name: &str) -> io::Result<usize> {
        Ok(self.export_address(name)? - self.base_address())
    }
}

impl Drop for LocalLibrary {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                FreeLibrary(self.handle);
            }
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MachineInfo {
    process_machine: Word,
    native_machine: Word,
}

impl MachineInfo {
    fn query(handle: HandleRaw) -> io::Result<Self> {
        let mut process_machine = 0u16;
        let mut native_machine = 0u16;
        let ok = unsafe { IsWow64Process2(handle, &mut process_machine, &mut native_machine) };
        if ok == 0 {
            return Err(last_error("IsWow64Process2"));
        }
        Ok(Self {
            process_machine,
            native_machine,
        })
    }

    fn is_x64(self) -> bool {
        self.native_machine == IMAGE_FILE_MACHINE_AMD64
            && self.process_machine == IMAGE_FILE_MACHINE_UNKNOWN
    }
}

fn utf16z_to_string(buffer: &[u16]) -> String {
    let len = buffer
        .iter()
        .position(|&value| value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..len])
}

fn os_str_to_wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn last_error(context: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("{}: {}", context.into(), io::Error::last_os_error()),
    )
}
