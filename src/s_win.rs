use windows::core::HRESULT;

#[inline]
fn win32_err_string(err: HRESULT) -> String {
    err.message().to_string_lossy()
}

pub mod memory {
    use super::{process::get_last_error, win32_err_string};
    use std::{
        error::Error,
        ffi::c_void,
        mem::size_of,
        ptr::{self, null},
        slice::from_raw_parts_mut,
    };
    use windows::Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            Memory::{
                VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_DECOMMIT, MEM_RELEASE,
                PAGE_PROTECTION_FLAGS, VIRTUAL_ALLOCATION_TYPE, VIRTUAL_FREE_TYPE,
            },
        },
    };

    pub struct ForeignMemoryShadow(&'static mut [u8]);

    impl ForeignMemoryShadow {
        #[inline]
        pub fn n_bytes(&self) -> usize {
            self.0.len()
        }

        #[inline]
        pub fn start_addr(&self) -> *const u8 {
            self.0.as_ptr()
        }

        #[inline]
        unsafe fn start_addr_mut(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
    }

    #[inline]
    pub fn read_process_memory<T>(
        hprocess: HANDLE,
        lpbuffer: &mut [T],
        alloc: &ForeignMemoryShadow,
        lpnumberofbytesread: Option<*mut usize>,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(lpbuffer.len() * size_of::<T>(), alloc.n_bytes());

        let lpbaseaddress = (alloc.start_addr() as *const usize).cast::<c_void>();
        let lpbuffer = lpbuffer.as_mut_ptr().cast::<c_void>();
        let lpnumberofbytesread = lpnumberofbytesread.unwrap_or(ptr::null_mut());

        let res = unsafe {
            ReadProcessMemory(
                hprocess,
                lpbaseaddress,
                lpbuffer,
                alloc.n_bytes(),
                lpnumberofbytesread,
            )
            .as_bool()
        };

        match res {
            true => Ok(()),
            false => {
                let err = get_last_error();
                Err(win32_err_string(err.to_hresult()).into())
            }
        }
    }

    #[inline]
    pub fn write_process_memory<T>(
        hprocess: HANDLE,
        lpbuffer: &[T],
        alloc: &ForeignMemoryShadow,
        lpnumberofbyteswritten: Option<*mut usize>,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(alloc.n_bytes(), lpbuffer.len() * size_of::<T>());

        let lpbaseaddress = (alloc.start_addr() as *const usize).cast::<c_void>();
        let lpbuffer = lpbuffer.as_ptr().cast::<c_void>();
        let lpnumberofbyteswritten = lpnumberofbyteswritten.unwrap_or(ptr::null_mut());

        let res = unsafe {
            WriteProcessMemory(
                hprocess,
                lpbaseaddress,
                lpbuffer,
                alloc.n_bytes(),
                lpnumberofbyteswritten,
            )
            .as_bool()
        };

        match res {
            true => Ok(()),
            false => {
                let err = get_last_error();
                Err(win32_err_string(err.to_hresult()).into())
            }
        }
    }

    #[inline]
    pub fn virtual_protect_ex(
        hprocess: HANDLE,
        alloc: &ForeignMemoryShadow,
        flnewprotect: PAGE_PROTECTION_FLAGS,
        lpfloldprotect: &mut PAGE_PROTECTION_FLAGS,
    ) -> Result<(), Box<dyn Error>> {
        let lpaddress = (alloc.start_addr() as *const usize).cast::<c_void>();

        let res = unsafe {
            VirtualProtectEx(
                hprocess,
                lpaddress,
                alloc.n_bytes(),
                flnewprotect,
                lpfloldprotect,
            )
            .as_bool()
        };

        match res {
            true => Ok(()),
            false => {
                let err = get_last_error();
                Err(win32_err_string(err.to_hresult()).into())
            }
        }
    }

    #[inline]
    pub fn virtual_alloc_ex(
        hprocess: HANDLE,
        lpaddress: Option<usize>,
        dwsize: usize,
        flallocationtype: VIRTUAL_ALLOCATION_TYPE,
        flprotect: PAGE_PROTECTION_FLAGS,
    ) -> Result<ForeignMemoryShadow, Box<dyn Error>> {
        let res: *mut c_void;
        if let Some(lpaddress) = lpaddress {
            let lpaddress = (lpaddress as *const usize).cast::<c_void>();
            res =
                unsafe { VirtualAllocEx(hprocess, lpaddress, dwsize, flallocationtype, flprotect) };
        } else {
            let lpaddress = null::<usize>().cast::<c_void>();
            res =
                unsafe { VirtualAllocEx(hprocess, lpaddress, dwsize, flallocationtype, flprotect) };
        }

        match res.is_null() {
            true => {
                let err = get_last_error();
                Err(win32_err_string(err.to_hresult()).into())
            }
            false => {
                Ok(unsafe { ForeignMemoryShadow(from_raw_parts_mut(res.cast::<u8>(), dwsize)) })
            }
        }
    }

    #[inline]
    pub fn virtual_free_ex(
        hprocess: HANDLE,
        mut alloc: ForeignMemoryShadow,
        dwfreetype: VIRTUAL_FREE_TYPE,
        decommit_region: bool,
    ) -> Result<(), Box<dyn Error>> {
        let lpaddress = unsafe { alloc.start_addr_mut().cast::<c_void>() };
        let mut dwsize = alloc.n_bytes();

        if (dwfreetype == MEM_RELEASE) || (dwfreetype == MEM_DECOMMIT && decommit_region) {
            dwsize = 0;
        }

        let res = unsafe { VirtualFreeEx(hprocess, lpaddress, dwsize, dwfreetype).as_bool() };

        match res {
            true => Ok(()),
            false => {
                let err = get_last_error();
                Err(win32_err_string(err.to_hresult()).into())
            }
        }
    }
}
pub mod process {
    use super::win32_err_string;
    use std::{
        error::Error,
        ffi::c_void,
        mem,
        ptr::{self},
        time::Duration,
    };
    use windows::Win32::{
        Foundation::{CloseHandle, GetLastError, HANDLE, WIN32_ERROR},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
                CREATE_TOOLHELP_SNAPSHOT_FLAGS, PROCESSENTRY32W,
            },
            Threading::{
                CreateRemoteThread, OpenProcess, WaitForSingleObject, PROCESS_ACCESS_RIGHTS,
            },
            WindowsProgramming::INFINITE,
        },
    };

    #[inline]
    pub fn create_tool_help_32_snapshot(
        dwflags: CREATE_TOOLHELP_SNAPSHOT_FLAGS,
        th32processid: u32,
    ) -> Result<HANDLE, Box<dyn Error>> {
        let res = unsafe { CreateToolhelp32Snapshot(dwflags, th32processid) };

        match res {
            Ok(res) => Ok(res),
            Err(err) => Err(win32_err_string(err.code()).into()),
        }
    }

    #[inline]
    pub fn process_32_first_w(
        hsnapshot: HANDLE,
        lppe: &mut PROCESSENTRY32W,
    ) -> Result<(), Box<dyn Error>> {
        let res = unsafe { Process32FirstW(hsnapshot, lppe).as_bool() };

        match res {
            true => Ok(()),
            false => {
                let err = get_last_error();
                Err(win32_err_string(err.to_hresult()).into())
            }
        }
    }

    #[inline]
    pub fn process_32_next_w(
        hsnapshot: HANDLE,
        lppe: &mut PROCESSENTRY32W,
    ) -> Result<(), Box<dyn Error>> {
        let res = unsafe { Process32NextW(hsnapshot, lppe).as_bool() };

        match res {
            true => Ok(()),
            false => {
                let err = get_last_error();
                Err(win32_err_string(err.to_hresult()).into())
            }
        }
    }

    #[inline]
    pub fn open_process(
        dwdesiredaccess: PROCESS_ACCESS_RIGHTS,
        binherithandle: bool,
        dwprocessid: u32,
    ) -> Result<HANDLE, Box<dyn Error>> {
        let res = unsafe { OpenProcess(dwdesiredaccess, binherithandle, dwprocessid) };

        match res {
            Ok(res) => Ok(res),
            Err(err) => Err(win32_err_string(err.code()).into()),
        }
    }

    #[inline]
    pub fn get_last_error() -> WIN32_ERROR {
        unsafe { GetLastError() }
    }

    #[inline]
    pub fn close_handle(hobject: HANDLE) -> bool {
        unsafe { CloseHandle(hobject).as_bool() }
    }

    #[inline]
    pub fn create_remote_thread<T>(
        hprocess: HANDLE,
        dwstacksize: Option<usize>,
        lpstartaddress: usize,
        lpparameter: &T,
        dwcreationflags: u32,
        lpthreadid: Option<*mut u32>,
    ) -> Result<HANDLE, Box<dyn Error>> {
        let dwstacksize = dwstacksize.unwrap_or(0);
        let lpthreadid = lpthreadid.unwrap_or(ptr::null_mut());
        let lpparameter = (lpparameter as *const T).cast::<c_void>();

        let res = unsafe {
            CreateRemoteThread(
                hprocess,
                ptr::null(),
                dwstacksize,
                mem::transmute(lpstartaddress),
                lpparameter,
                dwcreationflags,
                lpthreadid,
            )
        };

        match res {
            Ok(res) => Ok(res),
            Err(err) => Err(win32_err_string(err.code()).into()),
        }
    }

    pub enum WfsoP2 {
        Zero,
        Infinite,
        Period(Duration),
    }

    #[inline]
    pub fn wait_for_single_object(hhandle: HANDLE, dwmilliseconds: WfsoP2) -> u32 {
        let dwmilliseconds = match dwmilliseconds {
            WfsoP2::Zero => 0,
            WfsoP2::Infinite => INFINITE,
            WfsoP2::Period(p) => p.as_millis() as u32,
        };
        unsafe { WaitForSingleObject(hhandle, dwmilliseconds) }
    }
}
pub mod wrapper {
    use std::{error::Error, ffi::OsString, mem::size_of, os::windows::prelude::OsStringExt};

    use windows::Win32::System::Diagnostics::ToolHelp::{PROCESSENTRY32W, TH32CS_SNAPPROCESS};

    use super::process::{
        close_handle, create_tool_help_32_snapshot, process_32_first_w, process_32_next_w,
    };

    #[inline]
    pub fn get_pid_by_name(name: &str) -> Result<u32, Box<dyn Error>> {
        let h_snap = create_tool_help_32_snapshot(TH32CS_SNAPPROCESS, 0)?;
        let mut pe32 = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if process_32_first_w(h_snap, &mut pe32).is_err() {
            close_handle(h_snap);
            return Err("Process32First".into());
        };
        loop {
            let n_exec = OsString::from_wide(pe32.szExeFile.as_slice());
            let n_exec = n_exec.into_string().unwrap().replace('\u{0}', "");

            if n_exec == name {
                close_handle(h_snap);
                return Ok(pe32.th32ProcessID);
            }

            if process_32_next_w(h_snap, &mut pe32).is_err() {
                close_handle(h_snap);
                break;
            }
        }
        Err("Process not found".into())
    }
}
#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use windows::Win32::System::{
        Memory::{MEM_COMMIT, MEM_RELEASE, PAGE_PROTECTION_FLAGS, PAGE_READONLY, PAGE_READWRITE},
        Threading::{PROCESS_ALL_ACCESS, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE},
    };

    use crate::s_win::{
        memory::{read_process_memory, virtual_free_ex, virtual_protect_ex, write_process_memory},
        process::close_handle,
    };

    use super::{memory::virtual_alloc_ex, process::open_process, wrapper::get_pid_by_name};

    #[test]
    fn test_get_pid_by_name() {
        let name = "ac_client.exe";
        let res = get_pid_by_name(name);
        assert!(res.is_ok())
    }

    #[test]
    fn test_open_process() {
        let name = "ac_client.exe";
        let pid = get_pid_by_name(name).unwrap();
        let res = open_process(PROCESS_ALL_ACCESS, false, pid);
        assert!(res.is_ok());
        close_handle(res.unwrap());
    }

    #[test]
    fn test_read_write() {
        let name = "ac_client.exe";
        let pid = get_pid_by_name(name).unwrap();
        let hprocess = open_process(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            false,
            pid,
        )
        .unwrap();

        const LEN: usize = 4 * size_of::<u8>();
        let mem = virtual_alloc_ex(hprocess, None, LEN, MEM_COMMIT, PAGE_READWRITE);
        assert!(mem.is_ok());

        let target_mem = mem.unwrap();
        let mut lpbuffer: [u8; LEN] = [u8::MAX, u8::MAX, u8::MAX, u8::MAX];

        let res = write_process_memory(hprocess, &lpbuffer[..], &target_mem, None);
        assert!(res.is_ok());

        lpbuffer = [u8::MIN, u8::MIN, u8::MIN, u8::MIN];
        let res = read_process_memory(hprocess, &mut lpbuffer, &target_mem, None);
        assert!(res.is_ok());
        assert_eq!(lpbuffer, [u8::MAX, u8::MAX, u8::MAX, u8::MAX]);

        let res = virtual_free_ex(hprocess, target_mem, MEM_RELEASE, false);
        assert!(res.is_ok());
        close_handle(hprocess);
    }

    #[test]
    fn test_protected_write() {
        // change READ_WRITE to READ_ONLY and try to write
        let name = "ac_client.exe";
        let pid = get_pid_by_name(name).unwrap();
        let hprocess = open_process(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            false,
            pid,
        )
        .unwrap();

        const LEN: usize = 4 * size_of::<u8>();
        let mem = virtual_alloc_ex(hprocess, None, LEN, MEM_COMMIT, PAGE_READWRITE).unwrap();
        write_process_memory(hprocess, &[u8::MAX, u8::MAX, u8::MAX, u8::MAX], &mem, None).unwrap();

        let mut prot: PAGE_PROTECTION_FLAGS = Default::default();
        let res = virtual_protect_ex(hprocess, &mem, PAGE_READONLY, &mut prot);
        assert!(res.is_ok());

        let res = write_process_memory(hprocess, &[u8::MIN, u8::MIN, u8::MIN, u8::MIN], &mem, None);
        assert!(res.is_err());

        virtual_free_ex(hprocess, mem, MEM_RELEASE, false).unwrap();
        close_handle(hprocess);
    }
}
