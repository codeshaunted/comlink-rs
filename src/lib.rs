use log::{error, info};
use retour::static_detour;
use std::ffi::CStr;
use std::os::raw::c_void;
use std::{arch::naked_asm, ffi::c_char};
use winapi::um::winuser::{GetAsyncKeyState, VK_F5};
use winapi::{
    shared::{
        minwindef::{BOOL, DWORD, FALSE, HINSTANCE, LPVOID, TRUE},
        ntdef::HANDLE,
    },
    um::{
        consoleapi::AllocConsole,
        libloaderapi::{GetProcAddress, LoadLibraryA},
        memoryapi::VirtualProtect,
        processenv::SetStdHandle,
        winbase::STD_OUTPUT_HANDLE,
        winnt::DLL_PROCESS_ATTACH,
        winnt::PAGE_EXECUTE_READWRITE,
    },
};

mod foreign;

static mut FUNC_1: *const c_void = std::ptr::null();
static mut FUNC_2: *const c_void = std::ptr::null();
static mut FUNC_3: *const c_void = std::ptr::null();
static mut FUNC_4: *const c_void = std::ptr::null();
static mut FUNC_5: *const c_void = std::ptr::null();

#[unsafe(no_mangle)]
#[allow(unused_variables)]
pub extern "system" fn DllMain(
    dll_module: HINSTANCE,
    call_reason: DWORD,
    reserved: LPVOID,
) -> BOOL {
    match call_reason {
        DLL_PROCESS_ATTACH => init(),
        _ => TRUE,
    }
}

// pub fn patch<T>(dst: usize, new: T) {
//     unsafe {
//         let dst = dst as LPVOID;
//         let mut old_protect: DWORD = PAGE_EXECUTE_READWRITE;
//         VirtualProtect(
//             dst,
//             std::mem::size_of::<T>(),
//             PAGE_EXECUTE_READWRITE,
//             &mut old_protect,
//         );
//         *(dst as *mut T) = new;
//         VirtualProtect(dst, std::mem::size_of::<T>(), old_protect, &mut old_protect);
//     }
// }

// const JMP_OPCODE: u8 = 0xE9;
// pub fn detour(old: usize, new: LPVOID) {
// 	unsafe {
// 		let old = old as LPVOID;
// 		let jmp_distance: DWORD = new as DWORD - old as DWORD - 5;
// 		let mut old_protect: DWORD = PAGE_EXECUTE_READWRITE;
// 		VirtualProtect(old, 5, PAGE_EXECUTE_READWRITE, &mut old_protect);
// 		*(old as *mut u8) = JMP_OPCODE;
// 		*(((old as usize)+1) as *mut DWORD) = jmp_distance;
// 		VirtualProtect(old, 5, old_protect, &mut old_protect);
// 	}
// }

macro_rules! external_decl {
    (
        $addr:expr => $vis:vis fn $name:ident( $($arg_name:ident : $arg_type:ty),* $(,)? )
        -> $ret:ty
    ) => {
        $vis unsafe fn $name( $($arg_name : $arg_type),* ) -> $ret {
            type FnSig = unsafe extern "C" fn( $($arg_type),* ) -> $ret;
            unsafe {
                let function: FnSig = std::mem::transmute($addr as usize);

                info!("Calling function at address {:p}", function as *const c_void);

                function( $($arg_name),* )
            }
        }
    };
    (
        $addr:expr => $vis:vis const $name:ident : $ty:ty;
    ) => {
        $vis const $name: *mut $ty = unsafe { std::mem::transmute($addr as usize) };
    };
}

static_detour! {
  static MenuPCVideoSettingsDraw: extern "C" fn(*mut foreign::MENU_s);
}

static_detour! {
    static MenuPCVideoSettingsUpdate: extern "C" fn(*mut foreign::MENU_s);
}

const FULLSCREEN_ON: *const c_char = c"Fullscreen: On".as_ptr();
const FULLSCREEN_OFF: *const c_char = c"Fullscreen: Off".as_ptr();

fn menu_pc_video_settings_draw(menu: *mut foreign::MENU_s) -> () {
    unsafe {
        let text_ptr = if (*foreign::_d3dCore).windowed {
            FULLSCREEN_OFF
        } else {
            FULLSCREEN_ON
        };

        foreign::_DrawMenuEntryEx(menu, text_ptr as *mut c_char, *foreign::_MenuA);

        MenuPCVideoSettingsDraw.call(menu);
    }
}

fn menu_pc_video_settings_update(menu: *mut foreign::MENU_s) -> () {
    unsafe {
        if (*menu).entry_selected == 0
            && ((*menu).unknown_select_1 != 0
                || (*menu).unknown_select_2 != 0
                || (*menu).unknown_select_3 != 0)
        {
            (*foreign::_MenuSFX) = *foreign::_MENUSFX_MENUMOVE;
            (*foreign::_d3dCore).windowed = !(*foreign::_d3dCore).windowed;
        } else {
            (*menu).entry_selected -= 1;
            MenuPCVideoSettingsUpdate.call(menu);
            (*menu).entry_selected += 1;
        }
    }
}

static_detour! {
    static LoadPerm: extern "C" fn();
}

fn load_perm() -> () {
    unsafe {
        // if we turn off background loading, it skips the intro logos
        *foreign::_BGLOAD = 0;
        LoadPerm.call();

        // turn it back on for normal play
        *foreign::_BGLOAD = 1;
    }
}

fn init() -> BOOL {
    env_logger::init();

    unsafe {
        AllocConsole();
        SetStdHandle(STD_OUTPUT_HANDLE, 0 as HANDLE);
    }

    let dinput = unsafe { LoadLibraryA(c"C:\\Windows\\System32\\dinput8.dll".as_ptr()) };
    if dinput.is_null() {
        error!("Failed to load real dinput8.dll");
        return FALSE;
    }
    unsafe {
        FUNC_1 = std::mem::transmute(GetProcAddress(dinput, c"DirectInput8Create".as_ptr()));
        FUNC_2 = std::mem::transmute(GetProcAddress(dinput, c"DllCanUnloadNow".as_ptr()));
        FUNC_3 = std::mem::transmute(GetProcAddress(dinput, c"DllGetClassObject".as_ptr()));
        FUNC_4 = std::mem::transmute(GetProcAddress(dinput, c"DllRegisterServer".as_ptr()));
        FUNC_5 = std::mem::transmute(GetProcAddress(dinput, c"DllUnregisterServer".as_ptr()));
    }

    info!("Successfully loaded real dinput8.dll and forwarded functions");

    unsafe {
        MenuPCVideoSettingsDraw
            .initialize(std::mem::transmute(0x00511ea0), menu_pc_video_settings_draw)
            .unwrap();
        MenuPCVideoSettingsDraw.enable().unwrap();

        MenuPCVideoSettingsUpdate
            .initialize(
                std::mem::transmute(0x0050ef80),
                menu_pc_video_settings_update,
            )
            .unwrap();
        MenuPCVideoSettingsUpdate.enable().unwrap();

        LoadPerm
            .initialize(std::mem::transmute(0x004ca5b0), load_perm)
            .unwrap();
        LoadPerm.enable().unwrap();
    }

    TRUE
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "system" fn DirectInput8Create() {
    naked_asm!("jmp [{}]", sym FUNC_1);
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() {
    naked_asm!("jmp [{}]", sym FUNC_2);
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "system" fn DllGetClassObject() {
    naked_asm!("jmp [{}]", sym FUNC_3);
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "system" fn DllRegisterServer() {
    naked_asm!("jmp [{}]", sym FUNC_4);
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
pub extern "system" fn DllUnregisterServer() {
    naked_asm!("jmp [{}]", sym FUNC_5);
}
