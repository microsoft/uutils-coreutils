// This file is part of the uutils coreutils package.
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

//! Windows NT API helpers with RAII wrappers.
#![allow(clippy::unreadable_literal)]

use std::fmt::Write as _;
use std::mem::MaybeUninit;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::SystemTime;
use std::{io, ptr};

use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Security::{
    GROUP_SECURITY_INFORMATION, GetFileSecurityW, GetLengthSid, LookupAccountSidW,
    OWNER_SECURITY_INFORMATION, PSID, SidTypeUnknown,
};

use crate::fsext::MetadataTimeField;

pub const READ_CONTROL: u32 = 0x00020000;
pub const SYNCHRONIZE: u32 = 0x00100000;
pub const FILE_READ_EA: u32 = 0x00000008;
pub const FILE_READ_ATTRIBUTES: u32 = 0x00000080;
pub const FILE_SHARE_READ: u32 = 0x00000001;
pub const FILE_SHARE_WRITE: u32 = 0x00000002;
pub const FILE_SHARE_DELETE: u32 = 0x00000004;
pub const FILE_DIRECTORY_FILE: u32 = 0x00000001;
pub const FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x00004000;
pub const FILE_OPEN_REPARSE_POINT: u32 = 0x00200000;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x00000020;
pub const FILE_OPEN_FOR_FREE_SPACE_QUERY: u32 = 0x00800000;

const OBJ_CASE_INSENSITIVE: u32 = 0x00000040;

pub const FILE_REMOTE_DEVICE: u32 = 0x00000010;

const FILE_ATTRIBUTE_READONLY: u32 = 0x00000001;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000000C;
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA0000003;

#[allow(non_upper_case_globals)]
pub const FileBasicInformation: u32 = 4;
#[allow(non_upper_case_globals)]
pub const FileFsVolumeInformation: u32 = 1;
#[allow(non_upper_case_globals)]
pub const FileFsDeviceInformation: u32 = 4;
#[allow(non_upper_case_globals)]
pub const FileFsAttributeInformation: u32 = 5;
#[allow(non_upper_case_globals)]
pub const FileFsFullSizeInformation: u32 = 7;
#[allow(non_upper_case_globals)]
pub const FileIdInformation: u32 = 59;
#[allow(non_upper_case_globals)]
pub const FileStatInformation: u32 = 68;
#[allow(non_upper_case_globals)]
pub const FileStatLxInformation: u32 = 70;

#[repr(C)]
pub struct FILE_FS_VOLUME_INFORMATION {
    pub volume_creation_time: i64,
    pub volume_serial_number: u32,
    pub volume_label_length: u32,
    pub supports_objects: u8,
    pub volume_label: [u16; 128],
}

#[repr(C)]
pub struct FILE_FS_DEVICE_INFORMATION {
    pub device_type: u32,
    pub characteristics: u32,
}

#[repr(C)]
pub struct FILE_FS_ATTRIBUTE_INFORMATION {
    pub file_system_attributes: u32,
    pub maximum_component_name_length: i32,
    pub file_system_name_length: u32,
    pub file_system_name: [u16; 128],
}

#[repr(C)]
pub struct FILE_FS_FULL_SIZE_INFORMATION {
    pub total_allocation_units: i64,
    pub caller_available_allocation_units: i64,
    pub actual_available_allocation_units: i64,
    pub sectors_per_allocation_unit: u32,
    pub bytes_per_sector: u32,
}

#[repr(C)]
pub struct FILE_ID_INFORMATION {
    pub volume_serial_number: u64,
    pub file_id: [u8; 16],
}

#[derive(Debug)]
#[repr(C)]
struct FILE_STAT_INFORMATION {
    file_id: i64,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    allocation_size: i64,
    end_of_file: i64,
    file_attributes: u32,
    reparse_tag: u32,
    number_of_links: u32,
    effective_access: u32,
}

#[derive(Debug)]
#[repr(C)]
struct FILE_STAT_LX_INFORMATION {
    file_id: i64,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    allocation_size: i64,
    end_of_file: i64,
    file_attributes: u32,
    reparse_tag: u32,
    number_of_links: u32,
    effective_access: u32,
    lx_flags: u32,
    lx_uid: u32,
    lx_gid: u32,
    lx_mode: u32,
    lx_device_id_major: u32,
    lx_device_id_minor: u32,
}

#[repr(C)]
struct UNICODE_STRING {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct OBJECT_ATTRIBUTES {
    length: u32,
    root_directory: *mut std::ffi::c_void,
    object_name: *const UNICODE_STRING,
    attributes: u32,
    security_descriptor: *mut std::ffi::c_void,
    security_quality_of_service: *mut std::ffi::c_void,
}

#[repr(C)]
struct IO_STATUS_BLOCK {
    status: NTSTATUS,
    information: usize,
}

unsafe extern "system" {
    fn NtOpenFile(
        file_handle: *mut *mut std::ffi::c_void,
        desired_access: u32,
        object_attributes: *const OBJECT_ATTRIBUTES,
        io_status_block: *mut IO_STATUS_BLOCK,
        share_access: u32,
        open_options: u32,
    ) -> NTSTATUS;

    fn NtClose(handle: *mut std::ffi::c_void) -> NTSTATUS;

    fn NtQueryInformationFile(
        file_handle: *mut std::ffi::c_void,
        io_status_block: *mut IO_STATUS_BLOCK,
        file_information: *mut std::ffi::c_void,
        length: u32,
        file_information_class: u32,
    ) -> NTSTATUS;

    fn NtQueryVolumeInformationFile(
        file_handle: *mut std::ffi::c_void,
        io_status_block: *mut IO_STATUS_BLOCK,
        fs_information: *mut std::ffi::c_void,
        length: u32,
        fs_information_class: u32,
    ) -> NTSTATUS;

    fn RtlDosPathNameToNtPathName_U(
        dos_file_name: *const u16,
        nt_file_name: *mut UNICODE_STRING,
        file_part: *mut *mut u16,
        reserved: *mut std::ffi::c_void,
    ) -> u8;

    fn RtlFreeUnicodeString(unicode_string: *mut UNICODE_STRING);
    fn RtlNtStatusToDosError(status: NTSTATUS) -> u32;
}

#[cold]
fn nt_status_to_io_error(status: NTSTATUS) -> io::Error {
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

#[repr(transparent)]
pub struct NtHandle(*mut std::ffi::c_void);

impl Drop for NtHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { NtClose(self.0) };
        }
    }
}

#[repr(transparent)]
struct UnicodeString(UNICODE_STRING);

impl UnicodeString {
    fn empty() -> Self {
        Self(UNICODE_STRING {
            length: 0,
            maximum_length: 0,
            buffer: ptr::null_mut(),
        })
    }
}

impl Drop for UnicodeString {
    fn drop(&mut self) {
        if !self.0.buffer.is_null() {
            unsafe { RtlFreeUnicodeString(&raw mut self.0) };
        }
    }
}

fn to_wide_null(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Opens a file or directory via `NtOpenFile`.
///
/// The file is opened with full share access (`READ | WRITE | DELETE`).
pub fn open_file(path: &Path, desired_access: u32, open_options: u32) -> io::Result<NtHandle> {
    let wide = to_wide_null(path);
    let mut nt_path = UnicodeString::empty();
    if unsafe {
        RtlDosPathNameToNtPathName_U(
            wide.as_ptr(),
            &raw mut nt_path.0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }

    let attr = OBJECT_ATTRIBUTES {
        length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        root_directory: ptr::null_mut(),
        object_name: &raw const nt_path.0,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: ptr::null_mut(),
        security_quality_of_service: ptr::null_mut(),
    };
    let mut handle = ptr::null_mut();
    let mut iosb = MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    let status = unsafe {
        NtOpenFile(
            &raw mut handle,
            desired_access,
            &raw const attr,
            iosb.as_mut_ptr(),
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            open_options,
        )
    };
    if status < 0 {
        return Err(nt_status_to_io_error(status));
    }
    Ok(NtHandle(handle))
}

/// Queries volume information for the file associated with the given handle.
///
/// # Safety
///
/// `T` must be the correct struct for the given `information_class`.
pub unsafe fn query_volume_information<T>(
    handle: &NtHandle,
    information_class: u32,
) -> io::Result<T> {
    let mut info = MaybeUninit::<T>::uninit();
    let mut iosb = MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    let status = unsafe {
        NtQueryVolumeInformationFile(
            handle.0,
            iosb.as_mut_ptr(),
            info.as_mut_ptr().cast(),
            size_of::<T>() as u32,
            information_class,
        )
    };
    if status < 0 {
        return Err(nt_status_to_io_error(status));
    }
    Ok(unsafe { info.assume_init() })
}

/// Queries file information for the given handle.
///
/// # Safety
///
/// `T` must be the correct struct for the given `information_class`.
pub unsafe fn query_information_file<T>(
    handle: &NtHandle,
    information_class: u32,
) -> io::Result<T> {
    let mut info = MaybeUninit::<T>::uninit();
    let mut iosb = MaybeUninit::<IO_STATUS_BLOCK>::uninit();
    let status = unsafe {
        NtQueryInformationFile(
            handle.0,
            iosb.as_mut_ptr(),
            info.as_mut_ptr().cast(),
            size_of::<T>() as u32,
            information_class,
        )
    };
    if status < 0 {
        return Err(io::Error::from_raw_os_error(status));
    }
    Ok(unsafe { info.assume_init() })
}

pub const SECURITY_MAX_SID_SIZE: usize = 68;
pub const SECURITY_MAX_SID_STRING_CHARACTERS: usize = 187;

pub type Sid = [u8; SECURITY_MAX_SID_SIZE];

#[repr(C)]
struct SECURITY_DESCRIPTOR_RELATIVE {
    revision: u8,
    sbz1: u8,
    control: u16,
    owner: u32,
    group: u32,
    sacl: u32,
    dacl: u32,
}

/// # Safety
/// `sd` must point to a valid self-relative security descriptor.
/// `offset` must be a valid SID offset within it, or 0.
unsafe fn sd_sid_to_fixed(sd: *const SECURITY_DESCRIPTOR_RELATIVE, offset: u32) -> Sid {
    let mut buf = [0u8; SECURITY_MAX_SID_SIZE];

    if offset != 0 {
        let psid = unsafe { sd.cast::<u8>().add(offset as usize) } as PSID;
        let len = unsafe { GetLengthSid(psid) } as usize;
        unsafe { ptr::copy_nonoverlapping(psid as *const u8, buf.as_mut_ptr(), len) };
    }

    buf
}

/// Turns a SID into a string.
pub fn sid_to_string(psid: &Sid) -> String {
    const SID_REVISION: u8 = 1;
    const SID_MAX_SUB_AUTHORITIES: usize = 15;
    const SID_HEADER_LEN: usize = 8;

    let sub_authority_count = psid[1] as usize;
    let sid_len = SID_HEADER_LEN + sub_authority_count * 4;
    if psid[0] != SID_REVISION
        || sub_authority_count > SID_MAX_SUB_AUTHORITIES
        || sid_len > psid.len()
    {
        return String::new();
    }

    let mut result = String::with_capacity(SECURITY_MAX_SID_STRING_CHARACTERS);
    result.push_str("S-1-");

    let identifier_authority =
        u64::from_be_bytes([0, 0, psid[2], psid[3], psid[4], psid[5], psid[6], psid[7]]);
    if identifier_authority > u32::MAX as u64 {
        _ = write!(result, "0x{identifier_authority:X}");
    } else {
        _ = write!(result, "{identifier_authority}");
    }

    for sub_authority in psid[SID_HEADER_LEN..sid_len].as_chunks::<4>().0 {
        let value = u32::from_le_bytes(*sub_authority);
        _ = write!(result, "-{value}");
    }

    result
}

/// Resolves a SID to an account name via `LookupAccountSidW`.
pub fn resolve_sid_to_name(psid: &Sid) -> String {
    let mut name_buf = [0u16; SECURITY_MAX_SID_STRING_CHARACTERS];
    let mut domain_buf = [0u16; SECURITY_MAX_SID_STRING_CHARACTERS];
    let mut name_len: u32 = name_buf.len() as u32;
    let mut domain_len: u32 = domain_buf.len() as u32;
    let mut sid_use = SidTypeUnknown;

    if unsafe {
        LookupAccountSidW(
            ptr::null(),
            // NOTE: The parameter is [in]. It does not modify the &Sid.
            psid.as_ptr().cast::<std::ffi::c_void>().cast_mut(),
            name_buf.as_mut_ptr(),
            &raw mut name_len,
            domain_buf.as_mut_ptr(),
            &raw mut domain_len,
            &raw mut sid_use,
        )
    } == 0
    {
        String::new()
    } else {
        String::from_utf16_lossy(&name_buf[..name_len as usize])
    }
}

#[derive(Debug)]
pub struct OwnerGroup {
    pub owner_sid: Sid,
    pub group_sid: Sid,
}

/// Retrieves owner and group SIDs via `GetFileSecurityW` into a
/// stack-allocated buffer. Returns `None` on failure.
pub fn path_to_owner_and_group(path: &Path) -> Option<OwnerGroup> {
    // The buffer must be u32-aligned for SECURITY_DESCRIPTOR_RELATIVE.
    #[repr(C)]
    struct SdBuf {
        sd: SECURITY_DESCRIPTOR_RELATIVE,
        sids: [u8; 2 * SECURITY_MAX_SID_SIZE],
    }

    let wide_path = to_wide_null(path);
    let mut buf = MaybeUninit::<SdBuf>::uninit();
    let mut needed: u32 = 0;

    if unsafe {
        GetFileSecurityW(
            wide_path.as_ptr(),
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION,
            buf.as_mut_ptr().cast(),
            size_of::<SdBuf>() as u32,
            &raw mut needed,
        )
    } == 0
    {
        return None;
    }

    let sd = buf.as_ptr().cast::<SECURITY_DESCRIPTOR_RELATIVE>();

    Some(OwnerGroup {
        owner_sid: unsafe { sd_sid_to_fixed(sd, (*sd).owner) },
        group_sid: unsafe { sd_sid_to_fixed(sd, (*sd).group) },
    })
}

#[derive(Debug, Clone, Copy)]
pub struct FileType {
    file_attributes: u32,
    reparse_tag: u32,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
impl FileType {
    pub fn is_dir(&self) -> bool {
        self.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0 && !self.is_symlink()
    }

    pub fn is_file(&self) -> bool {
        !self.is_dir() && !self.is_symlink()
    }

    pub fn is_symlink(&self) -> bool {
        self.reparse_tag == IO_REPARSE_TAG_SYMLINK || self.reparse_tag == IO_REPARSE_TAG_MOUNT_POINT
    }
}

pub trait FileTypeExt {
    fn is_fifo(&self) -> bool;
    fn is_char_device(&self) -> bool;
    fn is_block_device(&self) -> bool;
}

impl FileTypeExt for FileType {
    fn is_fifo(&self) -> bool {
        false
    }

    fn is_char_device(&self) -> bool {
        false
    }

    fn is_block_device(&self) -> bool {
        false
    }
}

#[derive(Debug)]
pub struct Metadata {
    file_type: FileType,
    len: u64,
    modified: SystemTime,
    accessed: SystemTime,
    created: SystemTime,
    mode: u32,
    blocks: u64,
    dev: u64,
    uid: u32,
    gid: u32,
    nlink: u64,
    ino: u64,
    blksize: u64,
    rdev: u64,
    user_name: Option<String>,
    group_name: Option<String>,
    change_time: Option<SystemTime>,
}

const LX_FILE_METADATA_HAS_UID: u32 = 0x1;
const LX_FILE_METADATA_HAS_GID: u32 = 0x2;
const LX_FILE_METADATA_HAS_MODE: u32 = 0x4;
const LX_FILE_METADATA_HAS_DEVICE_ID: u32 = 0x8;

fn file_open_options(dereference: bool) -> u32 {
    FILE_SYNCHRONOUS_IO_NONALERT
        | FILE_OPEN_FOR_BACKUP_INTENT
        | if dereference {
            0
        } else {
            FILE_OPEN_REPARSE_POINT
        }
}

impl Metadata {
    fn from_path(path: &Path, dereference: bool) -> io::Result<Self> {
        let handle = open_file(
            path,
            SYNCHRONIZE | READ_CONTROL | FILE_READ_EA | FILE_READ_ATTRIBUTES,
            file_open_options(dereference),
        )?;

        let mut stat: FILE_STAT_LX_INFORMATION = unsafe { std::mem::zeroed() };

        // FILE_STAT_LX_INFORMATION contains extra fields with WSL metadata.
        let mut status = unsafe {
            let mut iosb = MaybeUninit::<IO_STATUS_BLOCK>::uninit();
            NtQueryInformationFile(
                handle.0,
                iosb.as_mut_ptr(),
                (&raw mut stat).cast(),
                size_of::<FILE_STAT_LX_INFORMATION>() as u32,
                FileStatLxInformation,
            )
        };
        // ...but it may fail for some filesystems (e.g. SMB, ramdisks).
        // In that case, retry with FILE_STAT_INFORMATION.
        // NOTE: The base struct layout is identical.
        if status < 0 {
            status = unsafe {
                let mut iosb = MaybeUninit::<IO_STATUS_BLOCK>::uninit();
                NtQueryInformationFile(
                    handle.0,
                    iosb.as_mut_ptr(),
                    (&raw mut stat).cast(),
                    size_of::<FILE_STAT_INFORMATION>() as u32,
                    FileStatInformation,
                )
            };
        }
        if status < 0 {
            return Err(io::Error::from_raw_os_error(status));
        }

        let created = filetime_to_system_time(stat.creation_time);
        let accessed = filetime_to_system_time(stat.last_access_time);
        let modified = filetime_to_system_time(stat.last_write_time);
        let change_time = (stat.change_time > 0).then(|| filetime_to_system_time(stat.change_time));
        let allocation_size = stat.allocation_size.max(0) as u64;
        let len = stat.end_of_file.max(0) as u64;
        let file_type = FileType {
            file_attributes: stat.file_attributes,
            reparse_tag: stat.reparse_tag,
        };
        let nlink = stat.number_of_links as u64;
        let ino = stat.file_id as u64;
        let mode = if stat.lx_flags & LX_FILE_METADATA_HAS_MODE != 0 {
            stat.lx_mode
        } else {
            const S_IFLNK: u32 = 0o120_000;
            const S_IFREG: u32 = 0o100_000;
            const S_IFDIR: u32 = 0o040_000;
            let file_type_bits = if file_type.is_symlink() {
                S_IFLNK
            } else if file_type.is_dir() {
                S_IFDIR
            } else {
                S_IFREG
            };
            let permission_bits = if stat.file_attributes & FILE_ATTRIBUTE_READONLY != 0 {
                0o555
            } else {
                0o777
            };
            file_type_bits | permission_bits
        };
        let uid = if stat.lx_flags & LX_FILE_METADATA_HAS_UID != 0 {
            stat.lx_uid
        } else {
            0
        };
        let gid = if stat.lx_flags & LX_FILE_METADATA_HAS_GID != 0 {
            stat.lx_gid
        } else {
            0
        };
        let rdev = if stat.lx_flags & LX_FILE_METADATA_HAS_DEVICE_ID != 0 {
            (stat.lx_device_id_major as u64) << 32 | (stat.lx_device_id_minor as u64)
        } else {
            0
        };

        let dev = if let Ok(file_id) =
            unsafe { query_information_file::<FILE_ID_INFORMATION>(&handle, FileIdInformation) }
        {
            file_id.volume_serial_number
        } else {
            0
        };

        let blksize = if let Ok(vol) = unsafe {
            query_volume_information::<FILE_FS_FULL_SIZE_INFORMATION>(
                &handle,
                FileFsFullSizeInformation,
            )
        } {
            let bs = vol.sectors_per_allocation_unit as u64 * vol.bytes_per_sector as u64;
            if bs != 0 { bs } else { 4096 }
        } else {
            4096
        };

        let owner_group = path_to_owner_and_group(path);
        let user_name = owner_group
            .as_ref()
            .map(|og| resolve_sid_to_name(&og.owner_sid));
        let group_name = owner_group
            .as_ref()
            .map(|og| resolve_sid_to_name(&og.group_sid));

        Ok(Self {
            mode,
            blocks: allocation_size.div_ceil(512),
            file_type,
            len,
            modified,
            accessed,
            created,
            dev,
            uid,
            gid,
            nlink,
            ino,
            blksize,
            rdev,
            user_name,
            group_name,
            change_time,
        })
    }

    pub fn file_type(&self) -> FileType {
        self.file_type
    }

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.len
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn modified(&self) -> io::Result<SystemTime> {
        Ok(self.modified)
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn accessed(&self) -> io::Result<SystemTime> {
        Ok(self.accessed)
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn created(&self) -> io::Result<SystemTime> {
        Ok(self.created)
    }

    pub fn mode(&self) -> u32 {
        self.mode
    }

    pub fn blocks(&self) -> u64 {
        self.blocks
    }

    pub fn dev(&self) -> u64 {
        self.dev
    }

    pub fn gid(&self) -> u32 {
        self.gid
    }

    pub fn uid(&self) -> u32 {
        self.uid
    }

    pub fn nlink(&self) -> u64 {
        self.nlink
    }

    pub fn ino(&self) -> u64 {
        self.ino
    }

    pub fn blksize(&self) -> u64 {
        self.blksize
    }

    pub fn rdev(&self) -> u64 {
        self.rdev
    }

    pub fn user_name(&self) -> Option<&str> {
        self.user_name.as_deref()
    }

    pub fn group_name(&self) -> Option<&str> {
        self.group_name.as_deref()
    }

    pub fn change_time(&self) -> Option<SystemTime> {
        self.change_time
    }
}

pub fn metadata<P: AsRef<Path>>(path: P) -> io::Result<Metadata> {
    Metadata::from_path(path.as_ref(), true)
}

pub fn symlink_metadata<P: AsRef<Path>>(path: P) -> io::Result<Metadata> {
    Metadata::from_path(path.as_ref(), false)
}

pub fn metadata_get_time(metadata: &Metadata, md_time: MetadataTimeField) -> Option<SystemTime> {
    match md_time {
        MetadataTimeField::Change => metadata.change_time,
        MetadataTimeField::Modification => Some(metadata.modified),
        MetadataTimeField::Access => Some(metadata.accessed),
        MetadataTimeField::Birth => Some(metadata.created),
    }
}

const _: () = unsafe {
    assert!(
        std::mem::transmute::<SystemTime, i64>(std::time::UNIX_EPOCH)
            == 11_644_473_600 * 10_000_000
    );
};

fn filetime_to_system_time(value: i64) -> SystemTime {
    unsafe { std::mem::transmute::<i64, SystemTime>(value) }
}
