//! HIP (Host Information Profile) report generation.
//!
//! GlobalProtect gateways can gate VPN access on a "host integrity
//! check" — a signed XML document describing the client's OS,
//! antivirus, firewall, and disk-encryption state. Administrators
//! typically configure policies like "require Defender real-time
//! protection enabled" or "require disk encryption" and reject
//! clients whose HIP report doesn't satisfy them.
//!
//! # Scope of this crate
//!
//! This crate produces the XML document. It deliberately does NOT:
//!
//! * Submit the report over HTTP — that belongs in the HTTP client
//!   (`gp-auth::GpClient`) alongside the other `/ssl-vpn/*.esp`
//!   endpoints.
//! * Interact with `libopenconnect`'s built-in `--csd-wrapper` hook
//!   — we do the submission ourselves in Rust for the same
//!   "architecture rule" reasons the rest of the project already
//!   follows (`gp-route`, `gp-dns`).
//! * Perform real OS/antivirus introspection. The current profiles
//!   are template-based and keyed off the caller's `client_os`
//!   choice (`Windows`, `Linux`, or `Mac`), matching the identity
//!   already presented in the HTTP headers.
//!
//! # Why match `client_os`?
//!
//! The HIP report has to be internally consistent with the rest of
//! the GlobalProtect session. Sending `clientos=Linux` on the HTTP
//! side but a hard-coded Windows HIP XML gives the gateway two
//! conflicting identities for the same client, which strict policy
//! engines may reject or score differently.
//!
//! # XML structure
//!
//! ```text
//! <hip-report name="hip-report">
//!   <md5-sum>…</md5-sum>
//!   <user-name>…</user-name>
//!   <domain>…</domain>
//!   <host-name>…</host-name>
//!   <host-id>…</host-id>
//!   <ip-address>…</ip-address>
//!   <generate-time>MM/DD/YYYY HH:MM:SS</generate-time>
//!   <categories>
//!     <entry name="host-info">
//!       <client-version>…</client-version>
//!       <os>…</os>
//!       <os-vendor>…</os-vendor>
//!       <domain>…</domain>
//!       <host-name>…</host-name>
//!       <host-id>…</host-id>
//!     </entry>
//!     <entry name="antivirus">…</entry>
//!     <entry name="disk-backup">…</entry>
//!     <entry name="disk-encryption">…</entry>
//!     <entry name="firewall">…</entry>
//!   </categories>
//! </hip-report>
//! ```
//!
//! The `md5-sum` is **not** computed locally — the gateway tells
//! the client which hash to include via the
//! `/ssl-vpn/hipreportcheck.esp` response, and the client echoes
//! it back unchanged in the submission.

#[cfg(unix)]
use std::ffi::CStr;
use std::fs;

/// Version string reported in the HIP `<client-version>` element.
///
/// NOTE: this is a distinct field from `gp-proto::GpParams::
/// client_version`, which carries the numeric `clientVer` build
/// code (`"4100"`) sent as an HTTP form parameter on the portal /
/// gateway login endpoints. The HIP `client-version` is the
/// user-visible release string the gateway shows in its policy
/// logs — they are two different protocol fields and must not be
/// unified into a single constant.
pub const DEFAULT_CLIENT_VERSION: &str = "5.1.0-28";

/// Generic Linux/WSL fallback used when we can't read any machine
/// ID off disk. This is a purely placeholder UUID — real hosts
/// should populate it from `/etc/machine-id`.
const DEFAULT_HOST_ID_FALLBACK: &str = "00000000-0000-0000-0000-000000000000";

/// HIP profile family to emit. Distinct from the gateway-facing
/// `clientos` / openconnect strings: this only drives the XML
/// shape and canned product inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HipOs {
    Windows,
    Mac,
    Linux,
}

impl HipOs {
    pub fn from_client_os_arg(client_os: Option<&str>) -> Self {
        match client_os
            .unwrap_or("Windows")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "linux" => Self::Linux,
            "mac" | "macos" | "darwin" => Self::Mac,
            "win" | "windows" => Self::Windows,
            _ => Self::Windows,
        }
    }
}

/// Host-level facts we introspect (hostname, machine id) so the
/// HIP report can reference them. Separated from [`HostProfile`] so
/// tests can stub in fixtures without touching the host.
#[derive(Debug, Clone)]
pub struct HostInfo {
    /// Hostname reported to the gateway. Detected via
    /// `gethostname(2)` on Unix; falls back to `"localhost"`.
    pub host_name: String,
    /// Stable per-host identifier. Detected from `/etc/machine-id`
    /// (or `/var/lib/dbus/machine-id` as a fallback), normalised
    /// into a lowercase dash-separated UUID form.
    pub host_id: String,
}

impl HostInfo {
    /// Read the host's real facts. On failure, falls back to
    /// safe placeholders rather than erroring.
    pub fn detect() -> Self {
        Self {
            host_name: detect_hostname().unwrap_or_else(|| "localhost".to_string()),
            host_id: detect_machine_id().unwrap_or_else(|| DEFAULT_HOST_ID_FALLBACK.to_string()),
        }
    }

    /// Deterministic fixture — identical to [`HostInfo::detect`]'s
    /// full-fallback output. Useful for tests.
    pub fn placeholder() -> Self {
        Self {
            host_name: "localhost".into(),
            host_id: DEFAULT_HOST_ID_FALLBACK.into(),
        }
    }
}

/// Declarative description of the host profile we claim in the
/// report. This is the part administrators actually check in their
/// policies (antivirus running, firewall on, etc.), so getting it
/// wrong is the difference between "connected with restrictions"
/// and "rejected outright."
///
/// Pangolin ships canned profiles for Windows, macOS, and Linux.
/// Callers who need to claim a different posture can still
/// construct one directly.
#[derive(Debug, Clone)]
pub struct HostProfile {
    /// Which XML category family to emit.
    pub hip_os: HipOs,
    /// Claimed OS product string, e.g. `"Microsoft Windows 10 Pro, 64-bit"`.
    pub os: String,
    /// Claimed OS vendor, e.g. `"Microsoft"`.
    pub os_vendor: String,
    /// Domain the client claims to be joined to. Many deployments
    /// don't care; use an empty string if you don't know.
    pub domain: String,
    /// Installed antivirus products (name + version, real-time on/off).
    pub antivirus: Vec<AntivirusProduct>,
    /// Host firewall products.
    pub firewall: Vec<FirewallProduct>,
    /// Disk encryption products.
    pub disk_encryption: Vec<DiskEncryptionProduct>,
    /// Disk backup products. Many gateways silently require at
    /// least one entry in this category even if they don't
    /// enforce policy on it.
    pub disk_backup: Vec<DiskBackupProduct>,
}

#[derive(Debug, Clone)]
pub struct AntivirusProduct {
    pub vendor: String,
    pub name: String,
    pub version: String,
    /// Definition / signature version, e.g. `"1.245.683.0"`. Required
    /// on Windows AV `Prod` elements — policies that check "AV
    /// definitions current" validate this field.
    pub defver: String,
    /// Engine version, e.g. `"1.1.13804.0"`.
    pub engver: String,
    pub real_time_protection: bool,
    /// Format: `MM/DD/YYYY HH:MM:SS`.
    pub last_full_scan_time: String,
}

#[derive(Debug, Clone)]
pub struct FirewallProduct {
    pub vendor: String,
    pub name: String,
    pub version: String,
    /// `"yes"`, `"no"`, or `"n/a"`.
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct DiskEncryptionProduct {
    pub vendor: String,
    pub name: String,
    pub version: String,
    /// e.g. `"C:\\"`, `"full"`.
    pub drive: String,
    /// `"encrypted"` or `"not-encrypted"`.
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct DiskBackupProduct {
    pub vendor: String,
    pub name: String,
    pub version: String,
    /// `"MM/DD/YYYY HH:MM:SS"`.
    pub last_backup_time: String,
}

impl HostProfile {
    pub fn from_client_os(client_os: Option<&str>) -> Self {
        match HipOs::from_client_os_arg(client_os) {
            HipOs::Windows => Self::spoofed_windows(),
            HipOs::Mac => Self::spoofed_macos(),
            HipOs::Linux => Self::spoofed_linux(),
        }
    }

    /// Plausible Windows 10 + Defender + Firewall profile. This
    /// matches what a typical `openconnect trojans/hipreport.sh`
    /// run produces when given a Windows gateway. Most corporate
    /// GP deployments accept it.
    pub fn spoofed_windows() -> Self {
        Self {
            hip_os: HipOs::Windows,
            os: "Microsoft Windows 10 Pro , 64-bit".into(),
            os_vendor: "Microsoft".into(),
            domain: String::new(),
            antivirus: vec![AntivirusProduct {
                vendor: "Microsoft Corp.".into(),
                name: "Windows Defender".into(),
                version: "4.18.24080.9".into(),
                // These values match the sort of thing openconnect's
                // reference trojans/hipreport.sh emits for Windows.
                // Policies that check "AV definitions present" want
                // non-empty defver/engver.
                defver: "1.415.12.0".into(),
                engver: "1.1.24080.9".into(),
                real_time_protection: true,
                last_full_scan_time: "01/01/2024 00:00:00".into(),
            }],
            firewall: vec![FirewallProduct {
                vendor: "Microsoft Corp.".into(),
                name: "Microsoft Windows Firewall".into(),
                version: "10.0".into(),
                status: "yes".into(),
            }],
            disk_encryption: vec![DiskEncryptionProduct {
                vendor: "Microsoft Corp.".into(),
                name: "Windows Drive Encryption".into(),
                version: "10.0.15063.0".into(),
                drive: "C:\\".into(),
                status: "full".into(),
            }],
            disk_backup: vec![DiskBackupProduct {
                vendor: "Microsoft Corp.".into(),
                name: "Windows Backup and Restore".into(),
                version: "10.0.15063.0".into(),
                last_backup_time: "01/01/2024 00:00:00".into(),
            }],
        }
    }

    pub fn spoofed_macos() -> Self {
        Self {
            hip_os: HipOs::Mac,
            os: "Apple Mac OS X 13.0".into(),
            os_vendor: "Apple".into(),
            domain: String::new(),
            antivirus: vec![
                AntivirusProduct {
                    vendor: "Apple Inc.".into(),
                    name: "Xprotect".into(),
                    version: "2167".into(),
                    defver: "235000000000000".into(),
                    engver: String::new(),
                    real_time_protection: true,
                    last_full_scan_time: "n/a".into(),
                },
                AntivirusProduct {
                    vendor: "Apple Inc.".into(),
                    name: "Gatekeeper".into(),
                    version: "13.0".into(),
                    defver: String::new(),
                    engver: String::new(),
                    real_time_protection: true,
                    last_full_scan_time: "n/a".into(),
                },
            ],
            firewall: vec![
                FirewallProduct {
                    vendor: "Apple Inc.".into(),
                    name: "Mac OS X Builtin Firewall".into(),
                    version: "13.0".into(),
                    status: "yes".into(),
                },
                FirewallProduct {
                    vendor: "OpenBSD".into(),
                    name: "Packet Filter".into(),
                    version: "13.0".into(),
                    status: "no".into(),
                },
            ],
            disk_encryption: vec![
                DiskEncryptionProduct {
                    vendor: "Apple Inc.".into(),
                    name: "FileVault".into(),
                    version: "13.0".into(),
                    drive: "Macintosh HD".into(),
                    status: "encrypted".into(),
                },
                DiskEncryptionProduct {
                    vendor: "Apple Inc.".into(),
                    name: "FileVault".into(),
                    version: "13.0".into(),
                    drive: "Data".into(),
                    status: "encrypted".into(),
                },
                DiskEncryptionProduct {
                    vendor: "Apple Inc.".into(),
                    name: "FileVault".into(),
                    version: "13.0".into(),
                    drive: "All".into(),
                    status: "encrypted".into(),
                },
            ],
            disk_backup: vec![DiskBackupProduct {
                vendor: "Apple Inc.".into(),
                name: "Time Machine".into(),
                version: "1.3".into(),
                last_backup_time: "n/a".into(),
            }],
        }
    }

    pub fn spoofed_linux() -> Self {
        Self {
            hip_os: HipOs::Linux,
            os: "Linux 6.1".into(),
            os_vendor: "Linux".into(),
            domain: String::new(),
            antivirus: Vec::new(),
            firewall: vec![
                FirewallProduct {
                    vendor: "IPTables".into(),
                    name: "IPTables".into(),
                    version: "1.8.4".into(),
                    status: "no".into(),
                },
                FirewallProduct {
                    vendor: "The Netfilter Project".into(),
                    name: "nftables".into(),
                    version: "0.9.3".into(),
                    status: "n/a".into(),
                },
            ],
            disk_encryption: vec![DiskEncryptionProduct {
                vendor: "GitLab Inc.".into(),
                name: "cryptsetup".into(),
                version: "2.3.3".into(),
                drive: "/".into(),
                status: "encrypted".into(),
            }],
            disk_backup: Vec::new(),
        }
    }
}

/// Fully-assembled HIP report ready to serialize.
#[derive(Debug, Clone)]
pub struct HipReport {
    /// The exact md5 the gateway told us to include via
    /// `/ssl-vpn/hipreportcheck.esp`. We echo it verbatim — the
    /// server validates it against its own policy hash.
    pub md5_sum: String,
    pub user_name: String,
    pub host: HostInfo,
    pub profile: HostProfile,
    /// Tun-interface IPv4 assigned by the gateway.
    pub client_ip: String,
    /// `openconnect` client version we claim.
    pub client_version: String,
    /// `MM/DD/YYYY HH:MM:SS` in local time.
    pub generate_time: String,
}

impl HipReport {
    /// Serialize the report into the XML form GlobalProtect
    /// accepts. The string is safe to POST to
    /// `/ssl-vpn/hipreport.esp` after URL-form-encoding as the
    /// `report` field.
    pub fn to_xml(&self) -> String {
        let mut s = String::with_capacity(4096);
        s.push_str("<hip-report name=\"hip-report\">");
        push_tag(&mut s, "md5-sum", &self.md5_sum);
        push_tag(&mut s, "user-name", &self.user_name);
        push_tag(&mut s, "domain", &self.profile.domain);
        push_tag(&mut s, "host-name", &self.host.host_name);
        push_tag(&mut s, "host-id", &self.host.host_id);
        push_tag(&mut s, "ip-address", &self.client_ip);
        push_tag(&mut s, "ipv6-address", "");
        push_tag(&mut s, "generate-time", &self.generate_time);
        // Required top-level element. Some deployments silently
        // discard reports without this tag, resulting in
        // "report submitted" + "gateway kicks you at the grace
        // window expiry" — observed live against UNSW Prisma
        // Access on 2026-04-14.
        push_tag(&mut s, "hip-report-version", "4");
        s.push_str("<categories>");
        self.push_host_info_category(&mut s);
        self.push_platform_categories(&mut s);
        s.push_str("</categories>");
        s.push_str("</hip-report>");
        s
    }

    fn push_host_info_category(&self, s: &mut String) {
        s.push_str("<entry name=\"host-info\">");
        push_tag(s, "client-version", &self.client_version);
        push_tag(s, "os", &self.profile.os);
        push_tag(s, "os-vendor", &self.profile.os_vendor);
        push_tag(s, "domain", &self.profile.domain);
        push_tag(s, "host-name", &self.host.host_name);
        push_tag(s, "host-id", &self.host.host_id);
        s.push_str("<network-interface>");
        match self.profile.hip_os {
            HipOs::Windows => {
                // Match openconnect's reference Windows wrapper:
                // fixed adapter GUID + MAC, actual tunnel IP.
                s.push_str("<entry name=\"{DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF}\">");
                push_tag(s, "description", "PANGP Virtual Ethernet Adapter #2");
                push_tag(s, "mac-address", "01-02-03-00-00-01");
                s.push_str("<ip-address><entry name=\"");
                push_escaped(s, &self.client_ip);
                s.push_str("\"/></ip-address>");
                s.push_str("<ipv6-address><entry name=\"\"/></ipv6-address>");
                s.push_str("</entry>");
            }
            HipOs::Mac => {
                s.push_str("<entry name=\"en0\">");
                push_tag(s, "description", "en0");
                s.push_str("<ip-address><entry name=\"");
                push_escaped(s, &self.client_ip);
                s.push_str("\"/></ip-address>");
                s.push_str("<ipv6-address><entry name=\"\"/></ipv6-address>");
                s.push_str("</entry>");
            }
            HipOs::Linux => {
                s.push_str("<entry name=\"enp1s0f0\">");
                push_tag(s, "description", "enp1s0f0");
                s.push_str("<ip-address><entry name=\"");
                push_escaped(s, &self.client_ip);
                s.push_str("\"/></ip-address>");
                s.push_str("<ipv6-address><entry name=\"\"/></ipv6-address>");
                s.push_str("</entry>");
            }
        }
        s.push_str("</network-interface>");
        s.push_str("</entry>");
    }

    fn push_platform_categories(&self, s: &mut String) {
        match self.profile.hip_os {
            HipOs::Windows => {
                // Openconnect's reference Windows profile emits
                // this exact category set and order.
                self.push_antivirus_category(s);
                self.push_anti_spyware_category(s);
                self.push_disk_backup_category(s);
                self.push_disk_encryption_category(s);
                self.push_firewall_category(s);
                self.push_windows_patch_management_category(s);
            }
            HipOs::Mac => {
                self.push_macos_anti_malware_category(s);
                self.push_disk_backup_category(s);
                self.push_macos_disk_encryption_category(s);
                self.push_firewall_category(s);
                self.push_macos_patch_management_category(s);
            }
            HipOs::Linux => {
                self.push_empty_list_category(s, "anti-malware");
                self.push_disk_backup_category(s);
                self.push_disk_encryption_category(s);
                self.push_firewall_category(s);
                self.push_linux_patch_management_category(s);
            }
        }
        self.push_data_loss_prevention_category(s);
    }

    /// Emit the shared `<Prod …/>` element used by both antivirus
    /// and anti-spyware categories. `prod_type` is `"1"` for AV,
    /// `"2"` for anti-spyware — GlobalProtect treats them as
    /// separate policy categories but the on-the-wire element shape
    /// is identical, differing only in that numeric field.
    fn push_av_prod_element(&self, s: &mut String, av: &AntivirusProduct, prod_type: &str) {
        let (datemon, dateday, dateyear) = parse_generate_time_mdy(&self.generate_time);
        s.push_str("<Prod name=\"");
        push_escaped(s, &av.name);
        s.push_str("\" version=\"");
        push_escaped(s, &av.version);
        s.push_str("\" defver=\"");
        push_escaped(s, &av.defver);
        s.push_str("\" prodType=\"");
        s.push_str(prod_type);
        s.push_str("\" engver=\"");
        push_escaped(s, &av.engver);
        s.push_str("\" osType=\"1\" vendor=\"");
        push_escaped(s, &av.vendor);
        s.push_str("\" dateday=\"");
        push_escaped(s, &dateday);
        s.push_str("\" dateyear=\"");
        push_escaped(s, &dateyear);
        s.push_str("\" datemon=\"");
        push_escaped(s, &datemon);
        s.push_str("\">");
        s.push_str("</Prod>");
    }

    fn push_antivirus_category(&self, s: &mut String) {
        s.push_str("<entry name=\"antivirus\"><list>");
        for av in &self.profile.antivirus {
            s.push_str("<entry><ProductInfo>");
            self.push_av_prod_element(s, av, "1");
            push_tag(s, "real-time-protection", yes_no(av.real_time_protection));
            push_tag(s, "last-full-scan-time", &av.last_full_scan_time);
            s.push_str("</ProductInfo></entry>");
        }
        s.push_str("</list></entry>");
    }

    fn push_macos_anti_malware_category(&self, s: &mut String) {
        let (datemon, dateday, dateyear) = parse_generate_time_mdy(&self.generate_time);
        s.push_str("<entry name=\"anti-malware\"><list>");
        for av in &self.profile.antivirus {
            s.push_str("<entry><ProductInfo>");
            s.push_str("<Prod vendor=\"");
            push_escaped(s, &av.vendor);
            s.push_str("\" name=\"");
            push_escaped(s, &av.name);
            s.push_str("\" version=\"");
            push_escaped(s, &av.version);
            s.push_str("\" defver=\"");
            push_escaped(s, &av.defver);
            s.push_str("\" engver=\"");
            push_escaped(s, &av.engver);
            s.push_str("\" datemon=\"");
            push_escaped(s, &datemon);
            s.push_str("\" dateday=\"");
            push_escaped(s, &dateday);
            s.push_str("\" dateyear=\"");
            push_escaped(s, &dateyear);
            s.push_str("\" prodType=\"3\" osType=\"4\"/>");
            push_tag(s, "real-time-protection", yes_no(av.real_time_protection));
            push_tag(s, "last-full-scan-time", &av.last_full_scan_time);
            s.push_str("</ProductInfo></entry>");
        }
        s.push_str("</list></entry>");
    }

    fn push_anti_spyware_category(&self, s: &mut String) {
        // We reuse the antivirus product list here — most Windows
        // AV products (Defender included) are classified as both
        // antivirus AND anti-spyware by GP policies, and sending
        // them under both categories is what openconnect's
        // reference hipreport.sh does. The ONLY difference from
        // push_antivirus_category is prodType="2" instead of "1".
        s.push_str("<entry name=\"anti-spyware\"><list>");
        for av in &self.profile.antivirus {
            s.push_str("<entry><ProductInfo>");
            self.push_av_prod_element(s, av, "2");
            push_tag(s, "real-time-protection", yes_no(av.real_time_protection));
            push_tag(s, "last-full-scan-time", &av.last_full_scan_time);
            s.push_str("</ProductInfo></entry>");
        }
        s.push_str("</list></entry>");
    }

    fn push_windows_patch_management_category(&self, s: &mut String) {
        // Hard-coded to claim "Windows Update Agent, enabled, no
        // missing patches". Mirrors openconnect's reference
        // template. Gateways that require patch-management rarely
        // inspect further than "category present and enabled".
        s.push_str("<entry name=\"patch-management\"><list>");
        s.push_str("<entry><ProductInfo>");
        s.push_str(
            "<Prod name=\"Microsoft Windows Update Agent\" version=\"10.0.15063.0\" vendor=\"Microsoft Corp.\">",
        );
        s.push_str("</Prod>");
        push_tag(s, "is-enabled", "yes");
        s.push_str("</ProductInfo></entry>");
        s.push_str("</list><missing-patches/></entry>");
    }

    fn push_macos_patch_management_category(&self, s: &mut String) {
        s.push_str("<entry name=\"patch-management\"><list>");
        s.push_str("<entry><ProductInfo>");
        s.push_str("<Prod vendor=\"Apple Inc.\" name=\"Software Update\" version=\"3.0\"/>");
        push_tag(s, "is-enabled", "yes");
        s.push_str("</ProductInfo></entry>");
        s.push_str("</list><missing-patches/></entry>");
    }

    fn push_linux_patch_management_category(&self, s: &mut String) {
        s.push_str("<entry name=\"patch-management\"><list>");
        s.push_str("<entry><ProductInfo>");
        s.push_str("<Prod name=\"Dandified Yum\" version=\"4.2.23\" vendor=\"Red Hat, Inc.\">");
        s.push_str("</Prod>");
        push_tag(s, "is-enabled", "yes");
        s.push_str("</ProductInfo></entry>");
        s.push_str("</list><missing-patches/></entry>");
    }

    fn push_firewall_category(&self, s: &mut String) {
        // openconnect's reference emits <Prod …></Prod> with a body
        // (not self-closing). Matches the on-wire shape that real
        // GP Windows clients send. Some servers are pedantic about
        // element shape even when the content is empty.
        s.push_str("<entry name=\"firewall\"><list>");
        for fw in &self.profile.firewall {
            s.push_str("<entry><ProductInfo>");
            s.push_str("<Prod name=\"");
            push_escaped(s, &fw.name);
            s.push_str("\" version=\"");
            push_escaped(s, &fw.version);
            s.push_str("\" vendor=\"");
            push_escaped(s, &fw.vendor);
            s.push_str("\">");
            s.push_str("</Prod>");
            push_tag(s, "is-enabled", &fw.status);
            s.push_str("</ProductInfo></entry>");
        }
        s.push_str("</list></entry>");
    }

    fn push_disk_encryption_category(&self, s: &mut String) {
        s.push_str("<entry name=\"disk-encryption\"><list>");
        for de in &self.profile.disk_encryption {
            s.push_str("<entry><ProductInfo>");
            s.push_str("<Prod name=\"");
            push_escaped(s, &de.name);
            s.push_str("\" version=\"");
            push_escaped(s, &de.version);
            s.push_str("\" vendor=\"");
            push_escaped(s, &de.vendor);
            s.push_str("\">");
            s.push_str("</Prod>");
            s.push_str("<drives><entry>");
            push_tag(s, "drive-name", &de.drive);
            push_tag(s, "enc-state", &de.status);
            s.push_str("</entry></drives>");
            s.push_str("</ProductInfo></entry>");
        }
        s.push_str("</list></entry>");
    }

    fn push_macos_disk_encryption_category(&self, s: &mut String) {
        if self.profile.disk_encryption.is_empty() {
            self.push_empty_list_category(s, "disk-encryption");
            return;
        }
        let first = &self.profile.disk_encryption[0];
        s.push_str("<entry name=\"disk-encryption\"><list><entry><ProductInfo>");
        s.push_str("<Prod name=\"");
        push_escaped(s, &first.name);
        s.push_str("\" version=\"");
        push_escaped(s, &first.version);
        s.push_str("\" vendor=\"");
        push_escaped(s, &first.vendor);
        s.push_str("\">");
        s.push_str("</Prod><drives>");
        for de in &self.profile.disk_encryption {
            s.push_str("<entry>");
            push_tag(s, "drive-name", &de.drive);
            push_tag(s, "enc-state", &de.status);
            s.push_str("</entry>");
        }
        s.push_str("</drives></ProductInfo></entry></list></entry>");
    }

    fn push_disk_backup_category(&self, s: &mut String) {
        s.push_str("<entry name=\"disk-backup\"><list>");
        for bk in &self.profile.disk_backup {
            s.push_str("<entry><ProductInfo>");
            s.push_str("<Prod name=\"");
            push_escaped(s, &bk.name);
            s.push_str("\" version=\"");
            push_escaped(s, &bk.version);
            s.push_str("\" vendor=\"");
            push_escaped(s, &bk.vendor);
            s.push_str("\">");
            s.push_str("</Prod>");
            push_tag(s, "last-backup-time", &bk.last_backup_time);
            s.push_str("</ProductInfo></entry>");
        }
        s.push_str("</list></entry>");
    }

    fn push_empty_list_category(&self, s: &mut String, category: &str) {
        s.push_str("<entry name=\"");
        s.push_str(category);
        s.push_str("\"><list/></entry>");
    }

    fn push_data_loss_prevention_category(&self, s: &mut String) {
        s.push_str("<entry name=\"data-loss-prevention\"><list/></entry>");
    }
}

/// Parse the first 10 bytes of a `"MM/DD/YYYY HH:MM:SS"` timestamp
/// into `(month, day, year)` as separate strings suitable for
/// embedding as HIP Prod element attributes. Defensive: on any
/// parse failure, returns `("01", "01", "2024")` placeholders —
/// no panic, and the HIP report is still well-formed.
fn parse_generate_time_mdy(generate_time: &str) -> (String, String, String) {
    let bytes = generate_time.as_bytes();
    let ok = bytes.len() >= 10
        && bytes[2] == b'/'
        && bytes[5] == b'/'
        && bytes[..2].iter().all(|b| b.is_ascii_digit())
        && bytes[3..5].iter().all(|b| b.is_ascii_digit())
        && bytes[6..10].iter().all(|b| b.is_ascii_digit());
    if ok {
        let mo = std::str::from_utf8(&bytes[..2]).unwrap_or("01").to_string();
        let d = std::str::from_utf8(&bytes[3..5])
            .unwrap_or("01")
            .to_string();
        let y = std::str::from_utf8(&bytes[6..10])
            .unwrap_or("2024")
            .to_string();
        (mo, d, y)
    } else {
        ("01".to_string(), "01".to_string(), "2024".to_string())
    }
}

/// Builder convenience: stitch [`HostInfo`], [`HostProfile`],
/// user/md5/IP/time into a [`HipReport`].
pub fn build_report(
    md5_sum: impl Into<String>,
    user_name: impl Into<String>,
    client_ip: impl Into<String>,
    host: HostInfo,
    profile: HostProfile,
    generate_time: impl Into<String>,
) -> HipReport {
    HipReport {
        md5_sum: md5_sum.into(),
        user_name: user_name.into(),
        host,
        profile,
        client_ip: client_ip.into(),
        client_version: DEFAULT_CLIENT_VERSION.to_string(),
        generate_time: generate_time.into(),
    }
}

// --- helpers ---

fn push_tag(s: &mut String, tag: &str, value: &str) {
    s.push('<');
    s.push_str(tag);
    s.push('>');
    push_escaped(s, value);
    s.push_str("</");
    s.push_str(tag);
    s.push('>');
}

fn push_escaped(s: &mut String, value: &str) {
    for c in value.chars() {
        match c {
            // Metacharacters. `"` / `'` are technically only
            // required inside attribute values, but escaping them
            // in element text too is strictly correct and lets us
            // use the same helper for both contexts.
            '<' => s.push_str("&lt;"),
            '>' => s.push_str("&gt;"),
            '&' => s.push_str("&amp;"),
            '"' => s.push_str("&quot;"),
            '\'' => s.push_str("&apos;"),
            // XML 1.0 forbids NUL and most C0 controls (everything
            // below U+0020 except `\t`, `\n`, `\r`). A stray NUL
            // would make the document non-well-formed; tab/LF/CR
            // in attribute values get whitespace-normalized by
            // parsers, which silently corrupts the value. Drop
            // the entire illegal set — GP HIP fields (hostname,
            // username, product name, …) have no legitimate use
            // for control characters, so stripping is safe.
            c if (c as u32) < 0x20 => {}
            _ => s.push(c),
        }
    }
}

fn yes_no(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
    }
}

fn detect_hostname() -> Option<String> {
    #[cfg(unix)]
    {
        // Use the libc call rather than `hostname` crate to avoid
        // adding a dep for one function.
        let mut buf = vec![0u8; 256];
        let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if rc != 0 {
            return None;
        }
        // gethostname may not null-terminate if the name is too long;
        // enforce it manually.
        if let Some(nul) = buf.iter().position(|&b| b == 0) {
            buf.truncate(nul + 1);
        } else {
            buf.push(0);
        }
        let cstr = CStr::from_bytes_until_nul(&buf).ok()?;
        let s = cstr.to_str().ok()?.to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").ok()
    }
}

fn detect_machine_id() -> Option<String> {
    // Prefer /etc/machine-id (systemd), fall back to the dbus copy
    // that most distros ship.
    //
    // Valid shapes after trim:
    //   * exactly 32 lowercase hex chars (the systemd / dbus form)
    //   * a 36-char UUID with dashes (rarer but legal)
    // Anything else is treated as corrupt and we fall through to
    // the caller's placeholder — a loose `len() >= 8` check would
    // happily forward garbage as a host id.
    for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(raw) = fs::read_to_string(path) {
            if let Some(uuid) = format_as_uuid(raw.trim()) {
                return Some(uuid);
            }
        }
    }
    None
}

/// Normalize a machine-id string into dash-separated lowercase
/// UUID form. Accepts:
///
///   * 32 hex chars with no dashes → formatted into
///     `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"`
///   * a 36-char input in *canonical* UUID layout — hex blocks of
///     length 8, 4, 4, 4, 12 separated by dashes at positions
///     8, 13, 18, 23. Returned lowercased.
///
/// Returns `None` for any other shape (wrong length, non-hex
/// characters, dashes in non-canonical positions, etc.) so the
/// caller can fall through to a safe placeholder instead of
/// forwarding garbage.
fn format_as_uuid(raw: &str) -> Option<String> {
    let lower = raw.to_ascii_lowercase();
    if lower.contains('-') {
        if !is_canonical_uuid(&lower) {
            return None;
        }
        return Some(lower);
    }
    if lower.len() != 32 {
        return None;
    }
    if !lower.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &lower[0..8],
        &lower[8..12],
        &lower[12..16],
        &lower[16..20],
        &lower[20..32]
    ))
}

/// Whether `s` is a lowercase 36-char UUID in the canonical
/// `8-4-4-4-12` layout with hex everywhere except the four fixed
/// dash positions.
fn is_canonical_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    // Canonical dash positions.
    const DASH_POSITIONS: [usize; 4] = [8, 13, 18, 23];
    for (i, b) in s.bytes().enumerate() {
        if DASH_POSITIONS.contains(&i) {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report() -> HipReport {
        build_report(
            "abc123def456",
            "alice@example.com",
            "10.1.2.3",
            HostInfo {
                host_name: "alice-laptop".into(),
                host_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            },
            HostProfile::spoofed_windows(),
            "01/02/2026 03:04:05",
        )
    }

    #[test]
    fn xml_contains_required_top_level_fields() {
        let xml = sample_report().to_xml();
        assert!(xml.starts_with("<hip-report name=\"hip-report\">"));
        assert!(xml.ends_with("</hip-report>"));
        assert!(xml.contains("<md5-sum>abc123def456</md5-sum>"));
        assert!(xml.contains("<user-name>alice@example.com</user-name>"));
        assert!(xml.contains("<host-name>alice-laptop</host-name>"));
        assert!(xml.contains("<host-id>aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee</host-id>"));
        assert!(xml.contains("<ip-address>10.1.2.3</ip-address>"));
        assert!(xml.contains("<generate-time>01/02/2026 03:04:05</generate-time>"));
    }

    #[test]
    fn xml_contains_all_categories() {
        let xml = sample_report().to_xml();
        for entry in [
            "<entry name=\"host-info\">",
            "<entry name=\"antivirus\">",
            "<entry name=\"anti-spyware\">",
            "<entry name=\"disk-backup\">",
            "<entry name=\"disk-encryption\">",
            "<entry name=\"firewall\">",
            "<entry name=\"patch-management\">",
            "<entry name=\"data-loss-prevention\">",
        ] {
            assert!(xml.contains(entry), "missing category: {entry}");
        }
    }

    #[test]
    fn antivirus_category_reports_defender_enabled() {
        let xml = sample_report().to_xml();
        assert!(xml.contains("name=\"Windows Defender\""));
        assert!(xml.contains("<real-time-protection>yes</real-time-protection>"));
    }

    #[test]
    fn firewall_category_reports_enabled() {
        let xml = sample_report().to_xml();
        // Spoofed Windows profile now uses the
        // "Microsoft Windows Firewall" product name — matches
        // openconnect's reference hipreport.sh.
        assert!(xml.contains("name=\"Microsoft Windows Firewall\""));
        assert!(xml.contains("<is-enabled>yes</is-enabled>"));
    }

    #[test]
    fn profile_from_client_os_selects_linux() {
        let profile = HostProfile::from_client_os(Some("Linux"));
        assert_eq!(profile.hip_os, HipOs::Linux);
        assert_eq!(profile.os_vendor, "Linux");
    }

    #[test]
    fn profile_from_client_os_selects_macos() {
        let profile = HostProfile::from_client_os(Some("Mac"));
        assert_eq!(profile.hip_os, HipOs::Mac);
        assert_eq!(profile.os_vendor, "Apple");
    }

    #[test]
    fn unknown_client_os_falls_back_to_windows_profile() {
        let profile = HostProfile::from_client_os(Some("Android"));
        assert_eq!(profile.hip_os, HipOs::Windows);
        assert_eq!(profile.os_vendor, "Microsoft");
    }

    #[test]
    fn linux_profile_uses_linux_categories() {
        let report = build_report(
            "md5",
            "alice",
            "10.1.2.3",
            HostInfo::placeholder(),
            HostProfile::spoofed_linux(),
            "01/02/2026 03:04:05",
        );
        let xml = report.to_xml();
        assert!(xml.contains("<os-vendor>Linux</os-vendor>"));
        assert!(xml.contains("<entry name=\"anti-malware\"><list/></entry>"));
        assert!(!xml.contains("<entry name=\"antivirus\">"));
        assert!(xml.contains("name=\"cryptsetup\""));
        assert!(xml.contains("name=\"Dandified Yum\""));
    }

    #[test]
    fn mac_profile_uses_anti_malware_category() {
        let report = build_report(
            "md5",
            "alice",
            "10.1.2.3",
            HostInfo::placeholder(),
            HostProfile::spoofed_macos(),
            "01/02/2026 03:04:05",
        );
        let xml = report.to_xml();
        assert!(xml.contains("<os-vendor>Apple</os-vendor>"));
        assert!(xml.contains("<entry name=\"anti-malware\">"));
        assert!(!xml.contains("<entry name=\"antivirus\">"));
        assert!(xml.contains("name=\"Xprotect\""));
        assert!(xml.contains("name=\"Software Update\""));
    }

    #[test]
    fn xml_escapes_dangerous_characters() {
        let mut report = sample_report();
        report.user_name = r#"a<b>&"c"'d"#.into();
        let xml = report.to_xml();
        assert!(xml.contains("<user-name>a&lt;b&gt;&amp;&quot;c&quot;&apos;d</user-name>"));
        // Sanity: no raw '<' between the tags for user-name.
        assert!(!xml.contains(r#"<user-name>a<b>"#));
    }

    #[test]
    fn escapes_attribute_values() {
        let mut profile = HostProfile::spoofed_windows();
        profile.antivirus[0].vendor = r#"Evil" />Corp"#.into();
        let mut report = sample_report();
        report.profile = profile;
        let xml = report.to_xml();
        // The closing quote of the vendor attribute must NOT appear
        // unescaped before the rest of the attributes.
        assert!(
            xml.contains(r#"vendor="Evil&quot; /&gt;Corp""#),
            "attribute escaping failed:\n{xml}"
        );
    }

    #[test]
    fn host_info_placeholder_is_stable() {
        let a = HostInfo::placeholder();
        let b = HostInfo::placeholder();
        assert_eq!(a.host_name, b.host_name);
        assert_eq!(a.host_id, b.host_id);
        assert_eq!(a.host_id, DEFAULT_HOST_ID_FALLBACK);
    }

    #[test]
    fn host_info_detect_returns_something() {
        // We can't assert specific values (depends on host), but
        // detect() must not panic and must return non-empty strings.
        let h = HostInfo::detect();
        assert!(!h.host_name.is_empty());
        assert!(!h.host_id.is_empty());
    }

    #[test]
    fn format_as_uuid_handles_32_char_hex() {
        assert_eq!(
            format_as_uuid("abcdef0123456789abcdef0123456789").as_deref(),
            Some("abcdef01-2345-6789-abcd-ef0123456789")
        );
    }

    #[test]
    fn format_as_uuid_passes_through_dashed_uuid() {
        assert_eq!(
            format_as_uuid("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE").as_deref(),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        );
    }

    #[test]
    fn format_as_uuid_rejects_short_input() {
        assert!(format_as_uuid("SHORT").is_none());
        assert!(format_as_uuid("").is_none());
    }

    #[test]
    fn format_as_uuid_rejects_non_hex_32_char() {
        // Exact 32 chars but not hex — must be rejected, not
        // sliced into UUID-shaped garbage.
        assert!(format_as_uuid("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
    }

    #[test]
    fn format_as_uuid_rejects_dashed_non_hex() {
        assert!(format_as_uuid("gggggggg-hhhh-iiii-jjjj-kkkkkkkkkkkk").is_none());
    }

    #[test]
    fn format_as_uuid_rejects_wrong_length_dashed() {
        // 37 characters with dashes — rejected.
        assert!(format_as_uuid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeeef").is_none());
    }

    #[test]
    fn format_as_uuid_rejects_noncanonical_dash_placement() {
        // 36 chars, only hex + dashes, but dashes are in the wrong
        // positions. Canonical layout requires dashes at 8, 13,
        // 18, 23. Both of these are 36 chars of pure [hex|-] and
        // would have passed the round-7 implementation.
        assert!(format_as_uuid("----aaaa-bbbb-cccc-dddd-eeeeeeeeeeee").is_none());
        assert!(format_as_uuid("aaaa-aaaabbbbccccddddeeeeeeeeeeee-aa").is_none());
    }

    #[test]
    fn format_as_uuid_accepts_canonical_mixed_case() {
        assert_eq!(
            format_as_uuid("12345678-90AB-CDEF-1234-567890abcdef").as_deref(),
            Some("12345678-90ab-cdef-1234-567890abcdef")
        );
    }

    #[test]
    fn push_escaped_strips_control_chars() {
        let mut out = String::new();
        push_escaped(&mut out, "a\0b\tc\nd\re");
        // NUL + tab + LF + CR all dropped.
        assert_eq!(out, "abcde");
    }

    #[test]
    fn xml_output_has_no_nul_byte() {
        let mut report = sample_report();
        // User supplies a hostile hostname with an embedded NUL.
        report.host.host_name = "bad\0host".into();
        let xml = report.to_xml();
        assert!(!xml.contains('\0'), "xml contained a raw NUL: {xml:?}");
        assert!(xml.contains("<host-name>badhost</host-name>"));
    }

    #[test]
    fn yes_no_matches_expected() {
        assert_eq!(yes_no(true), "yes");
        assert_eq!(yes_no(false), "no");
    }

    #[test]
    fn build_report_sets_defaults() {
        let r = build_report(
            "m",
            "u",
            "1.2.3.4",
            HostInfo::placeholder(),
            HostProfile::spoofed_windows(),
            "t",
        );
        assert_eq!(r.client_version, DEFAULT_CLIENT_VERSION);
        assert_eq!(r.md5_sum, "m");
        assert_eq!(r.user_name, "u");
        assert_eq!(r.client_ip, "1.2.3.4");
    }
}
