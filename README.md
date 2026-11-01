# yigitsapa system analyses
**Package:** `yigitsapa system analyses v1.0`  
**Package version:** `v1.0`  
**Engine:** `yigitsapa System Analyses Engine`  
`yigitsapa system analyses` collects CPU, GPU, RAM, storage, sensor, operating-system, and hardware-health information exposed by Windows and device firmware. It reports the source and measurement status of collected data. It does not invent unavailable temperatures or SMART health values. The analyzer's measurement and evaluation logic is carried forward from the supplied source archive.
## Quick start: GUI
The GUI opens with the fixed heading **yigitsapa System Analyses Engine**. A Quick analysis starts automatically after the window opens. Live analyzer output appears in the scrollable area below the heading. The status bar remains fixed at the bottom of the window and displays the current state of the analysis. Use the mode selector to choose Quick, Standard, Deep, or Diagnostics for a later run.
The GUI streams both standard output and error output from the main analyzer. The **Stop** button requests termination of the active analyzer process. Reports are saved by the engine to `system_analyses_reports` when the relevant output options are enabled.
To run the analyzer directly from PowerShell or Command Prompt, use the commands in [CLI quick start](#cli-quick-start).
## Supported environment
- Windows 11 Pro x64, using the native AMD64/x64 architecture and a Windows 11 build.
- 64-bit, standard (non-free-threaded) CPython. The source project's development and field-validation environment used Python 3.14.10 x64. The Windows Python launcher can select Python 3.14 with `py -3.14`.
Before analysis begins, the program checks the Windows edition, Windows build, processor architecture, and Python bitness. The fact that parser and fixture tests accept Linux/macOS-like input does not mean those systems are supported hardware-analysis targets. `--help` lists the available options; `--diagnostics` reports dependency, permission, and data-source status.
### Hardware-model and vendor independence
The application does not branch on a particular computer's CPU, GPU, RAM, motherboard, or disk model. Hardware information is collected dynamically from the computer on which it runs, using sources such as Windows API/CIM-WMI, DXGI, SMBIOS, hardware-sensor providers, and `smartctl`. Known vendor identifiers are used for classification; unknown vendor, model, and device names are preserved as raw values wherever possible.
A field report from one test computer is therefore not a component list or compatibility guarantee for another computer. Machine-specific part and serial numbers are abstracted with synthetic identifiers in regression scenarios. Vendor-recognition behavior is also tested with examples from different vendors and identifier families. Actual hardware validation must be performed separately on the target system.
## Package layout
| File or directory | Responsibility |
|---|---|
| `system_analyses.py` | Unified analyzer: hardware inventory, platform adapters, SMART matching, and CPU/GPU/storage sensor providers. |
| `system_analyses_gui.py` | Tkinter desktop interface; runs the analyzer and streams its output into the GUI. |
| `run.bat` | Windows launcher that starts the GUI with a windowless Python interpreter. |
| `README.md` | Installation, architecture, usage, data sources, limitations, and validation guidance. |
| `CHANGELOG.md` | Release notes for this package, beginning at `v1.0`. |
| `requirements.txt` | Runtime Python dependencies, including primary and fallback temperature providers. |
| `pyproject.toml` | Ruff, ty, and basedpyright quality-check configuration and package metadata. |
| `install_pawnio.ps1` | Assists with installing the external PawnIO Windows kernel driver after explicit user consent. |
| `.github/workflows/system-analyses-tests.yml` | Windows/Python-version test matrix and quality gates. |
| `.gitignore` | Excludes Python caches, virtual environments, and local report output. |
## Installation
Open PowerShell or Command Prompt in the extracted project folder:
```powershell
py -3.14 --version
py -3.14 -m pip install --upgrade pip
py -3.14 -m pip install -r requirements.txt
```
`requirements.txt` installs the Python components from one place:
- `psutil`: operating-system and resource counters.
- `HardwareMonitor` + `pythonnet`: CPU, GPU, motherboard, memory, and storage sensor access through LibreHardwareMonitor.
- `PyLibreHardwareMonitor`: an alternative Python wrapper for the same LibreHardwareMonitor engine. It is attempted if the primary wrapper cannot start or does not return live data.
- Windows ACPI/WMI (`root\wmi`, `MSAcpi_ThermalZoneTemperature`): thermal-zone records exposed by firmware and Windows thermal management; each zone is retained as a separate sensor source.
- `amd-adlx` (optional): AMD's official ADLX Python binding. On supported AMD GPUs it reads driver-provided edge and hotspot temperatures directly. A wheel is available for CPython 3.14 x64, but this package is not installed automatically through `requirements.txt`.
The two hardware-monitoring wrappers use the same underlying engine, so they are not normally started at the same time. If the primary provider returns valid live temperatures, the fallback provider is not used. `--diagnostics` can test the fallback provider independently for diagnostic purposes.
### PawnIO driver
PawnIO is an **external Windows kernel driver** that may be required to access certain low-level sensors; it is not a Python package. It is therefore not included in `requirements.txt` as a pip dependency and is never installed silently by the application. If installation is required, run the following explicitly from an elevated PowerShell window:
```powershell
.\install_pawnio.ps1
```
The installation script requests UAC/administrator permission. WinGet can also be used:
```powershell
winget install -e --id namazso.PawnIO
```
Restart Windows if the driver installation requests it. Having PawnIO installed and running does not guarantee that every motherboard, CPU, GPU, or storage sensor will be exposed. PawnIO remains part of the project architecture; consolidation of the analyzer does not remove the driver.
### AMD GPU temperatures through ADLX (optional)
On systems with an AMD graphics card and a compatible AMD Software driver, the official ADLX Python binding can be used. This dependency is optional and is not required for the general installation. If a suitable wheel is available for CPython 3.14 x64, install and check it with:
```powershell
py -3.14 -m pip install amd-adlx
py -3.14 -c "from adlx import ADLX; print('ADLX Python binding is ready')"
```
The program performs read-only operations through ADLX. It does not change fan, voltage, clock, power-limit, or tuning settings. It does not create a temperature measurement if the driver does not support edge/hotspot values. AMD's `GPUTemperature` metric represents die-edge temperature; `GPUHotspotTemperature` represents the highest junction-sensor temperature on the die. References: [AMD ADLX Python binding](https://pypi.org/project/amd-adlx/) and [ADLX performance-monitoring API](https://gpuopen.com/manuals/adlx/).
### SMART utility
SMART data is collected with `smartctl.exe` from `smartmontools`, not through a Python wrapper. Install `smartctl.exe` separately and make it available through `PATH`. Official resources: [smartmontools](https://www.smartmontools.org/) and [official GitHub releases](https://github.com/smartmontools/smartmontools/releases).
## CLI quick start
```powershell
# Usage and available options
py -3.14 system_analyses.py --help
# Dependency, provider, permission, and sensor diagnostics
py -3.14 system_analyses.py --diagnostics
py -3.14 system_analyses.py --diagnostics --json > diagnostics.json
# Quick, standard, or deep analysis
py -3.14 system_analyses.py --quick
py -3.14 system_analyses.py
py -3.14 system_analyses.py --deep
# Timestamped sensor sampling for 30 seconds at 1-second intervals
py -3.14 system_analyses.py --quick --sensor-sampling --sensor-duration 30 --sensor-interval 1
# Start an elevated CMD process with UAC consent for sensor/SMART access
py -3.14 system_analyses.py --elevate --quick --sensor-sampling --sensor-duration 30 --sensor-interval 1 --storage-health-probe
# Health history from previous reports
py -3.14 system_analyses.py --quick --history-dir .\system_analyses_reports --history-limit 20
# Export Excel-compatible CSV and offline HTML from a live measurement
py -3.14 system_analyses.py --quick --sensor-sampling --sensor-duration 30 --csv-out .\exports\sensors.csv --html-out .\exports\report.html
# Re-analyze a saved JSON report and export it
py -3.14 system_analyses.py --from-json .\system_analyses_reports\report.json --csv-out .\exports\sensors.csv --html-out .\exports\report.html
# Benchmark repetitions and warm-up runs
py -3.14 system_analyses.py --bench-warmups 1 --bench-repeats 3
# Analyze or compare a previous report
py -3.14 system_analyses.py --from-json .\system_analyses_reports\report.json
py -3.14 system_analyses.py --compare-json .\system_analyses_reports\previous_report.json
```
`--storage-health-probe` explicitly starts a SMART query; the default Quick analysis does not force SMART queries. Load-generating or externally connected tests such as `--gpu-bench`, `--memory-test-mb`, `--encoder-bench`, network speed tests, and disk benchmarks are optional. Review the limits and effects shown in the CLI help before using these modes.
## Health history, CSV/HTML exports, and smart alerts
`--history-dir` builds temperature, sensor, disk/SMART-health, and benchmark time series from previous JSON reports in a folder. Battery capacity health, wear, full-charge capacity, and cycle counters can also be compared across reports when supported by the battery. Battery history is matched first by a hash of the raw WMI instance identifier; if that is unavailable, it is matched only by a unique vendor/name combination. Ambiguous matches are not merged.
`--csv-out` creates UTF-8-SIG telemetry rows that Excel can open directly. Timestamp, sampling duration, metric, component, value, unit, and data source columns are preserved. Disk I/O rows contain cumulative byte counters at the sampling instant; CSV export does not convert them into MB/s rates. Battery capacity health/wear and cycle count are added as report-time measurements when available.
`--html-out` creates a single HTML file that does not require external JavaScript, a CDN, or a remote analysis service. Health alerts and the text report are written with HTML escaping. Both export options can be used during a live run and while re-analyzing a report with `--from-json`.
Smart alerts rely only on currently available sensor, SMART, memory-commit, battery, and previous-report comparison data. Example application thresholds are CPU 90/100 °C, GPU 85/95 °C, storage 65/75 °C; SMART media/uncorrectable errors and failed health status are critical; SSD usage counters 80%/95%; memory commit 80%/90%; and battery capacity health 50% or lower. These are application-level early warnings. They do not replace manufacturer thermal limits or diagnosis by an authorized service provider. The program does not automatically shut down the computer, install drivers, or change Windows settings.
## Battery, workload, and driver/firmware change history
When Windows `root/wmi` classes `BatteryStaticData`, `BatteryFullChargedCapacity`, and `BatteryCycleCount` are available, the design/full-charge capacity, capacity health, estimated wear, and cycle count are reported. If the classes or matching counters are unavailable, the field remains `unavailable` or `partial`; the instantaneous battery percentage is not substituted for capacity health.
Workload profiles retain their suitability categories and show actual CPU/RAM/disk/GPU benchmark results separately. An FFmpeg synthetic 720p encoding test can be run with `--encoder-bench`. Gaming FPS, real Blender scene render time, or video-editing timeline duration are not treated as measured unless those workloads are actually run.
`--compare-json` compares driver versions, BIOS/UEFI versions, and identified storage firmware versions against a previous report. Matching is performed by stable device or platform identity; ambiguous or duplicate identities are skipped. Change tracking is read-only and does not update drivers or firmware.
`--elevate` opens a new CMD process with administrator privileges only when explicitly requested and after a UAC prompt. If the user cancels the UAC prompt, hardware analysis does not continue as an elevated operation. Administrator permission alone does not guarantee sensor data availability.
## Sensor sampling duration and interval
`--sensor-duration` specifies the measurement-window length. HardwareMonitor/pythonnet and PawnIO startup time is excluded from this window. `--sensor-interval` is the target time between the start of consecutive samples. If a sensor read takes longer than the interval, missed slots are skipped; samples are not compressed and collected back-to-back. The JSON/TXT report includes the requested interval as well as the observed median and maximum intervals, provider preparation time, and whether the sampling window completed. Provider startup or read failures are shown as `partial`/`unavailable`; real sensor readings are never fabricated.
## Sensor providers and data principles
The sensor layer is not hard-coded to a specific CPU/GPU vendor. It prioritizes Windows-exposed sources and libraries that already implement hardware protocols, such as LibreHardwareMonitor. The main script does not attempt to reimplement I²C/SMBus/Super-I/O/PCIe/GPU sensor protocols from scratch. It starts providers, normalizes measurements, preserves source identity, and combines records conservatively.
1. **Hardware sensor engine:** LibreHardwareMonitor through `HardwareMonitor/pythonnet`. It provides temperature, fan, voltage, load, and clock data for supported CPUs, GPUs, motherboards, DIMMs, storage devices, and other components.
2. **Wrapper compatibility path:** `PyLibreHardwareMonitor` accesses the same LibreHardwareMonitor engine through a different Python interface. It is not an independent second hardware-sensor engine; it is attempted only if the first wrapper cannot start or cannot produce live values.
3. **Native Windows thermal data:** `MSAcpi_ThermalZoneTemperature` under `root\wmi`. It returns ACPI thermal zones defined by Windows/firmware. `CurrentTemperature` is measured in 0.1 Kelvin units; the engine converts it to Celsius and keeps it separate under the `ACPI Thermal Zone` type.
4. **Windows operating-system telemetry:** WMI/CIM, PDH performance counters, DXGI, and Storage Reliability. CPU load, GPU engine/memory use, RAM, disk I/O, and other Windows-provided counters are read through these interfaces.
5. **NVIDIA NVML:** Provides GPU temperature telemetry when the NVIDIA driver/SDK actually returns a temperature. It is attempted according to GPU presence and availability.
6. **AMD ADLX:** If the `amd-adlx` or compatible `ADLXPybind` binding and an ADLX-capable AMD driver are available, `GPUTemperature` (edge) and `GPUHotspotTemperature` (junction) are read. No temperature is added if the binding is missing, the metric is unsupported, or the driver returns no value. `DXGI` provides GPU engine/memory telemetry; it is not by itself a GPU temperature source.
7. **`psutil`:** Supported CPU/RAM/disk/network/battery counters on Windows and other test platforms. It does not replace other sources when a temperature API is not supported.
An ACPI thermal zone is not assumed to be equivalent to a CPU Package, GPU Hotspot, VRM, or DIMM sensor. It represents the temperature of a zone defined by firmware and is therefore retained as `ACPI Thermal Zone` in reports. Not every motherboard/firmware exposes the same thermal zones. Windows thermal management may use these zones for cooling/throttling policy, but that does not mean the operating system exposes every physical sensor to applications through a general API. `Windows.Devices.Sensors` is primarily intended for device sensors such as accelerometers, gyroscopes, compasses, and light sensors; it is not a general CPU/GPU temperature API. `Win32_TemperatureProbe.CurrentReading` is not used as a temperature source because current WMI implementations do not populate it reliably in real time.
Every temperature record preserves `SensorIdentifier`, component identity, hardware role, provider, and timestamp. Live ACPI rows display the full thermal-zone identifier, such as `TSZ0_0`; a short report label does not hide that identifier. When the same physical component can be read through multiple sources, unique identifiers from the Windows inventory are used first (DXGI LUID for GPUs, physical-disk identity for storage, and a CPU package key for a single processor package). If no such identifier exists, matching is restricted to a unique hardware name. When multiple GPUs/disks share the same model, ambiguous records are not merged.
For the overall temperature-observation total, values from different providers count as one observation only when they refer to the same component, the same semantic channel, and the same sampling instant, and are within 0.25 °C of one another. Provider-specific sensor records and `SensorIdentifier` values are still retained separately. This prevents CPU package, GPU hotspot, VRM, ACPI thermal-zone, and different disk-temperature channels from being mixed. If identity, time, or channel information is missing, records are not merged by guesswork.
The following rules are deliberately preserved:
- A GPU temperature is not estimated or derived from CPU temperature when the driver/sensor does not report one.
- Empty, zero, threshold (`Warning Temperature`, `Critical Temperature`), negative, or otherwise invalid values are not treated as live temperatures.
- A hardware/VRM role is assigned only when the actual sensor class and label support it.
- No vendor-specific mandatory branch is required for AMD, Intel, NVIDIA, or another vendor; hardware providers are normalized through common interfaces.
- PawnIO remains part of the sensor-access architecture. No sensor provider automatically removes PawnIO or is treated as a replacement for it.
## Storage inventory and physical-disk grouping
Windows may expose the same physical disk as different records through different APIs. For example, `Win32_DiskDrive`, `Get-PhysicalDisk`, PnP, and volume sources can return different path formats, device identifiers, and slightly different capacity values for the same disk. The analyzer groups these observations under physical disks using the following rules:
- Primary identities: normalized serial number, WWN, PnP device identifier, and physical device path.
- The same disk number/index is a supporting matching signal when it does not conflict with other identities.
- Capacity matching uses a tolerance of `max(16 MiB, 1% of capacity)`. This tolerance accounts only for provider-reporting differences; it does not override model/identity conflicts.
- If a strong identity such as serial/WWN/PnP/path is unavailable, model+capacity matching is used only when there is one unambiguous candidate and records originate from different sources.
- If multiple candidates exist, serial/disk-index values conflict, or matching is not unique, records are not merged according to arbitrary order.
- Source paths, device identifiers, disk indexes, and capacity observations from each source are preserved within the group. When available, `\\.\PHYSICALDRIVE<n>` is selected as the canonical reporting path.
- `physical_device_id` is derived from a SHA-256 digest of a unique identity such as serial number/WWN/PnP/path. Serial numbers are not written to reports in clear text. If only a weak fallback identity such as model+capacity+disk index exists, the method is marked `model_capacity_index_fallback`; this is not a hardware identity guaranteed to remain stable across reconnects or boots. If the same fallback identity occurs in multiple groups, no artificial unique ID is assigned (`physical_device_id=null`, `physical_identity_method=ambiguous_identity`).
Grouping corrects cases where different Windows API records represent the same physical disk, but it cannot invent a unique identity that the hardware/firmware does not expose. Ambiguous records remain separate, especially for USB bridges without serial numbers and multi-disk/RAID/HBA scenarios. A group with an ambiguous identity is left as `null` rather than receiving a fake unique ID; SMART results cannot then be incorrectly assigned to that group.
### WMI memory-array capacity units
According to the Microsoft WMI contract, `Win32_PhysicalMemoryArray.MaxCapacityEx` is expressed in **kilobytes (KiB)** and must be multiplied by 1024 to convert to bytes. The older/deprecated `MaxCapacity` field is treated as bytes according to its contract on older Windows versions. The analyzer handles the fields separately and prefers `MaxCapacityEx` when available. This corrects conversions such as a WMI value that would otherwise appear as `64.0 MiB` when it should be `64.0 GiB`.
## SMART and Windows Storage Reliability are separate sources
`smartctl` is the **single canonical SMART source**. Wrappers built on top of `smartctl`, such as `pySMART` or `diskinfo`, are not used as additional data sources. SMART and Windows Storage Reliability are never merged as if they were the same health source.
### Query and matching order
1. When `--storage-health-probe` is enabled, `smartctl --scan-open -j` discovers device names that support SMART access.
2. If a `smartctl` path directly matches one of the Windows inventory paths, it is attached to that group.
3. If the path does not match, a read-only identity/capacity query is attempted with `smartctl -i -j -n standby`.
4. Identity data is matched to exactly one physical-disk group by unique serial number; if there is no serial number, a unique model+capacity combination is used. Capacity mismatch or multiple candidates prevents matching.
5. If matching succeeds unambiguously, a detailed `smartctl -a -j -n standby` query is sent. No detailed query is sent to an unmatched or ambiguous device.
6. A duplicate `smartctl` scan record for the same physical group is not queried a second time.
7. The SMART result is attached to one disk group through `matched_physical_device_id`. If an exact physical group cannot be identified, data is not copied to any disk by guesswork.
`-n standby` helps avoid waking a standby ATA device when supported; identical behavior cannot be guaranteed across all USB bridges, controllers, and drivers. Queries are read-only SMART information queries; the application does not automatically start a SMART self-test or write to a disk.
### SMART query states
| `query_status` | Meaning |
|---|---|
| `success` | A SMART health status or real SMART attribute/health-log data was found. If `smart_status.passed` is `false`, the query itself did not fail; the device's health result is failing. |
| `unsupported` | JSON/device information or a temperature was returned, but no SMART health/attribute data was provided. This does not count as a successful SMART-health query. |
| `not_matched` | The `smartctl` device could not be matched to exactly one physical disk in the Windows inventory; no detailed query was sent. |
| `failed` | The query or JSON processing failed. |
| `duplicate_scan_entry` | A scan alias for the same physical disk was found again; the duplicate query was skipped. |
The summary status is `ok` when at least one real query succeeds and other expected devices are missing/failed; it is `partial` when some expected devices are missing/failed; and it is `unavailable` when there is no successful query containing real SMART data. A temperature value alone, or a zero `smartctl` process exit code, does not prove that SMART data was obtained. A USB device without SMART support is expected to remain `health_status=unknown`; it is not considered to have completed a health query.
### SMART `smartctl` exit codes and historical records
The `smartctl` exit code is not a single number that merely indicates process success/failure; it must be interpreted as a bitmask. When valid SMART data is present in JSON, the analyzer preserves `query_status=success` while recording health/diagnostic warnings from the exit code separately:
| Bit value | Meaning |
|---:|---|
| 1 | Command-line parsing or internal smartctl error |
| 2 | Device could not be opened/identified, or it is in a low-power state |
| 4 | SMART command or checksum error |
| 8 | SMART status check reported `DISK FAILING` |
| 16 | A pre-fail attribute is currently at or below its threshold |
| 32 | An attribute has been at or below its threshold in the past |
| 64 | The SMART device error log contains a record |
| 128 | The SMART self-test log contains a failed-test record |
For example, exit code `64` indicates a historical error-log record even when the overall SMART summary is `passed=true`. This does not prove that the disk is currently failing, but it must not be silently ignored. The analyzer reports this as a health warning and carries accessible error counts, descriptions, disk power-on hours, and ATA register fields into the report. ATA error-register bits are interpreted in the context of the command/feature. smartmontools resolves ATA error descriptions using `commands[4]`, the newest command-history slot. Because JSON output omits empty/zero-filled history slots, the analyzer treats this context as definitive only when all five command-history entries are present. In shorter/sparse `previous_commands` lists, the newest visible record is shown only as historical information; opcode or LBA interpretation is not inferred from it.
This context is not a separate failed-command opcode field: the SMART error record contains completion registers from the time of the error and the command history preceding it. In the context of `SET FEATURES [Enable write cache]` (CR `0xEF`), smartmontools recognizes the `ABRT` bit; for this command the LBA register field is not a sector address and must not be interpreted as evidence of a bad sector. Bit `128` is a separate self-test-log warning. The ATA `Power_On_Hours` attribute is read from standard attribute ID 9 when the `smartctl` JSON does not provide a top-level power-on-hours value. Wear is not estimated from vendor-specific raw attribute values.
Special case: when the overall SMART health result is PASS, a single ABRT record occurred at power-on hour 0, and the newest slot in a complete five-command history is definitively `SET FEATURES [Enable write cache]` (CR `0xEF`, FR `0x02`), this narrow scenario is classified as an informational “startup configuration record.” The record is not deleted and this does not prove that the disk is error-free; a small health-score impact and a backup/monitoring recommendation are retained. If there are multiple records, a positive media error, SMART failure, a different command, an unknown event time, or an incomplete/sparse five-entry history, the general SMART error-log warning remains active.
Windows `Storage Reliability` temperature, wear, and power-on counter data is kept separately under the `OS_STORAGE_RELIABILITY` source. It is not copied into SMART fields, does not increase the SMART success count, and does not replace a SMART query. The inability to retrieve SMART data does not mean that the disk is healthy.
## Windows page file / virtual memory
Page-file status is queried read-only through the WMI/CIM classes `Win32_ComputerSystem.AutomaticManagedPagefile`, `Win32_PageFileUsage`, and `Win32_PageFileSetting`. Usage/peak values and Windows automatic-management preferences are included in the report. If a WMI query fails, the program does not assume that the page file is disabled; the state remains `unknown`.
When the page file is disabled, commit percentage, commit peak/limit ratio, and available RAM are evaluated together. If memory pressure is low, a system-managed page file is shown only as a recommendation for large video, rendering, virtual-machine, and other memory-intensive workloads. If commit pressure is high, the warning level is raised. The program never changes Windows settings automatically. If `Win32_PageFileUsage` returns no runtime entry while WMI reports automatic management enabled, the report does not say “disabled”; configuration and instantaneous counter status are shown separately.
## Reports, health score, and data coverage
TXT and JSON reports are saved by default to the `system_analyses_reports` folder. Reports may contain hardware models, disk serial numbers, device paths, driver details, and system-configuration information. Review these fields before sharing a report.
`Data coverage` is not an accuracy guarantee or a health score; it indicates how much of the requested source/measurement data was obtained. The hardware-health score also depends on measured sensors, Windows events, and separate health sources. A score of `100/100` does not mean that every component is flawless when SMART data was not obtained or a temperature measurement is unavailable. Review source attribution, measurement status, sensor sample count, and error notes separately.
## Workload suitability and measurement scope
Workload profiles are approximate indicators of hardware suitability; they are not application/codec/scene tests and do not guarantee FPS or render time. Each profile displays a `Measurement coverage` field. If a core clock/IPC measurement was not performed with `--quick` or `--no-jit`, `st_gops` calculated from default IPC values is only an estimate; it is not used on its own to classify office, audio, or photo workloads as `Insufficient`. Multi-core suitability is taken from a separate multi-core component rather than the combined CPU score, so a low/unmeasured single-core estimate does not artificially lower the multi-core result. When measurements are missing, the highest rating is capped at `Suitable` and the missing indicators remain visible in the report.
## Automated tests and real-hardware validation
All tests are in a single file:
```powershell
py -3.14 -Werror::SyntaxWarning -m py_compile system_analyses.py test_suite.py
py -3.14 -m unittest -v test_suite.py
```
Optionally, if pytest is installed:
```powershell
py -3.14 -m pytest -q
```
CLI startup checks:
```powershell
py -3.14 system_analyses.py --help
py -3.14 system_analyses.py --diagnostics
```
Automated tests cover synthetic providers, fixed JSON examples, parser inputs, schema behavior, and regressions. They do not physically access hardware; they do not establish that a Windows sensor driver, PawnIO, a specific USB bridge, or real-disk SMART access has been verified. Real-hardware validation must be performed separately on the target Windows 11 Pro x64 machine, with administrator permission where required.
### Static analysis and coverage quality gates
The GitHub Actions workflow contains three separate quality jobs: a Windows/Python 3.10–3.14 regression matrix; Ruff + ty + basedpyright static checks; and branch-coverage tests with a coverage threshold on Python 3.14. Ruff checks syntax/basic errors and undefined names across the main source and test files. `ty` and `basedpyright` initially apply strict type checking to the `scripts/check_coverage.py` quality-gate helper; not all type annotations in the main monolithic analyzer are yet checked in strict mode. The scope is designed to expand incrementally without a broad, risky rewrite of existing code.
The baseline thresholds for the main `system_analyses.py` file are at least 55% line coverage and 45% branch coverage. These were selected with a safety margin below the approximate Linux baseline of 60% line / 54% branch coverage; CI remeasures on Windows. The workflow fails if new regressions drop coverage below the thresholds. Windows-specific real-hardware access is not considered validated by a Linux-only test run.
For local quality checks (developer tools are not added to `requirements.txt` as application dependencies):
```powershell
py -3.14 -m pip install ruff ty basedpyright coverage
py -3.14 -Werror::SyntaxWarning -m py_compile system_analyses.py test_suite.py scripts/check_coverage.py
py -3.14 -m unittest -v test_suite.py
ruff check system_analyses.py test_suite.py scripts/check_coverage.py
ty check scripts/check_coverage.py
basedpyright --project pyproject.toml
py -3.14 -m coverage run --branch -m unittest -q test_suite.py
py -3.14 -m coverage json --pretty-print -o coverage.json
py -3.14 scripts/check_coverage.py coverage.json --line-min 55 --branch-min 45
```
## Data handling and limitations
- Hardware discovery is limited to information exposed by Windows, firmware/SMBIOS, drivers, connected devices, and the permissions available to the process.
- Missing sensor or SMART data remains unavailable/unknown; the analyzer does not invent temperatures, health values, device identities, or benchmark results.
- Hardware names and source identifiers are retained where possible. Reports can contain identifying device details; review them before sharing.
- SMART and Windows Storage Reliability remain separate sources. A SMART query that is unsupported or unmatched is not counted as a successful health check.
- Optional benchmarks may create temporary files, generate CPU/GPU load, or send limited network traffic. Read each CLI option before enabling such tests.
- The application is read-only with respect to Windows configuration, drivers, firmware, and device tuning. The optional PawnIO installation script is a separate, explicitly user-invoked operation.
## Release identity
This package starts at **`v1.0 — Initial Release`**. The previous package's version numbering is not continued in this English edition. Features and technical behavior carried forward from the supplied source archive are described above and summarized in `CHANGELOG.md` as part of this first release.