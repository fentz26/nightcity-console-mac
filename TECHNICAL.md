# NightCity Console: how it works and how it was built

This document is the deep technical record of porting Cyber Engine Tweaks-style functionality to the native macOS (Apple Silicon) build of Cyberpunk 2077, and of the reverse engineering that made it possible. It covers injection, RTTI resolution, the engine calling convention, the Metal overlay, the launcher, and the concrete findings (addresses, struct layouts, bugs found and fixed) that this component depends on.

Everything here targets the macOS (Apple Silicon) Steam build of Cyberpunk 2077 v2.3.1. Offsets and hashes are specific to that build.

## 1. The problem

Cyber Engine Tweaks (CET) is the standard cheat/scripting console for Cyberpunk 2077 on Windows. It relies on D3D12 and Windows-specific hooking, so it does not exist on macOS, and neither does any equivalent. NightCity Console rebuilds the core of that capability from scratch on Apple Silicon:

- Inject code into the running game process without disabling System Integrity Protection.
- Resolve the engine's runtime type system (RTTI) and call game functions with real, typed arguments.
- Draw a console on the live frame and capture keyboard/mouse input safely.

Three properties of the macOS port make this materially different from the Windows original: Apple Silicon enforces W^X (a page cannot be writable and executable at once), the Mach-O/dyld image model differs from the PE/Windows loader, and the engine's macOS build was compiled with a different ABI in several places (CName passed by value, some constructors inlined, GS-segment TLS unavailable). Each of these forced a specific solution documented below.

## 2. Injection

The shipped game binary has the hardened runtime enabled but ships the entitlements `com.apple.security.cs.allow-dyld-environment-variables` and `disable-library-validation`. That combination means `DYLD_INSERT_LIBRARIES` works with SIP left on, and any validly-signed dylib (ad-hoc is fine) loads into the process. No SIP changes, no patching the executable's load commands at install time.

Three dylibs are injected:

- `RED4ext.dylib` (macOS port): a REDengine hooking framework. It also loads the Frida gadget.
- `FridaGadget.dylib`: an in-process Frida runtime. Its config (`FridaGadget.config`) auto-loads `red4ext_hooks.js` on startup.
- `libcyberconsole_overlay.dylib`: the native Metal/ImGui overlay (section 7).

Plus `DYLD_FORCE_FLAT_NAMESPACE=1` and `SteamAppId=1091500` so the Steam API initializes.

W^X is the reason for the Frida gadget rather than classic inline hooking. On Apple Silicon, direct binary patching in the style of Detours fails because code pages are not writable. Frida uses `MAP_JIT` memory and JIT trampolines (toggling write permission with `pthread_jit_write_protect_np`), which is the only W^X-safe way to install inline hooks on this platform. This is also why the game must be re-signed with `allow-jit` and `allow-unsigned-executable-memory` (section 8): without those entitlements, AMFI kills the process the instant the JIT engine produces code.

The command engine lives entirely in `red4ext_hooks.js`. The overlay is a separate native dylib. They are decoupled and talk through two files in `/tmp` (section 6).

## 3. Finding offsets (the reverse engineering)

The macOS build ships a rich symbol table: `nm` yields roughly 68,000 symbols with addresses. Runtime address resolution is:

```text
runtime_addr = symbol_vaddr - 0x100000000 + module_base
```

where `module_base` is the load address of the `Cyberpunk2077` executable image. The vendored `cyberpunk2077_addresses.json` from earlier port attempts is stale/wrong for 2.3.1, so every offset was re-derived from the binary's own symbols plus disassembly in Ghidra (headless analysis with custom DecompFunc/Disasm/XrefData scripts) and radare2.

### The dyld image-index bug

The single most damaging early bug, which cascaded across every other port in this ecosystem, was image-base resolution. Earlier attempts computed `module_base` with `_dyld_get_image_header(0)`. Under `DYLD_INSERT_LIBRARIES` injection, image index 0 is not the game executable; it is the host/injected image. The game executable sits at a higher dyld image index (around 3 under injection). Using index 0 produced a base that was off by the slide between images (on the order of gigabytes), so every derived address was wrong and the process crashed immediately.

The fix is to enumerate `_dyld_image_count()` and `_dyld_get_image_header()`, find the `mach_header_64` whose `filetype == MH_EXECUTE` (the game executable), and cache that base once. All address math derives from that value.

### Key resolved addresses (v2.3.1)

File vaddrs are shown; runtime address = `module_base + (vaddr - 0x100000000)`. Stated as a formula:

```text
address = symbol_vaddr - 0x100000000 + module_base
```

| Symbol / purpose | Address |
|---|---|
| Universal script executor `FUN_102173120` `(func, context, frame, result, resultType)` | `0x102173120` (runtime `0x2173120`) |
| RTTI registry getter `CRTTISystem::Get` | `0x102188e8c` (runtime `0x2188e8c`) |
| Opcode handler table (script VM dispatch), `module_base +` | `0x908b798` |
| `Main` entry (used for clean-shutdown hook) | `module_base + 0x31e18` |
| Per-scope loose-archive loader `FUN_103edafcc` | `0x103edafcc` |
| ArchiveSet `Append` `FUN_103edd568` | `0x103edd568` |
| Resource depot `LoadArchives` `FUN_103edaae8` | `0x103edaae8` |
| Archive glob (`*.archive`) `FUN_103eda360` | `0x103eda360` |

Every scripted call goes through the universal script executor `FUN_102173120`.

The RTTI registry vtable exposes `GetClass` at vtbl+0x10, `GetFunction` at vtbl+0x30, and `GetEnum` at vtbl+0x18.

### Hashing

- CName is the FNV-1a 64-bit hash (FNV1a64) of the type/function name. CName is passed by value (in `x0`) on this build, which differs from the Windows SDK where it is passed by pointer; wrapper functions account for this.
- TweakDBID is `CRC32(name) | (len << 32)`.

A subtle but important distinction: RTTI method/class lookups use FNV-1a 64-bit, while TweakDB flat-key hashing uses CRC32. Conflating the two silently resolves the wrong entries.

### Game 2.5 (3.0.88.46235)

The runtime recognizes a build only by the first 16 code bytes at its own `CRTTISystem::Get` offset (2.3.1: `f44fbea9fd7b01a9fd43009108df02d0` at `+0x2188e8c`; 2.5: `fd7bbfa9fd030091087d03d008013a91` at `+0x10b3cac`; checked against both Steam binaries, neither matches the other's). Any other build gets no offsets and NightCity Console stays inactive. It picks an offset set; see `GAME_OFFSETS` in `runtime/red4ext_hooks.js` and `nccOffsets()` in `overlay/overlay.mm`. The 2.5 values were re-derived from the 2.5 binary:

| Symbol / purpose | 2.3.1 | 2.5 |
|---|---|---|
| Universal script executor `(func, context, frame, result, resultType)` | `module_base + 0x2173120` | `module_base + 0x1099fbc` |
| `CRTTISystem::Get` (singleton getter) | `module_base + 0x2188e8c` | `module_base + 0x10b3cac` |
| `Main` (clean-shutdown hook; the `LC_MAIN` entry) | `module_base + 0x31e18` | `module_base + 0x323a0` |
| Opcode handler table | `module_base + 0x908b798` | `module_base + 0x9a5c940` |
| `CScriptStackFrame` destructor | n/a | `module_base + 0x11ab310` |
| PoolScript allocator (frame call map) | n/a | `module_base + 0x7cddb78` |

The executor was found through the FinalFunc opcode handler (table entry 0x24), which calls it with the same five arguments as before. Two layout changes from 2.5 matter here (they match the RED4ext.SDK 2.5 update):

- `CScriptStackFrame` grew from 0x68 to 0xA8. A root frame owns a call map at +0x68 and points +0x98 at it; child frames copy the parent's +0x98. The executor builds its child frame from the caller frame it is given, so a hand-built caller frame must be 0xA8 bytes and initialized like the engine's own constructor does (isRoot at +0x64, the map's -1 marker at +0x88, the PoolScript allocator at +0x90, +0x98 = frame + 0x68), then destroyed with the frame destructor after the call. A 0x90-byte frame without this makes the engine read past the end of it.
- Function objects grew by 0x40 bytes after `unkAC` (`CClassFunction` is now 0x100, `parent` at +0xF0). The fields used here (names at +0x08/+0x10, return type at +0x18, params at +0x28/+0x30) did not move, and `CClass` function arrays are still at +0x48/+0x58. The `IRTTISystem` slots used here (`GetClass` +0x10, `GetEnum` +0x18) are unchanged; 2.5 added four virtuals before the destructor.

Loose-archive mods (section 9) work on 2.5 without NightCity's loader: the 2.5 game scans `archive/Mac/mod` itself (tested: an archive overriding `base\localization\en-us\onscreens\onscreens.json` changed the main-menu text). On exFAT drives macOS writes a `._name.archive` AppleDouble sidecar next to each file; the game's `*.archive` glob picks it up, fails to read it and asks `gamemod::GameModService` (method `module_base + 0x1d17f28`, vtable +0x1a8) to show `UI-Modio-ErrorMessages-Reloading`, which goes through the ink UI singleton (`module_base + 0x8ece4d0`) before it exists and crashes at startup - also without NightCity. The launcher deletes `._*` files in `archive/Mac/mod`, `r6/scripts`, `r6/tweaks` and `red4ext/plugins` before every launch, and the runtime replaces that method with a wrapper that skips it while the UI singleton is null. NightCity's own mod-folder loader stays 2.3.1-only (2.5 would register the folder twice).

The Frida-side mod-loading hooks are not ported to 2.5: the RED4ext-style `CONFIG.hooks` other than `Main`, the ArchiveXL/TweakXL integration hooks (factory/mesh hooks, localization hook, native registration and bind diagnostics) and the auto-reload of installed mods through the `cybermodman_*Reload` exports, which exist only in the 2.3.1 plugin builds. These check `isGame231()` and skip themselves on other versions instead of attaching to unrelated code.

On 2.5 the plugins come from a separate payload instead (`Resources/native25`, a `red4ext/`-relative tree built by `tools/fetch-deps.sh` from `NATIVE25_DIR`): the native macOS RED4ext loader (jackmaxwil's RED4ext-macos port, built for 2.5), its 2.5 address database (`red4ext/bin/x64/cyberpunk2077_addresses.json`, only entries verified against the 2.5 binary), `red4ext_plugin_check`, a `config.ini` with `strict_version_check = true`, and 2.5 builds of TweakXL and ArchiveXL with their `Scripts/` (and TweakXL's `Data/`). The launcher installs it in place of the 2.3.1 loader, config and plugins. Copies of the 2.3.1 plugins and AddressLib that the launcher itself installed earlier (byte-identical to the bundled ones) are moved to `red4ext/nightcity-disabled/` and moved back on 2.3.1, where the 2.5 files that are byte-identical to the bundle are deleted first; any other file is left in place and the 2.3.1-only ones are named in the launcher's status line. Other versions get the console only.

The loader hooks the game's inner `Main` (`+0x4e3274c`) and `CGameApplication::AddState`; the Frida runtime hooks the LC_MAIN entry (`+0x323a0`), the script executor and the mod-folder boot guard, so no address is hooked twice (checked against the loader's hook list in an in-world run: 91 hooks from the loader and both plugins). A plugin's scripts declare its natives, so before every compile on 2.5 the launcher copies `red4ext/plugins/<name>/Scripts` to `r6/scripts/zz_nightcity_plugins/<name>` for each plugin that `red4ext_plugin_check` accepts (the same check the loader applies; a declared native that nobody registers stops the game at script init) and removes that folder on other versions. Scripts are compiled with redscript 0.5.32, the first release that reads 2.5's `final.redscripts`; it only adds reading the 2.5 bundle header, so 2.3.1 bundles compile as before. The launcher re-reads the game version on Install and Play, so a game update while it is open switches the payload.

New 2.5 items in the catalog: scripts cannot enumerate TweakDB, so the record lists were read from `r6/cache/tweakdb.bin` of both builds (records section: `u32 count`, then `{u32 crc32, u32 length, u32 type hash}`; 2.3.1 is depot 1460472 manifest 5981221262164233110). An item is new when its record ID is absent from the 2.3.1 file and its record type is one of the item types. That gives 118 records; one of them, `Items.Preset_Ashura_Twitch`, is a Phantom Liberty record that 2.5 moved from `tweakdb_ep1.bin` into the base file, so it is not new (the OPEN//77 2.31 catalogues, which include EP1, list it). Record existence and record names are separate questions: the `itemdump` console command resolved every new ID to its display name and item type in-game, and a name string was accepted only when it matches both the crc32 and the length (candidates from `tweakdb.bin`, `final.redscripts` and name templates). Unresolved IDs are listed in CET's `<TDBID:crc32:length>` form, which `give` accepts. Spawning was checked separately in-game with `give` followed by `removeitem`: all non-shard items were found in the inventory; shards go to the journal on pickup (old shards behave the same), so they are not removable. Two records whose display name is `!OBSOLETE` are left out.

## 4. Calling a game function

REDengine's native script handlers read their arguments from bytecode in a `CScriptStackFrame`. To call a function from outside the script VM, that frame is constructed by hand:

1. Resolve the function. `clsByName(name)` calls the registry's `GetClass`. The class's instance-function array (CClass+0x48) and static-function array (CClass+0x58) are scanned, walking up parent classes, matching the short-name CName at function+0x10. This yields a `CClassFunction*`, its return type, and whether it is static.
2. Marshal each argument by the function's declared parameter type. For each argument, a synthetic `CProperty` is allocated (type at +0x00, valueOffset at +0x20), the encoded value is written into a locals buffer at that offset, and a `LocalVar` opcode (0x18) referencing the property is emitted, ending with `ParamEnd` (0x26). Supported types: Int32/Uint32/Int64/Float/Bool, CName (FNV-1a 64), TweakDBID, gameItemID, enums (resolved by member name against the enum value list, or by literal integer), object handles (`@player`/`@self`/`@<ptr>` written as `{instance, refCount}`), and raw struct passthrough.
3. Invoke `FUN_102173120(func, context, frame, &result, returnType)` (the universal script executor) and read the result.

Two failure modes were learned the hard way:

- You must supply exactly the number of parameters the function declares (or stop only at a genuinely optional trailing param). Under-supplying makes the handler read `ParamEnd` as a value opcode and crash. NightCity Console logs each function's live signature so commands are built against the real shape.
- Items must be built with `ItemID.FromTDBID(TweakDBID)` to produce a proper `gameItemID` (correct rngSeed and structure). Hand-built IDs validate but never commit, so `FromTDBID` is mandatory.

The opcode handler table is a DATA-section table (`module_base + 0x908b798`), indexed at runtime by the frame's current code byte. It is a table of function pointers, not code, so it must be dereferenced rather than called directly. This matters when decoding typed arguments out of raw stack frames in observe-style hooks.

## 5. Getting live engine systems

Two mechanisms, both reached from the live `GameInstance` (obtained via `PlayerPuppet.GetGame()`):

- Scriptable systems (e.g. `PlayerDevelopmentSystem`): `GameInstance.GetScriptableSystemsContainer(gi)` (a static method on `ScriptGameInstance`) returns a container, then `container.Get(CName)` returns the instance.
- Other engine facilities (godmode, teleportation, player system) are not in that container. They come from static getters on `GameInstance`, e.g. `GetGodModeSystem(gi)`, `GetTeleportationFacility(gi)`, `GetPlayerSystem(gi)`. The helper `getViaGetter(gi, "GetXxx")` resolves the static getter and calls it with the 8-byte GameInstance pointer.

The player handle is subtle. The Frida hook captures any object whose vtable matches `PlayerPuppet`, but some of those are transient/preview puppets. Resolving the player deterministically via `PlayerSystem.GetLocalPlayerControlledGameObject()` (class `cpPlayerSystem`) fixed intermittent failures in commands that depend on the correct owner (item give, heal, and so on).

## 6. The command engine and channel

`red4ext_hooks.js` polls `/tmp/cp2077_cmd.txt` about twice a second. A command is queued and executed on the game thread at a clean point: when the script executor's call depth returns to zero, so the call is not nested inside another scripted call. Output is appended to `/tmp/cp2077_out.txt`. This file channel is the only coupling between the command engine and the overlay, which keeps the two completely independent.

Commands are simple verbs (`give`, `money`, `perks`, `level`, `heal`, `teleport`, `setfact`, `call`, and so on). A small translator also recognizes the most common CET copy-paste line, `Game.AddToInventory("Items.X", n)`, and routes it through the same path, so item codes from the internet work unchanged.

## 7. The in-game overlay (Metal + ImGui)

The Frida gadget here has no Objective-C bridge and no `Module.findExportByName`, so the overlay is a separate native dylib that uses the Objective-C runtime directly via method swizzling.

Render path:

- At load (deferred a few seconds so Metal is ready) the concrete command-buffer class is found at runtime (`object_getClass` on a command buffer from a throwaway queue; on Apple GPUs this is an `AGXG<n>FamilyCommandBuffer`, where `<n>` varies by chip family) and `presentDrawable:` is swizzled. Because the present selector exists in several variants on different hardware (`presentDrawable:`, `presentDrawable:atTime:`, `presentDrawable:afterMinimumDuration:`), all variants are hooked, with nesting depth tracked so ImGui renders exactly once per frame on the outermost call.
- In the hook, before calling the original, a render pass is built on the drawable's texture with `loadAction = Load` (preserving the game's frame), and Dear ImGui is drawn into the same command buffer so it composites on top, then the present proceeds. The layer reports `framebufferOnly = 0`, so the drawable texture is freely usable and no layer recreation is needed. Pixel format is RGBA8Unorm.

Input path (the tricky part, and the reason ImGui correctness held up):

- Events arrive on the main thread; ImGui runs on the render thread; ImGui is not thread safe. So `-[NSApplication sendEvent:]` is swizzled, keyboard/mouse data is extracted into a mutex-guarded queue, and that queue is drained on the render thread just before `ImGui::NewFrame`. All ImGui calls stay on one thread.
- The backtick/tilde key (and F1) toggles the console. While open, input is swallowed so the game does not also react. Clipboard is wired to `NSPasteboard` with `ConfigMacOSXBehaviors`, so Cmd+V/C/X/A work.

The overlay also hosts a declarative JSON tab engine (`overlay/tabs/`) with mtime-based hot-reload, so new tabs and content can ship without rebuilding the dylib.

## 8. The launcher app, Steam Cloud, and clean shutdown

The launcher (`launcher/`) is a small SwiftUI app. Install copies the payload into `<game>/red4ext/` and strips the `com.apple.quarantine` attribute from the files it writes. This is the key macOS trick: files written by a locally-running app are not quarantined, so dyld will load them. Play sets the injection environment and launches the game binary directly. It also re-signs the game binary ad-hoc with the `allow-jit` and `allow-unsigned-executable-memory` entitlements (required for the Frida JIT engine under W^X, section 2), dropping CDPR's identity while preserving the `cs.*` relaxations needed to satisfy AMFI. SIP and Gatekeeper remain enabled.

Two macOS-specific findings shaped the launcher:

- Steam launch options do not work for injection on macOS. Steam launches Mac games through LaunchServices (`open`), not by `exec`, so the Linux-style `"wrapper.sh" %command%` trick fails. Direct launch is the working path.
- The game crashes on exit when hooks are attached: a SIGSEGV in the engine's own teardown calling a stale hook/trampoline, after the save is flushed but before libc `exit()`. Replacing `exit()` with `_exit()` is too late. The fix is to hook `Main`'s return (the game is quitting, the save is done) and call `_exit(0)` immediately, so the crashing teardown never runs. This also fixed Steam Cloud: launching directly still registers the session with the Steam client, but the crash-on-exit was aborting Steam's post-session cloud upload; a clean exit lets it complete.

## 9. Loose-archive mods and the resource depot

Loose `.archive` mods load natively on macOS by integrating with the engine's resource depot. The path token differs from Windows: the engine scans `archive/Mac/mod/` (macOS) rather than `archive/pc/mod/` (Windows). A new Mod-scope archive group is registered and the engine's loader pulls `*.archive` files from it. The Mods tab in the overlay enumerates this directory and toggles mods by renaming `.archive` to `.archive.off`.

The load path is driven by a small set of engine functions, re-derived for this build:

| Purpose | Symbol | Address |
|---|---|---|
| Per-scope loose-archive loader | `FUN_103edafcc` | `0x103edafcc` |
| Append an archive to an `ArchiveSet` | `FUN_103edd568` | `0x103edd568` |
| Load archives into the depot | `FUN_103edaae8` | `0x103edaae8` |
| Glob the directory for `*.archive` | `FUN_103eda360` | `0x103eda360` |

The per-scope loader (`FUN_103edafcc`) walks an `ArchiveSet` (entry stride `0x38`, `basePath` at `+0x10`, `scope` at `+0x30`), globs each scope's directory with `FUN_103eda360` using the scope prefix plus `*.archive`, calls `Append` (`FUN_103edd568`) for each file found, and `LoadArchives` (`FUN_103edaae8`) brings them into the depot.

These struct layouts were re-derived for the ARM64 build (verified by raw memory reads against the live engine, not assumed from the Windows SDK):

`ResourceDepot` (total 0x58, larger layouts observed up to 0x80 depending on build view):

| Field | Offset |
|---|---|
| `groups` (DynArray of ArchiveGroup) | `+0x10` |
| `rootPath` (CString) | `+0x30` |
| `hasModArchives` (bool) | `+0x50` |

`ArchiveGroup` (stride 0x38):

| Field | Offset |
|---|---|
| `archives` (DynArray) | `+0x00` |
| `basePath` (CString) | `+0x10` |
| `scope` (u32) | `+0x30` |

`ArchiveScope` enum values: Content=1, DLC=2, Patch=3, Mod=4. A new Mod-scope group is inserted before the first non-Mod group so the base archives stay in place but mod content overlays them.

Load order on macOS is ASCII-alphabetical by filename with first-loaded-wins per-file conflict resolution. There is no `modlist.txt` priority file; ordering is controlled by filename prefix. This is the opposite resolution direction from Windows.

## 10. Findings reused from the wider macOS modding port

NightCity Console shares an address library and SDK with the macOS TweakXL and ArchiveXL ports. Several findings from that work are load-bearing here and are recorded for contributors.

### CString memory layout (macOS ARM64)

The engine's own CString constructor/copy/destructor are not address-mapped on this build (they exist only as relocation targets in the Windows SDK, which resolve to 0 and null-deref on macOS). CString is therefore implemented natively: 24 bytes total, small-string inline buffer for lengths under 0x14 (20) bytes, otherwise a `malloc`'d heap buffer with the heap flag `0x40000000` set in the length field. This was the root cause of crashes on any String/CString flat override before the native implementation was added.

### TweakDB flat-generation cache invalidation

Custom/cloned TweakDB records initially spawned with blank display names. The item display reads a cached descriptor at `record+0x60`, which is rebuilt only when the record's cached generation differs from the global TweakDB generation byte at offset `0x160`. An earlier code path zeroed `0x160` before cloning, so cached-gen 0 equalled global 0 forever and the cache never rebuilt. The fix is to increment the `unk160` generation byte after committing the batch, forcing a re-resolve on the next lookup. Live flats are indexed at TweakDB offset `0x40`.

### CClass::CreateInstance is inlined

A discrete `CClass::CreateInstance(size, zero)` function does not exist in this binary; it was inlined into every caller (a full `__TEXT` scan found zero matches). Instance creation uses a vtable substitute: `AllocMemory` at vtable+0xF0 and `ConstructCls` at vtable+0xE0. The +0x08 shift relative to the Windows SDK is the Itanium ABI destructor-slot insertion.

### TLS without the GS segment

Windows reads thread-local game state via `__readgsqword(0x58)`. macOS has no GS segment for this, so the SDK uses a pthread-based static `g_gameTLS` pointer initialized by a runtime hook (`Detail::SetGameTLS`) called from the game bootstrap. The relevant pointer sits 0x30 bytes into the TLS structure.

### Earlier TweakDB hook mis-targeting

A prior fork hardcoded TweakDB offsets (`0x2b79ac0`, `0x2b7be94`, `0x2b7bab0`) that were valid functions but never called at boot. They had been matched via string-xref to editor/config init functions rather than the retail boot loader, which has no string markers (it runs on dispatcher worker threads). The correct initialization target was found by dynamic differential tracing: retargeting to `StatsDataSystem::InitializeRecords`, which reliably fires after the TweakDB is loaded.

## 11. Known limits and where to contribute

- Godmode registers with the engine godmode system (`HasGodMode` returns true), but on 2.3.1 the damage pipeline still applies hit damage. It prevents death, not damage. A true zero-damage mode would need a per-tick health stat-pool refill.
- Teleport is blocked by the game during active combat. Bookmarks are session-only.
- Not yet implemented: real vehicle summon (needs the garage vehicle id, not just `ToggleSummonMode`), equip-to-slot (needs `EquipmentSystemPlayerData`), and NPC/vehicle spawning.
- Offsets are tied to game v2.3.1. A game update will likely require re-deriving them.

The signatures needed for the unfinished features were already captured by the `convdump` diagnostic and are documented in the command engine, so they are a reasonable starting point for contributions.

## 12. Build and packaging

- `overlay/build.sh` clones Dear ImGui (pinned) and compiles `libcyberconsole_overlay.dylib`.
- `tools/fetch-deps.sh` puts `RED4ext.dylib` and `FridaGadget.dylib` into `deps/` (copied from a local game install if present). These large binaries are never committed.
- `launcher/build-app.sh` compiles the SwiftUI app with `swiftc`, assembles the `.app` bundle, copies the payload into `Contents/Resources`, and ad-hoc signs it for local testing.
- `dev/launch.sh` builds the overlay, stages the payload into a running game copy, and launches it with injection (honoring `CP2077_DIR` for non-default Steam paths).
- `tools/sign-notarize.sh` re-signs everything inside-out with a Developer ID and hardened runtime, notarizes the app and the dmg with `notarytool`, staples the tickets, and produces `dist/NightCity-Console-for-Mac.dmg` that passes Gatekeeper with no warnings. Run with your own Apple Developer ID.
