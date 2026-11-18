#!/usr/bin/env python3
"""Offline contract tests for the six *read-only* watchOS native face probes.

This checks static code invariants, not iPhone/Watch sandbox behavior.
Actual device access requires running the signed watchOS app on 23U95.
"""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
objc = (root / "HermesEnabler2/BQNativeFaceBoundaryLab.m").read_text()
swift = (root / "HermesEnabler2/NativeFaceBoundaryLabView.swift").read_text()
headers = (root / "HermesEnabler2/BQPermissionDiagnostics.h").read_text()
transport = (root / "HermesEnabler2/WatchConnectivity/WatchConnectivityManager.swift").read_text()
backup = (root / "HermesEnabler2/BackupView.swift").read_text()
content = (root / "HermesEnabler2/ContentView.swift").read_text()

tests = {
    "BQRunNativeFaceMachPolicy": "native-face-mach-policy.txt",
    "BQRunNativeFaceBootstrapLookup": "native-face-bootstrap-lookup.txt",
    "BQRunNativeFaceStorePolicy": "native-face-store-policy.txt",
    "BQRunNativeFaceBundleInventory": "native-face-bundle-inventory.txt",
    "BQRunProtectedWriterServiceGate": "protected-writer-service-gate.txt",
    "BQRunTrustedDaemonPolicyDifferential": "trusted-daemon-policy-differential.txt",
}
for func, report in tests.items():
    assert re.search(r"NSString\s*\*\s*" + func + r"\s*\(void\)", objc), func
    assert func in headers and func in swift, func
    assert report in objc and report in transport, report

assert 'NativeFaceBoundaryLabView()' in backup
assert 'NativeFaceBoundaryLabView()' in content
assert '"com.apple.nanofacegallery.librarybroker.server"' in objc
assert '"com.apple.nanotimekit.replication.library.listener"' in objc
assert '"com.apple.NanoTimeKit.complication"' in objc
assert '"com.apple.nanofacegallery.gallerybroker.server"' in objc
assert '"com.apple.nanotimekit.collectionserver"' in objc
assert 'sandbox_check' in objc and 'bootstrap_look_up' in objc
assert 'BOOTSTRAP_NOT_PRIVILEGED' in objc and 'BOOTSTRAP_UNKNOWN_SERVICE' in objc
assert '@"com.apple.tccd"' in objc and '@"com.apple.mobile.softwareupdated"' in objc
assert 'st.st_uid == geteuid()' in objc
assert 'T5 · TCC / Software Update' in swift
assert 'T6 · Apple-daemonrechten' in swift
assert 'T7 · ClockKit-validatie' in swift
assert 'T8 · Positieve Apple-controle' in swift
assert 'BQRunClockKitAvailabilityDifferential' in headers
assert 'BQRunClockKitAvailabilityDifferential()' in swift
assert '"clockkit-availability-differential.txt"' in transport
assert 'BQRunClockKitReadOnlyFaceValidation' in headers and 'BQRunClockKitReadOnlyFaceValidation()' in swift
assert '"clockkit-readonly-face-validation.txt"' in transport
t7 = (root / "HermesEnabler2/BQClockKitReadonlyValidation.m").read_text()
assert 'validateFaceType:faceType faceBundleId:bundleID' in t7
assert 'remoteObjectProxyWithErrorHandler:' in t7
assert 'BQCkRunNeverExists' not in t7
assert '5*NSEC_PER_SEC' in t7  # bounded XPC response wait; no infinite blocking
assert 'initWithMachServiceName:options:' in t7
assert 'initWithServiceName:"' not in t7  # only original failure mentioned in logs
assert 'TRANSPORT_ERROR' in t7 and 'SKIPPED: native face checks' in t7
assert 'const NSUInteger originalMachOptions = (NSUInteger)0x1000' in t7
assert '@"com.apple.ClockKit.CLKWatchFaceLibrary",originalMachOptions' in t7
assert 'it DOES NOT elevate our app' in t7
assert 'BQCKRequestValidation(connection,' in t7
assert 'remoteObjectProxyWithErrorHandler' in t7
assert 'if (!bundle.length) continue;' in t7
assert 'BQCKKnownAvailableStandardFace' in t7
assert 'NTKFaceDescriptor' in t7 and 'CLKDevice' in t7
assert 'BQCKLocalBundleAvailability' in t7
assert 'initWithBundleIdentifier:' in t7
assert 'LOCAL native Zeus availability:' in t7
assert 'LOCAL native Hermès2025 availability:' in t7
assert 'isAvailableForDevice:' in t7
assert 'style<44' in t7
assert 'POSITIVE CONTROL PASS' in t7
assert 'SKIPPED Hermès comparisons because server/device availability contexts disagree' in t7
assert 'BQCKRequestValidation(connection,validType,@"")' in t7
assert 'clockkit-availability-differential.txt' in t7
assert '0x1000' in t7
assert 'BQRunClockKitAvailabilityDifferential()' not in swift.split("private func runAll()",1)[1]
assert '"clockkit-readonly-face-validation.txt"' in t7
assert '"com.apple.ClockKit.CLKWatchFaceLibrary"' in t7
# T7 may only call Apple's *validator*. It is a separate opt-in, never in the
# existing six-test read-only batch and cannot import or mutate native faces.
batch = swift.split("private func runAll()",1)[1]
assert 'BQRunClockKitReadOnlyFaceValidation()' not in batch
code_t7 = re.sub(r'/\\*.*?\\*/|//[^\\n]*', '', t7, flags=re.S)
code_t7 = re.sub(r'@"(?:\\\\.|[^"\\\\])*"|"(?:(?:\\\\.)|[^"\\\\])*"', '""', code_t7)
for forbidden in ('addWatchFaceAtURL:', 'openWatchFaceURLWithSecurityScopedURL:',
    'openWatchFaceURLWithBookmarkData:', '_queue_addFace:forUUID:',
    'rebuildCache:', 'setCacheSentinel:', 'MGSetAnswer(', 'pwrite(', 'unlink('):
    assert forbidden not in code_t7, f"Forbidden unsafe T7 method: {forbidden}"

assert 'proc_listallpids' in objc and 'proc_name' in objc
assert 'check(pid, "file-write-data"' in objc
assert 'task_get_special_port(mach_task_self()' not in objc, (
    "Private direct API declared unavailable for watchOS: resolve dynamically")
assert 'O_RDONLY | O_NOFOLLOW | O_CLOEXEC' in objc
assert 'open(path.fileSystemRepresentation, flags)' in objc
assert 'NSString *destination = [BQDocuments() stringByAppendingPathComponent:name]' in objc

# No protected mutating APIs. The caller must not grant private entitlements.
for pattern in [
    r'\b(?:pwrite|pwritev|write|writev|ftruncate|truncate|unlink|rename|'
    r'renameat|symlink|link|mkdir|rmdir|chmod|chown|'
    r'sandbox_extension_consume|xpc_connection_send_message)\s*\(',
    r'\bNSXPCConnection\s*\*',
    r'open\s*\(\s*[^,]+\s*,\s*O_(?:WRONLY|RDWR|CREAT|TRUNC)',
]:
    # Strip comments and quoted strings so explanatory text cannot spoof API use.
    code = re.sub(r'/\*.*?\*/|//[^\n]*', '', objc, flags=re.S)
    code = re.sub(r'@"(?:\\.|[^"\\])*"|"(?:\\.|[^"\\])*"', '""', code)
    assert not re.search(pattern, code), f"Disallowed protected mutation pattern: {pattern}"

print("PASS: six no-RPC watchOS probes plus T7/T8 separately opt-in read-only ClockKit validations")
print("PASS: pre-backup navigation and matching Swift interface entrypoints")
print("PASS: only read-only filesystem descriptors; own-Documents log output")
print("NOTE: no on-device native Hermès unlock inferred from this source test")
