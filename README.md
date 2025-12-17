
# LilETW - Quick-n-Dirty ETW Parsing

### Features

- Supports configuring StackTracing (64-bit only) and EventID based filtering where applicable
- 64-bit KnownDll symbol resolving
- Normie types: returns a `std::optional<T>`
- Variable length inlined types (`UNICODE_STRING`, `SID`, `char`): returns a `std::unique_ptr<T>`
- Easy trace session setup via `StartTraceSession`
- Trace sessions get cleaned-up automatically at program exit. Also possible manually by calling `StopSession`
- Maybe some issue with special types with different providers idk
- Possible raceconditions in some places

Use [EtwExplorer](https://github.com/zodiacon/EtwExplorer) to find providers, events, keywords, member types etc.

---

## Examples

### Microsoft-Antimalware-AMFilter Provider, FileScan Event with EventID based filtering

```c++
#include "LilETW.hpp"
#include <thread>

#define ETW_SESSION_NAME L"Whatever"

static const GUID g_AMFilter = { 0xcfeb0608, 0x330e, 0x4410, { 0xb0, 0x0d, 0x56, 0xd8, 0xda, 0x99, 0x86, 0xe6 } };

bool CtrlHandler(DWORD ctrl_type) {

	switch (ctrl_type) {

	case CTRL_C_EVENT: {
		std::exit(0);
	}
	default:
		return false;
	}
}

void Callback(EVENT_RECORD* EventRecord) {

	LilETW::EventParser parser(EventRecord);

	auto file_name = parser.ParseMember<UNICODE_STRING>(L"FileName");

	if (file_name) {
		std::printf("File: %ws\n", file_name->Buffer);
	}
}

int main(int argc, char** argv) {

	std::vector<USHORT> filter_ids = { 9 }; // Only get this EventID in your callback
	auto trace = LilETW::TraceSessions::Get().StartTraceSession(g_AMFilter, ETW_SESSION_NAME, Callback, 8, false, TRACE_LEVEL_INFORMATION, 0x1, filter_ids, {});

	if (trace == INVALID_PROCESSTRACE_HANDLE) {
		return -1;
	}

	::SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, true);

	std::thread([](PROCESSTRACE_HANDLE handle) {
		::ProcessTrace(&handle, 1, nullptr, nullptr);
	}, trace).join();

	return 0;
}
```

Output:
```
...
File: HarddiskVolume3\Users\dev\AppData\Local\Temp\__PSScriptPolicyTest_yrt3ktpj.z3e.ps1
File: HarddiskVolume3\Users\dev\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
File: HarddiskVolume3\Windows\apppatch\pcamain.sdb
File: HarddiskVolume3\Windows\Prefetch\MSEDGE.EXE-37D25FAA.pf
File: HarddiskVolume3\Windows\Prefetch\MSEDGE.EXE-37D25FAA.pf
File: HarddiskVolume3\Windows\Prefetch\OPENCONSOLE.EXE-DDA41F0C.pf
File: HarddiskVolume3\Windows\Prefetch\OPENCONSOLE.EXE-DDA41F0C.pf
File: HarddiskVolume3\Windows\Prefetch\POWERSHELL.EXE-CA1AE517.pf
File: HarddiskVolume3\Windows\Prefetch\MSEDGE.EXE-37D25F9B.pf
File: HarddiskVolume3\Users\dev\AppData\Local\Microsoft\Edge\User Data\Default\Asset Store\assets.db\LOG
File: HarddiskVolume3\Windows\Prefetch\MSEDGE.EXE-37D25F9B.pf
File: HarddiskVolume3\Users\dev\AppData\Local\Microsoft\Edge\User Data\first_party_sets.db
File: HarddiskVolume3\Windows\Prefetch\ELEVATION_SERVICE.EXE-C59080CA.pf
File: HarddiskVolume3\Windows\Prefetch\ELEVATION_SERVICE.EXE-C59080CA.pf
File: HarddiskVolume3\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.AAD.BrokerPlugin_1000.19580.1000.2_neutral_neutral_cw5n1h2txyewy\ActivationStore.dat
File: HarddiskVolume3\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.AAD.BrokerPlugin_1000.19580.1000.2_neutral_neutral_cw5n1h2txyewy\ActivationStore.dat.LOG1
File: HarddiskVolume3\ProgramData\Microsoft\Windows\AppRepository\Packages\Microsoft.AAD.BrokerPlugin_1000.19580.1000.2_neutral_neutral_cw5n1h2txyewy\ActivationStore.dat
...
```

---

### [System Process Provider](https://learn.microsoft.com/en-us/windows/win32/etw/system-providers#system-process-provider), [Process Start, End, Start Data Collection Events](https://learn.microsoft.com/en-us/windows/win32/etw/process)

> [!NOTE]
> System providers dont support filters, usually they just get ignored. Filter yourself in your callback

```c++
static const GUID g_SysProcessProviderGuid = { 0x151f55dc, 0x467d, 0x471f, { 0x83, 0xb5, 0x5f, 0x88, 0x9d, 0x46, 0xff, 0x66 } };

void Callback(EVENT_RECORD* EventRecord) {

	if (EventRecord->EventHeader.EventDescriptor.Opcode <= 3) {

		LilETW::EventParser parser(EventRecord);

		auto pid	= parser.ParseMember<ULONG>(L"ProcessId");
		auto image	= parser.ParseMember<char>(L"ImageFileName");
		auto sid	= parser.ParseMember<SID>(L"UserSID");

		LPSTR sid_string;
		::ConvertSidToStringSidA(sid.get(), &sid_string);

		switch (EventRecord->EventHeader.EventDescriptor.Opcode) {
		case 1: {
			std::printf("Start [%d] - %s - %s\n", pid.value(), image.get(), sid_string);
			break;
		}
		case 2: {
			std::printf("End [%d] - %s\n", pid.value(), image.get());
			break;
		}
		case 3: {
			std::printf("Already running [%d] - %s - %s\n", pid.value(), image.get(), sid_string);
			break;
		}
		default:
			break;
		}

		::LocalFree(sid_string);
	}
}

...

auto trace = LilETW::TraceSessions::Get().StartTraceSession(g_SysProcessProviderGuid, ETW_SESSION_NAME, Callback, 4, true, TRACE_LEVEL_INFORMATION, SYSTEM_PROCESS_KW_GENERAL, {}, {});
```

Output:
```
...
Already running [8284] - RuntimeBroker.exe - S-1-5-21-4276899442-4019503543-527621159-1001
Already running [9948] - svchost.exe - S-1-5-18
Already running [9740] - msedge.exe - S-1-5-21-4276899442-4019503543-527621159-1001
Already running [9720] - msedge.exe - S-1-5-21-4276899442-4019503543-527621159-1001
Already running [9772] - msedge.exe - S-1-5-21-4276899442-4019503543-527621159-1001
Already running [2860] - msedge.exe - S-1-5-21-4276899442-4019503543-527621159-1001
Already running [4652] - msedge.exe - S-1-5-21-4276899442-4019503543-527621159-1001
Already running [10340] - test.exe - S-1-5-21-4276899442-4019503543-527621159-1001
Start [10392] - msedge.exe - S-1-5-21-4276899442-4019503543-527621159-1001
Start [10400] - msedge.exe - S-1-5-21-4276899442-4019503543-527621159-1001
Start [10416] - msedge.exe - S-1-5-21-4276899442-4019503543-527621159-1001
End [10392] - msedge.exe
End [10400] - msedge.exe
End [10416] - msedge.exe
End [9720] - msedge.exe
End [9740] - msedge.exe
End [9772] - msedge.exe
End [8284] - RuntimeBroker.exe
Start [10900] - smartscreen.exe - S-1-5-21-4276899442-4019503543-527621159-1001
...
```


---

### Microsoft-Windows-RPC Provider, RpcClientCallStart_V1 Event with StackTraces, EventID based filtering and Symbol resolving

```c++
static const GUID g_WindowsRpc = { 0x6ad52b32, 0xd609, 0x4be9, { 0xae, 0x07, 0xce, 0x8d, 0xae, 0x93, 0x7e, 0x39 } };

void Callback(EVENT_RECORD* EventRecord) {

	LilETW::EventParser parser(EventRecord);

	auto guid		= parser.ParseMember<GUID>(L"InterfaceUuid");
	auto imp_level	= parser.ParseMember<ULONG>(L"ImpersonationLevel");
	auto auth_level	= parser.ParseMember<ULONG>(L"AuthenticationLevel");

	auto frames		= parser.GetStackFrames64();

	wchar_t buf[39];
	::StringFromGUID2(*guid, buf, 39);

	std::printf("PID: %d - InterfaceUuid: %ws - ImpersonationLevel: %d - AuthenticationLevel: %d\n", parser.GetProcessId(), buf, imp_level.value(), auth_level.value());

	if (!frames.empty()) {

		for (auto frame : frames) {

			if (frame == 0x0 || frame >= 0xFFFF000000000000) {
				continue;
			}
			
			auto sym = parser.ResolveSymbol(frame);
			if (!sym.empty()) {
				std::printf("%s\n", sym.c_str());
			}
			else {
				std::printf("0x%p\n", frame);
			}
		}
	}

	std::printf("---\n");
}
...

std::vector<USHORT> filter_ids = { 5 }; // When you don't know keywords for an event, can use MAXULONGLONG Keyword with a filter
std::vector<USHORT> stacktrace = { 5 }; // Also configure stacktracing for EventId 5
LilETW::Symbols::Syms();				// Init symbols upfront
auto trace = LilETW::TraceSessions::Get().StartTraceSession(g_WindowsRpc, ETW_SESSION_NAME, Callback, 8, false, TRACE_LEVEL_VERBOSE, MAXULONGLONG, filter_ids, stacktrace);
```

Output:
```
...
---
PID: 8780 - InterfaceUuid: {A3225F5A-EBEE-42D7-A497-0AB0A601F9EF} - ImpersonationLevel: 2 - AuthenticationLevel: 6
ntdll!NtTraceEvent+0x17
ntdll!EtwEventWriteTransfer+0x241
rpcrt4!RpcBindingFromStringBindingW+0x3a97
rpcrt4!I_RpcNegotiateTransferSyntax+0x2d4
combase!CoWaitForMultipleHandles+0x2865
combase!CoTaskMemAlloc+0x63a0
combase!CoTaskMemAlloc+0x4bf2
combase!CoTaskMemAlloc+0x40c6
rpcrt4!NdrClientCall3+0x3c2
combase!WindowsCompareStringOrdinal+0x386
combase!ObjectStublessClient32+0x7e62
0x00007FF643EE251B
0x00007FFEECA8168D
0x00007FFEECA848E2
0x00007FFEECA84759
ntdll!TpSetWaitEx+0xa89
ntdll!RtlSetThreadSubProcessTag+0x1f7d
kernel32!BaseThreadInitThunk+0x17
ntdll!RtlUserThreadStart+0x2c
---
...
```
