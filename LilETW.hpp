#ifndef LILETW_HPP
#define LILETW_HPP

#include <windows.h>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <span>
#include <unordered_map>
#include <tdh.h>

#ifdef _MSC_VER
#pragma comment(lib, "tdh.lib")
#endif


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;

namespace LilETW {

	template<typename T>
	concept EtwSpecialType = std::is_same_v<T, UNICODE_STRING> || std::is_same_v<T, SID> || std::is_same_v<T, char>;

	class TraceSessions {
	public:
		static TraceSessions& Get() {
			static std::unique_ptr<TraceSessions> instance = std::make_unique<TraceSessions>();
			return *instance;
		}

		TraceSessions() = default;
		TraceSessions(TraceSessions const&) = delete;
		TraceSessions& operator=(TraceSessions const&) = delete;

		~TraceSessions() {

			while (!m_TraceSessions.empty()) {
				StopSession(m_TraceSessions.begin()->first);
			}
		}

		auto StartTraceSession(
			_In_ const GUID ProviderGuid,
			_In_ std::wstring Tracename,
			_In_ PEVENT_RECORD_CALLBACK Callback,
			_In_ ULONG BufferPageSizeMultiplier,
			_In_ BOOL SystemLogger,
			_In_ UCHAR Level,
			_In_ ULONGLONG Keywords,
			_In_ std::vector<USHORT> FilterIds,
			_In_ std::vector<USHORT> StacktraceIds
		) -> PROCESSTRACE_HANDLE {

			PROCESSTRACE_HANDLE			handle;
			EVENT_TRACE_LOGFILEW		logfile{};
			ENABLE_TRACE_PARAMETERS*	params = nullptr;

			std::unique_ptr<ENABLE_TRACE_PARAMETERS>	trace_params;
			std::vector<EVENT_FILTER_DESCRIPTOR>		filter_descs;
			std::vector<std::unique_ptr<BYTE[]>>		filter_mem;
						
			auto size = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES)) + static_cast<ULONG>(512 * sizeof(wchar_t));
			auto buffer = std::make_unique<BYTE[]>(size);

			std::memset(buffer.get(), 0, size);

			auto trace_properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.get());

			trace_properties->Wnode.Flags			= WNODE_FLAG_TRACED_GUID;
			trace_properties->Wnode.BufferSize		= size;
			trace_properties->Wnode.ClientContext	= 1;

			trace_properties->BufferSize		= 0x1000 * BufferPageSizeMultiplier;
			trace_properties->LogFileMode		= EVENT_TRACE_REAL_TIME_MODE | (SystemLogger ? EVENT_TRACE_SYSTEM_LOGGER_MODE : 0);
			trace_properties->MinimumBuffers	= 0;
			trace_properties->LoggerNameOffset	= sizeof(EVENT_TRACE_PROPERTIES);
			trace_properties->LogFileNameOffset	= 0;

			logfile.LogFileName			= nullptr;
			logfile.LoggerName			= Tracename.data();
			logfile.ProcessTraceMode	= PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
			logfile.EventRecordCallback	= Callback;

			if (!FilterIds.empty() || !StacktraceIds.empty()) {

				auto create_filter = [&filter_mem](const std::vector<USHORT>& ids, ULONG type) -> EVENT_FILTER_DESCRIPTOR {

					auto filter_size = sizeof(EVENT_FILTER_EVENT_ID) + (ids.size() - 1) * sizeof(USHORT);
					auto mem = std::make_unique<BYTE[]>(filter_size);
					std::memset(mem.get(), 0, filter_size);

					auto* filter = reinterpret_cast<EVENT_FILTER_EVENT_ID*>(mem.get());
					filter->FilterIn = true;
					filter->Count = static_cast<USHORT>(ids.size());

					for (size_t i = 0; i < ids.size(); i++) {
						filter->Events[i] = ids[i];
					}

					EVENT_FILTER_DESCRIPTOR desc{};
					desc.Ptr	= reinterpret_cast<ULONGLONG>(filter);
					desc.Size	= static_cast<ULONG>(filter_size);
					desc.Type	= type;

					filter_mem.push_back(std::move(mem));
					return desc;
				};

				if (!FilterIds.empty()) {
					filter_descs.push_back(create_filter(FilterIds, EVENT_FILTER_TYPE_EVENT_ID));
				}

				if (!StacktraceIds.empty()) {
					filter_descs.push_back(create_filter(StacktraceIds, EVENT_FILTER_TYPE_STACKWALK));
				}

				trace_params = std::make_unique<ENABLE_TRACE_PARAMETERS>();
				std::memset(trace_params.get(), 0, sizeof(ENABLE_TRACE_PARAMETERS));

				trace_params->Version			= ENABLE_TRACE_PARAMETERS_VERSION_2;
				trace_params->EnableFilterDesc	= filter_descs.data();
				trace_params->FilterDescCount	= static_cast<ULONG>(filter_descs.size());
				trace_params->EnableProperty	= StacktraceIds.empty() ? 0 : EVENT_ENABLE_PROPERTY_STACK_TRACE;

				params = trace_params.get();
			}

			auto status = ::StartTraceW(&handle, Tracename.data(), trace_properties);

			if (status != ERROR_SUCCESS) {
				std::printf("[!] StartTraceW: %lu\n", status);
				return INVALID_PROCESSTRACE_HANDLE;
			}

			if ((status = ::EnableTraceEx2(handle, &ProviderGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, Level, Keywords, 0, INFINITE, params)) != ERROR_SUCCESS) {
				std::printf("[!] EnableTraceEx2: %lu\n", status);
				return INVALID_PROCESSTRACE_HANDLE;
			}

			if ((handle = ::OpenTraceW(&logfile)) == INVALID_PROCESSTRACE_HANDLE) {
				std::printf("[!] OpenTraceW: %lu\n", ::GetLastError());
				return INVALID_PROCESSTRACE_HANDLE;
			}

			m_TraceSessions.emplace(handle, TraceSessionData{ handle, std::move(buffer), Tracename });
			return handle;
		}

		auto StopSession(_In_ PROCESSTRACE_HANDLE Tracehandle) -> void {

			if (Tracehandle == INVALID_PROCESSTRACE_HANDLE) {
				return;
			}

			auto it = m_TraceSessions.find(Tracehandle);

			if (it != m_TraceSessions.end()) {

				auto& session = it->second;

				auto status = ::ControlTraceW(0, session.Tracename.data(), reinterpret_cast<EVENT_TRACE_PROPERTIES*>(session.TraceProperties.get()), EVENT_TRACE_CONTROL_STOP);

				if (status != ERROR_SUCCESS) {
					std::printf("ControlTraceW (stopping): %lu\n", status);
				}

				m_TraceSessions.erase(it);
			}
		};

	private:

		struct TraceSessionData {
			PROCESSTRACE_HANDLE TraceHandle;
			std::unique_ptr<BYTE[]> TraceProperties;
			std::wstring Tracename;
		};

		std::unordered_map<PROCESSTRACE_HANDLE, TraceSessionData> m_TraceSessions;
	};


	class EventParser {
	public:

		explicit EventParser(EVENT_RECORD* EventRecord) : m_EventRecord(EventRecord) {}

		~EventParser() = default;

		std::span<ULONG64> GetStackFrames64() const {

			if (m_EventRecord->ExtendedDataCount == 0 || !m_EventRecord->ExtendedData[0].DataPtr || m_EventRecord->ExtendedData[0].ExtType != EVENT_HEADER_EXT_TYPE_STACK_TRACE64) {
				return {};
			}

			return std::span<ULONG64>(reinterpret_cast<ULONG64*>(m_EventRecord->ExtendedData[0].DataPtr), m_EventRecord->ExtendedData[0].DataSize / sizeof(ULONG64));
		}

		USHORT GetEventId() const {
			return m_EventRecord->EventHeader.EventDescriptor.Id;
		}

		ULONG GetProcessId() const {
			return m_EventRecord->EventHeader.ProcessId;
		}

		template<typename T>
		auto ParseMember(_In_ const std::wstring& member_name) {

			using ReturnTypes = std::conditional_t<EtwSpecialType<T>, std::unique_ptr<T>, std::optional<T>>;

			PROPERTY_DATA_DESCRIPTOR data_desc;

			if (!m_EventInfo) {
				RetrieveEventInfo();
			}

			for (ULONG i = 0; i < m_EventInfo->TopLevelPropertyCount; i++) {

				auto* property_info = reinterpret_cast<EVENT_PROPERTY_INFO*>(&m_EventInfo->EventPropertyInfoArray[i]);

				auto current_name = std::wstring(
					reinterpret_cast<WCHAR*>(
						reinterpret_cast<BYTE*>(m_EventInfo) + property_info->NameOffset
					)
				);

				if (current_name != member_name) {
					continue;
				}

				data_desc.Reserved		= 0;
				data_desc.ArrayIndex	= ULONG_MAX;
				data_desc.PropertyName	= reinterpret_cast<ULONGLONG>(
					reinterpret_cast<BYTE*>(m_EventInfo) + property_info->NameOffset
				);

				ULONG property_len = property_info->length;

				if (!property_len) {

					auto status = ::TdhGetPropertySize(m_EventRecord, 0, nullptr, 1, &data_desc, &property_len);

					if (status != ERROR_SUCCESS) {
						std::printf("TdhGetPropertySize: %lu\n", status);
						return ReturnTypes{};
					}
				}
				
				if constexpr (EtwSpecialType<T>) {
					return RetrieveSpecial<T>(data_desc, property_len);
				}
				else {
					return RetrieveNormal<T>(data_desc);
				}
			}

			std::printf("Member not found. %ws\n", member_name.c_str());
			return ReturnTypes{};
		}

	private:

		EVENT_RECORD*			m_EventRecord;
		TRACE_EVENT_INFO*		m_EventInfo	= nullptr;
		std::unique_ptr<BYTE[]> m_EventInfoBuffer;

		auto RetrieveEventInfo() -> void {

			ULONG buffer_size	= 0;
			ULONG status		= ::TdhGetEventInformation(m_EventRecord, 0, nullptr, nullptr, &buffer_size);

			if (status != ERROR_INSUFFICIENT_BUFFER) {
				std::printf("TdhGetEventInformation query failed: %lu\n", status);
				return;
			}

			m_EventInfoBuffer = std::make_unique<BYTE[]>(buffer_size);
			m_EventInfo = reinterpret_cast<TRACE_EVENT_INFO*>(m_EventInfoBuffer.get());

			status = ::TdhGetEventInformation(m_EventRecord, 0, nullptr, m_EventInfo, &buffer_size);

			if (status != ERROR_SUCCESS) {
				std::printf("TdhGetEventInformation fetch failed: %lu\n", status);
			}
		}

		template<typename T>
		requires (!EtwSpecialType<T>)
		auto RetrieveNormal(_In_ PROPERTY_DATA_DESCRIPTOR& description) -> std::optional<T> {

			T value{};

			auto status = ::TdhGetProperty(m_EventRecord, 0, nullptr, 1, &description, sizeof(T), reinterpret_cast<BYTE*>(&value));

			if (status != ERROR_SUCCESS) {
				std::printf("TdhGetProperty (normal): %lu\n", status);
				return std::nullopt;
			}

			return value;
		}

		template<typename T>
		requires (EtwSpecialType<T>&& std::is_trivially_destructible_v<T>)
		auto RetrieveSpecial(_In_ PROPERTY_DATA_DESCRIPTOR& description, _In_ ULONG size) -> std::unique_ptr<T> {

			if constexpr (std::is_same_v<T, UNICODE_STRING>) {
				if (size < sizeof(T)) {
					return nullptr;
				}
			}

			auto tmp = std::make_unique<std::byte[]>(size);

			auto status = ::TdhGetProperty(m_EventRecord, 0, nullptr, 1, &description, size, reinterpret_cast<BYTE*>(tmp.get()));

			if (status != ERROR_SUCCESS) {
				std::printf("TdhGetProperty (special): %lu\n", status);
				return nullptr;
			}

			auto offset = 0;

			if constexpr (std::is_same_v<T, SID>) {
				offset = 16;
			}

			void* raw = ::operator new(size - offset, std::nothrow);

			if (!raw) {
				return nullptr;
			}

			std::memcpy(raw, tmp.get() + offset, size - offset);

			T* ptr = reinterpret_cast<T*>(raw);

			if constexpr (std::is_same_v<T, UNICODE_STRING>) {
				ptr->Buffer = reinterpret_cast<PWSTR>(reinterpret_cast<std::byte*>(ptr) + sizeof(T));
			}

			return std::unique_ptr<T>(ptr);
		}

	};
}

#endif // !LILETW_HPP