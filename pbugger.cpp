#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

class Debugger {
public:
    Debugger() {
        h_process_ = nullptr;
        pid_ = 0;
        debugger_active_ = false;
    }

    bool load(const std::wstring &path_to_exe) {
        STARTUPINFO startup_info = {};
        PROCESS_INFORMATION process_info = {};

        startup_info.dwFlags = STARTF_USESHOWWINDOW;
        startup_info.wShowWindow = SW_HIDE;

        // Set the struct size
        startup_info.cb = sizeof(startup_info);

        // CreateProcess expects a non-const string for the application name
        // We'll pass NULL for application name and use command line instead
        std::wstring cmd_line = path_to_exe;

        if (CreateProcess(
            nullptr, // Application name (NULL to use command line)
            reinterpret_cast<LPSTR>(&cmd_line[0]), // Command line (modifiable)
            nullptr, // Process security attributes
            nullptr, // Thread security attributes
            FALSE, // Inherit handles
            DEBUG_PROCESS, // Determines how to create the process
            nullptr, // Environment
            nullptr, // Current directory
            &startup_info, // Startup info
            &process_info // Process information
        )) {
            std::cout << "[*] We have successfully launched the process!" << std::endl;
            std::cout << "[*] PID: " << process_info.dwProcessId << std::endl;

            // Obtain a valid handle to the newly created process
            // and store it for future access
            h_process_ = open_process(process_info.dwProcessId);
            pid_ = process_info.dwProcessId;
            debugger_active_ = true;

            // Close the handles from CreateProcess since we have our own
            CloseHandle(process_info.hProcess);
            CloseHandle(process_info.hThread);

            // Start the debugging loop
            run();

            return true;
        } else {
            std::cout << "[*] Error: 0x" << std::hex << GetLastError() << "\n";
            return false;
        }
    }

    static HANDLE open_process(const DWORD pid) {
        return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }

    static HANDLE open_thread(const DWORD thread_id) {
        if (const auto h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id); h_thread != nullptr) {
            return h_thread;
        }

        std::cout << "[*] Unable to open the thread.\n";
        return nullptr;
    }

    [[nodiscard]] std::vector<DWORD> enumerate_threads() const {
        std::vector<DWORD> thread_list;

        // TH32CS_SNAPTHREAD signals that we want to gather all the threads currently registered in the snapshot
        // We don't care about th32ProcessID because we determine whether the thread belongs to our process ourselves
        const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

        if (snapshot == INVALID_HANDLE_VALUE) {
            std::cout << "[*] Failed to take snapshot of threads.\n";
            return thread_list;
        }

        THREADENTRY32 thread_entry;
        thread_entry.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(snapshot, &thread_entry)) {
            do {
                if (thread_entry.th32OwnerProcessID == pid_) {
                    thread_list.push_back(thread_entry.th32ThreadID);
                }
            } while (Thread32Next(snapshot, &thread_entry));
        }

        CloseHandle(snapshot);
        return thread_list;
    }

    static CONTEXT get_thread_context(const DWORD thread_id) {
        CONTEXT context = {};
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

        const auto h_thread = open_thread(thread_id);
        if (h_thread == nullptr) {
            std::cout << "[*] Could not get a handle to the thread.\n";
            return context; // Returns empty context
        }

        if (GetThreadContext(h_thread, &context)) {
            CloseHandle(h_thread);
            return context;
        }

        std::cout << "[*] Failed to get thread context.\n";
        CloseHandle(h_thread);
        return context;
    }

    bool attach(const DWORD pid) {
        h_process_ = open_process(pid);

        if (DebugActiveProcess(pid)) {
            debugger_active_ = true;
            pid_ = pid;
            run();
            return true;
        }

        std::cout << "[*] Unable to attach to the process.\n";
        return false;
    }

    void run() const {
        while (debugger_active_ == true) {
            get_debug_event();
        }
    }

    static void get_debug_event() {
        DEBUG_EVENT debug_event = {};

        if (WaitForDebugEvent(&debug_event, INFINITE)) {
            ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                DBG_CONTINUE
            );
        }
    }

    bool detach() {
        if (DebugActiveProcessStop(pid_)) {
            std::cout << "[*] Finished debugging. Exiting...\n";
            return true;
        }

        std::cout << "There was an error\n";
        return false;
    }

    ~Debugger() {
        if (debugger_active_) {
            detach();
        }

        if (h_process_ != nullptr) {
            CloseHandle(h_process_);
        }
    }

private:
    HANDLE h_process_;
    DWORD pid_;
    bool debugger_active_;
};

int main() {
    std::cout << "[*] Enter PID to attach to: ";
    DWORD pid;
    std::cin >> pid;

    if (Debugger debugger; !debugger.attach(pid)) {
        std::cout << "[*] Failed to attach to process." << std::endl;
    }

    return 0;
}
