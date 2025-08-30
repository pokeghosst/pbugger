#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>

class Debugger {
public:
    Debugger() {
        h_process = NULL;
        pid = 0;
        debugger_active = false;
    }

    bool load(const std::wstring &path_to_exe) {
        // Determines how to create the process
        DWORD creation_flags = DEBUG_PROCESS;

        STARTUPINFO startup_info = {0};
        PROCESS_INFORMATION process_info = {0};

        startup_info.dwFlags = STARTF_USESHOWWINDOW;
        startup_info.wShowWindow = SW_HIDE;

        // Set the struct size
        startup_info.cb = sizeof(startup_info);

        // CreateProcess expects a non-const string for the application name
        // We'll pass NULL for application name and use command line instead
        std::wstring cmd_line = path_to_exe;

        if (CreateProcess(
            NULL, // Application name (NULL to use command line)
            reinterpret_cast<LPSTR>(&cmd_line[0]), // Command line (modifiable)
            NULL, // Process security attributes
            NULL, // Thread security attributes
            FALSE, // Inherit handles
            creation_flags, // Creation flags
            NULL, // Environment
            NULL, // Current directory
            &startup_info, // Startup info
            &process_info // Process information
        )) {
            std::cout << "[*] We have successfully launched the process!" << std::endl;
            std::cout << "[*] PID: " << process_info.dwProcessId << std::endl;

            // Obtain a valid handle to the newly created process
            // and store it for future access
            h_process = open_process(process_info.dwProcessId);
            pid = process_info.dwProcessId;
            debugger_active = true;

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

    HANDLE open_process(DWORD pid) {
        HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        return h_process;
    }

    HANDLE open_thread(DWORD thread_id) {
        HANDLE h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);

        if (h_thread != NULL) {
            return h_thread;
        } else {
            std::cout << "[*] Unable to open the thread.\n";
            return NULL;
        }
    }

    std::vector<DWORD> enumerate_threads() {
        std::vector<DWORD> thread_list;

        // TH32CS_SNAPTHREAD signals that we want to gather all the threads currently registered in the snapshot
        // We don't care about th32ProcessID because we determine whether the thread belongs to our process ourselves
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

        if (snapshot == INVALID_HANDLE_VALUE) {
            std::cout << "[*] Failed to take snapshot of threads.\n";
            return thread_list;
        }

        THREADENTRY32 thread_entry;
        thread_entry.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(snapshot, &thread_entry)) {
            do {
                if (thread_entry.th32OwnerProcessID == pid) {
                    thread_list.push_back(thread_entry.th32ThreadID);
                }
            } while (Thread32Next(snapshot, &thread_entry));
        }

        CloseHandle(snapshot);
        return thread_list;
    }

    CONTEXT get_thread_context(DWORD thread_id) {
        CONTEXT context;
        memset(&context, 0, sizeof(CONTEXT));
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

        HANDLE h_thread = open_thread(thread_id);
        if (h_thread == NULL) {
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

    bool attach(DWORD pid) {
        h_process = open_process(pid);

        if (DebugActiveProcess(pid)) {
            debugger_active = true;
            this->pid = pid;
            run();
            return true;
        } else {
            std::cout << "[*] Unable to attach to the process.\n";
            return false;
        }
    }

    void run() {
        while (debugger_active == true) {
            get_debug_event();
        }
    }

    void get_debug_event() {
        DEBUG_EVENT debug_event = {0};
        DWORD continue_status = DBG_CONTINUE;

        if (WaitForDebugEvent(&debug_event, INFINITE)) {
            ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                continue_status
            );
        }
    }

    bool detach() {
        if (DebugActiveProcessStop(pid)) {
            std::cout << "[*] Finished debugging. Exiting...\n";
            return true;
        } else {
            std::cout << "There was an error\n";
            return false;
        }
    }

    ~Debugger() {
        if (debugger_active) {
            detach();
        }
        if (h_process != NULL) {
            CloseHandle(h_process);
        }
    }

private:
    HANDLE h_process;
    DWORD pid;
    bool debugger_active;
};

int main() {
    Debugger debugger;

    std::cout << "[*] Enter PID to attach to: ";
    DWORD pid;
    std::cin >> pid;

    if (!debugger.attach(pid)) {
        std::cout << "[*] Failed to attach to process." << std::endl;
    }

    return 0;
}
