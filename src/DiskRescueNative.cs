using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
public sealed class BootCandidate {
    public long Offset {get;set;}
    public string Type {get;set;}
}
public static class DiskRescueNative {
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr sa,uint creation,uint flags,IntPtr template);
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern bool ReadFile(SafeFileHandle handle,byte[] buffer,uint count,out uint read,IntPtr overlapped);
    [DllImport("kernel32.dll",SetLastError=true)]
    static extern bool DeviceIoControl(SafeFileHandle handle,uint control,IntPtr input,uint inSize,out long output,uint outSize,out uint returned,IntPtr overlapped);
    [DllImport("kernel32.dll",EntryPoint="DeviceIoControl",SetLastError=true)]
    static extern bool StorageQuery(SafeFileHandle handle,uint control,byte[] input,uint inSize,[Out] byte[] output,uint outSize,out uint returned,IntPtr overlapped);
    public static bool StopRequested() {
        if(Console.IsInputRedirected) return false;
        try {if(Console.KeyAvailable) {ConsoleKey k=Console.ReadKey(true).Key;return k==ConsoleKey.Q || k==ConsoleKey.Escape;}}
        catch(InvalidOperationException) {}
        return false;
    }
    public static string Copy(string source,string target,long length,int sector) {return Copy(source,target,length,sector,null);}
    public static string Copy(string source,string target,long length,int sector,string expectedSerial) {
        if(!System.Text.RegularExpressions.Regex.IsMatch(source,@"^\\\\\.\\PhysicalDrive[0-9]+$")) throw new ArgumentException("Physical drive path required");
        if(length<=0 || (sector!=512 && sector!=4096) || length%sector!=0) throw new ArgumentException("Invalid geometry");
        using(SafeFileHandle input=CreateFile(source,0x80000000,3,IntPtr.Zero,3,0x08000000,IntPtr.Zero)) {
            if(input.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            long actual;uint returned;
            // IOCTL_DISK_GET_LENGTH_INFO is a read-only query on the already-open handle.
            if(!DeviceIoControl(input,0x0007405c,IntPtr.Zero,0,out actual,8,out returned,IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(),"Cannot verify source handle length");
            if(returned!=8 || actual!=length) throw new IOException("Source handle size changed; refusing to copy");
            if(!String.IsNullOrWhiteSpace(expectedSerial)) {
                byte[] descriptor=new byte[4096];uint received;
                if(!StorageQuery(input,0x002d1400,new byte[12],12,descriptor,(uint)descriptor.Length,out received,IntPtr.Zero) || received<28)
                    throw new IOException("Cannot verify serial number on opened source handle");
                uint at=BitConverter.ToUInt32(descriptor,24);
                if(at==0 || at>=received) throw new IOException("Opened source handle does not expose a serial number");
                int end=(int)at;while(end<received && descriptor[end]!=0) end++;
                string serial=System.Text.Encoding.ASCII.GetString(descriptor,(int)at,end-(int)at).Trim();
                if(!String.Equals(serial,expectedSerial.Trim(),StringComparison.OrdinalIgnoreCase))
                    throw new IOException("Source handle serial does not match selected disk. Nothing copied.");
            }
            using(FileStream output=new FileStream(target,FileMode.CreateNew,FileAccess.Write,FileShare.Read))
            using(SHA256 hash=SHA256.Create()) {
                byte[] buffer=new byte[4*1024*1024];long done=0;
                DateTime started=DateTime.UtcNow,last=DateTime.MinValue;
                while(done<length) {
                    if(StopRequested()) throw new OperationCanceledException("Stopped. Incomplete .partial image retained.");
                    uint wanted=(uint)Math.Min(buffer.Length,length-done),read;
                    if(!ReadFile(input,buffer,wanted,out read,IntPtr.Zero))
                        throw new IOException("Read failed at byte "+done+". Partial image retained. "+new Win32Exception(Marshal.GetLastWin32Error()).Message);
                    if(read!=wanted) throw new IOException("Short read at byte "+done+". Partial image retained.");
                    output.Write(buffer,0,(int)read);hash.TransformBlock(buffer,0,(int)read,buffer,0);done+=read;
                    if((DateTime.UtcNow-last).TotalSeconds>=1) {
                        double seconds=Math.Max(0.001,(DateTime.UtcNow-started).TotalSeconds), speed=done/seconds;
                        Console.Write("\rImage {0:F1}% | {1:F2}/{2:F2} GiB | {3:F1} MiB/s | ETA {4:F0} min   ",done*100.0/length,done/1073741824.0,length/1073741824.0,speed/1048576.0,(length-done)/speed/60);
                        last=DateTime.UtcNow;
                    }
                }
                output.Flush(true);hash.TransformFinalBlock(new byte[0],0,0);Console.WriteLine();
                return BitConverter.ToString(hash.Hash).Replace("-","").ToLowerInvariant();
            }
        }
    }
    static bool Match(byte[] b,int at,string value) {
        for(int j=0;j<value.Length;j++) if(b[at+j]!=(byte)value[j]) return false;
        return true;
    }
    public static BootCandidate[] ScanBootSectors(string image,int sector) {
        if(sector!=512 && sector!=4096) throw new ArgumentException("Invalid sector size");
        List<BootCandidate> hits=new List<BootCandidate>();
        using(FileStream input=new FileStream(image,FileMode.Open,FileAccess.Read,FileShare.Read)) {
            byte[] b=new byte[8*1024*1024];long pos=0;DateTime last=DateTime.MinValue;
            while(pos<input.Length) {
                if(StopRequested()) throw new OperationCanceledException("Scan stopped; previous reports retained.");
                int count=0,n;
                while(count<b.Length && (n=input.Read(b,count,b.Length-count))>0) count+=n;
                for(int at=0;at+512<=count;at+=sector) {
                    if(b[at+510]!=0x55 || b[at+511]!=0xaa || (b[at]!=0xeb && b[at]!=0xe9)) continue;
                    string type=null;
                    if(Match(b,at+3,"NTFS    ")) type="NTFS";
                    else if(Match(b,at+3,"EXFAT   ")) type="exFAT";
                    else if(Match(b,at+54,"FAT12   ") || Match(b,at+54,"FAT16   ") || Match(b,at+82,"FAT32   ")) type="FAT";
                    if(type!=null) {
                        hits.Add(new BootCandidate {Offset=(pos+at)/sector,Type=type});
                        if(hits.Count>10000) throw new IOException("Too many boot candidates; scanning stopped at 10000 to bound resource use");
                    }
                }
                pos+=count;
                if((DateTime.UtcNow-last).TotalSeconds>=1) {Console.Write("\rBoot scan {0:F1}% | candidates {1}   ",pos*100.0/input.Length,hits.Count);last=DateTime.UtcNow;}
            }
        }
        Console.WriteLine();return hits.ToArray();
    }
}
