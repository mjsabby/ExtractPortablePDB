namespace ExtractPortablePDB
{
    using System;
    using System.IO;
    using System.Reflection.PortableExecutable;

    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("Usage: ExtractPortablePDB PathToDll PathToPDb");
                Console.WriteLine("Example: ExtractPortablePDB C:\\Foo.dll C:\\Foo.pdb");
                return;
            }

            ExtractPortablePDB(args[0], args[1]);
        }

        public static void ExtractPortablePDB(string incomingPEFilePath, string outgoingPortablePDBPath)
        {
            using var fs = new FileStream(incomingPEFilePath, FileMode.Open, FileAccess.Read);
            using var pe = new PEReader(fs);
            if (!pe.IsEntireImageAvailable)
            {
                Console.WriteLine("ERROR: Not a PE File.");
                return;
            }

            var directoryEntries = pe.ReadDebugDirectory();
            foreach (var directoryEntry in directoryEntries)
            {
                if (directoryEntry.Type == DebugDirectoryEntryType.EmbeddedPortablePdb)
                {
                    unsafe
                    {
                        var pdbReader = pe.ReadEmbeddedPortablePdbDebugDirectoryData(directoryEntry).GetMetadataReader();
                        using var output = new FileStream(outgoingPortablePDBPath, FileMode.Create, FileAccess.Write);

                        var readStream = new UnmanagedMemoryStream(pdbReader.MetadataPointer, pdbReader.MetadataLength, pdbReader.MetadataLength, FileAccess.Read);
                        readStream.CopyTo(output);

                        Console.WriteLine($"SUCCESS: Wrote {pdbReader.MetadataLength} bytes to {outgoingPortablePDBPath}");
                        return;
                    }
                }
            }

            Console.WriteLine("ERROR: Did not contain a Portable PDB file.");
        }
    }
}