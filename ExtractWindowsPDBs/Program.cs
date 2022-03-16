namespace ExtractWindowsPDBs
{
    using System;
    using System.IO;
    using System.Reflection.PortableExecutable;
    using Microsoft.DiaSymReader.Tools;

    internal static class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Usage: ExtractWindowsPDBs DirectoryPathThatHasDLLs");
                Console.WriteLine("Example: ExtractWindowsPDBs C:\\MyDir");
                return;
            }

            var dlls = Directory.GetFiles(args[0], "*.dll", SearchOption.AllDirectories);
            var exes = Directory.GetFiles(args[0], "*.exe", SearchOption.AllDirectories);

            foreach (var file in dlls)
            {
                ExtractWindowsPDB(file, Path.ChangeExtension(file, "pdb"));
            }

            foreach (var file in exes)
            {
                ExtractWindowsPDB(file, Path.ChangeExtension(file, "pdb"));
            }
        }

        public static void ExtractWindowsPDB(string incomingPEFilePath, string outgoingWindowsPDBPath)
        {
            using var fs = new FileStream(incomingPEFilePath, FileMode.Open, FileAccess.Read);
            using var pe = new PEReader(fs);
            if (!pe.IsEntireImageAvailable)
            {
                Console.WriteLine($"ERROR: {incomingPEFilePath} Not a Valid File.");
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
                        using var output = new FileStream(outgoingWindowsPDBPath, FileMode.Create, FileAccess.Write);

                        var portablePdbStream = new UnmanagedMemoryStream(pdbReader.MetadataPointer, pdbReader.MetadataLength, pdbReader.MetadataLength, FileAccess.Read);

                        PdbConverter.Default.ConvertPortableToWindows(pe, portablePdbStream, output, PortablePdbConversionOptions.Default);

                        Console.WriteLine($"SUCCESS: Wrote {pdbReader.MetadataLength} bytes to {outgoingWindowsPDBPath}");
                        return;
                    }
                }
            }

            Console.WriteLine("ERROR: Did not contain a Portable PDB file.");
        }
    }
}