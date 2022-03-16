namespace ExtractPortablePDBs
{
    using System;
    using System.IO;
    using System.Reflection.PortableExecutable;
    using Microsoft.DiaSymReader.Tools;

    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Usage: ExtractPortablePDBs DirectoryPathThatHasDLLs");
                Console.WriteLine("Example: ExtractPortablePDBs C:\\MyDir");
                return;
            }

            var dlls = Directory.GetFiles(args[0], "*.dll", SearchOption.AllDirectories);
            var exes = Directory.GetFiles(args[0], "*.exe", SearchOption.AllDirectories);

            foreach (var file in dlls)
            {
                ExtractPortablePDB(file, Path.ChangeExtension(file, "pdb"));
            }

            foreach (var file in exes)
            {
                ExtractPortablePDB(file, Path.ChangeExtension(file, "pdb"));
            }
        }

        public static void ExtractPortablePDB(string incomingPEFilePath, string outgoingPortablePDBPath)
        {
            using var fs = new FileStream(incomingPEFilePath, FileMode.Open, FileAccess.Read);
            using var pe = new PEReader(fs);
            if (!pe.IsEntireImageAvailable)
            {
                Console.WriteLine($"ERROR: {incomingPEFilePath} Not a Managed PE File.");
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

                        var portablePdbStream = new UnmanagedMemoryStream(pdbReader.MetadataPointer, pdbReader.MetadataLength, pdbReader.MetadataLength, FileAccess.Read);

                        PdbConverter.Default.ConvertPortableToWindows(pe, portablePdbStream, output, PortablePdbConversionOptions.Default);

                        Console.WriteLine($"SUCCESS: Wrote {pdbReader.MetadataLength} bytes to {outgoingPortablePDBPath}");
                        return;
                    }
                }
            }

            Console.WriteLine("ERROR: Did not contain a Portable PDB file.");
        }
    }
}