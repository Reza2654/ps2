using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Ps2.Bundler;

public sealed record BundleMetadata(
    string EntryScript,
    string CreatedAt,
    string Sha256,
    List<string> Files
);

public static class BundlePackage
{
    private static readonly byte[] MagicBytes = Encoding.ASCII.GetBytes("PS2B");
    private const byte CurrentFormatVersion = 0x01;

    public static void CreateBundle(
        string entryScriptPath,
        string outputBundlePath,
        IEnumerable<string>? additionalFiles = null)
    {
        if (!File.Exists(entryScriptPath))
        {
            throw new FileNotFoundException($"Entry script not found at '{entryScriptPath}'.");
        }

        var entryFileName = Path.GetFileName(entryScriptPath);
        var filesToInclude = new List<string> { entryScriptPath };
        if (additionalFiles != null)
        {
            filesToInclude.AddRange(additionalFiles);
        }

        using var memoryZipStream = new MemoryStream();
        using (var archive = new ZipArchive(memoryZipStream, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var filePath in filesToInclude)
            {
                if (File.Exists(filePath))
                {
                    var entry = archive.CreateEntry(Path.GetFileName(filePath), CompressionLevel.Optimal);
                    using var entryStream = entry.Open();
                    using var fs = File.OpenRead(filePath);
                    fs.CopyTo(entryStream);
                }
            }
        }

        var zipPayload = memoryZipStream.ToArray();
        var sha256 = SHA256.HashData(zipPayload);
        var sha256Hex = Convert.ToHexString(sha256).ToLowerInvariant();

        var metadata = new BundleMetadata(
            EntryScript: entryFileName,
            CreatedAt: DateTime.UtcNow.ToString("o"),
            Sha256: sha256Hex,
            Files: filesToInclude.Select(Path.GetFileName).Where(f => f != null).ToList()!
        );

        var metaJson = JsonSerializer.Serialize(metadata);
        var metaBytes = Encoding.UTF8.GetBytes(metaJson);

        using var outputFs = File.Create(outputBundlePath);
        using var writer = new BinaryWriter(outputFs);

        // Header
        writer.Write(MagicBytes);               // 4 bytes: PS2B
        writer.Write(CurrentFormatVersion);     // 1 byte: Version 1
        writer.Write(sha256);                   // 32 bytes: SHA-256 of payload

        // Metadata
        writer.Write(metaBytes.Length);         // 4 bytes: Meta JSON length
        writer.Write(metaBytes);                // Meta JSON bytes

        // Compressed payload
        writer.Write(zipPayload.Length);        // 4 bytes: Payload length
        writer.Write(zipPayload);               // Payload bytes
    }

    public static (string EntryScriptContent, BundleMetadata Metadata, Dictionary<string, byte[]> Files) ReadBundle(string bundlePath)
    {
        if (!File.Exists(bundlePath))
        {
            throw new FileNotFoundException($"Bundle file not found at '{bundlePath}'.");
        }

        using var fs = File.OpenRead(bundlePath);
        using var reader = new BinaryReader(fs);

        var magic = reader.ReadBytes(4);
        if (!Encoding.ASCII.GetString(magic).Equals("PS2B", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Invalid PS2 bundle format: Magic header mismatch.");
        }

        var version = reader.ReadByte();
        if (version != CurrentFormatVersion)
        {
            throw new InvalidDataException($"Unsupported bundle version: {version}.");
        }

        var expectedSha256 = reader.ReadBytes(32);
        var metaLen = reader.ReadInt32();
        var metaBytes = reader.ReadBytes(metaLen);
        var metadata = JsonSerializer.Deserialize<BundleMetadata>(Encoding.UTF8.GetString(metaBytes))
            ?? throw new InvalidDataException("Failed to read bundle metadata.");

        var payloadLen = reader.ReadInt32();
        var payloadBytes = reader.ReadBytes(payloadLen);

        var actualSha256 = SHA256.HashData(payloadBytes);
        if (!expectedSha256.SequenceEqual(actualSha256))
        {
            throw new CryptographicUnexpectedOperationException("Bundle integrity verification failed! Payload hash does not match header checksum.");
        }

        var extractedFiles = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        using var zipStream = new MemoryStream(payloadBytes);
        using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

        foreach (var entry in archive.Entries)
        {
            using var entryStream = entry.Open();
            using var ms = new MemoryStream();
            entryStream.CopyTo(ms);
            extractedFiles[entry.Name] = ms.ToArray();
        }

        if (!extractedFiles.TryGetValue(metadata.EntryScript, out var entryBytes))
        {
            throw new FileNotFoundException($"Entry script '{metadata.EntryScript}' missing from bundle.");
        }

        var entryContent = Encoding.UTF8.GetString(entryBytes);
        return (entryContent, metadata, extractedFiles);
    }
}
