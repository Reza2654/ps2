using System;
using System.Collections.Generic;
using Ps2.Core;

namespace Ps2.Parser;

public sealed class ManifestParser
{
    public static (CapabilityManifest Manifest, string? Signature, int EndTokenIndex) Parse(IReadOnlyList<Token> tokens)
    {
        var manifest = new CapabilityManifest();
        string? signature = null;
        int i = 0;

        // Check for signature or manifest at the top
        while (i < tokens.Count && tokens[i].Type != TokenType.Eof)
        {
            if (tokens[i].Type == TokenType.SignatureDirective)
            {
                signature = tokens[i].LiteralValue as string;
                i++;
                continue;
            }

            if (tokens[i].Type == TokenType.ManifestStart)
            {
                i++; // skip #manifest

                if (i < tokens.Count && tokens[i].Type == TokenType.Requires)
                {
                    i++; // skip requires
                }

                if (i < tokens.Count && tokens[i].Type == TokenType.OpenBrace)
                {
                    i++; // skip '{'

                    while (i < tokens.Count && tokens[i].Type != TokenType.CloseBrace && tokens[i].Type != TokenType.ManifestEnd && tokens[i].Type != TokenType.Eof)
                    {
                        // Capability name like 'fs.read' or 'net.http' or 'env'
                        string capName = tokens[i].Text;
                        i++;

                        // if dot notation (e.g. fs . read)
                        if (i < tokens.Count && tokens[i].Type == TokenType.Dot)
                        {
                            i++; // skip .
                            if (i < tokens.Count)
                            {
                                capName += "." + tokens[i].Text;
                                i++;
                            }
                        }

                        if (i < tokens.Count && tokens[i].Type == TokenType.Colon)
                        {
                            i++; // skip :
                        }

                        // Parse list of strings or single string
                        if (i < tokens.Count && tokens[i].Type == TokenType.OpenBracket)
                        {
                            i++; // skip '['
                            while (i < tokens.Count && tokens[i].Type != TokenType.CloseBracket && tokens[i].Type != TokenType.Eof)
                            {
                                if (tokens[i].Type == TokenType.StringLiteral)
                                {
                                    AddCapabilityItem(manifest, capName, (string)tokens[i].LiteralValue!);
                                    i++;
                                }
                                else
                                {
                                    i++;
                                }

                                if (i < tokens.Count && tokens[i].Type == TokenType.Comma)
                                {
                                    i++;
                                }
                            }

                            if (i < tokens.Count && tokens[i].Type == TokenType.CloseBracket)
                            {
                                i++; // skip ']'
                            }
                        }
                        else if (i < tokens.Count && tokens[i].Type == TokenType.StringLiteral)
                        {
                            AddCapabilityItem(manifest, capName, (string)tokens[i].LiteralValue!);
                            i++;
                        }

                        if (i < tokens.Count && tokens[i].Type == TokenType.Comma)
                        {
                            i++;
                        }
                    }

                    if (i < tokens.Count && tokens[i].Type == TokenType.CloseBrace)
                    {
                        i++; // skip '}'
                    }
                }

                if (i < tokens.Count && tokens[i].Type == TokenType.ManifestEnd)
                {
                    i++; // skip #endmanifest
                }

                continue;
            }

            break; // Finished header directives
        }

        return (manifest, signature, i);
    }

    private static void AddCapabilityItem(CapabilityManifest manifest, string capabilityName, string item)
    {
        switch (capabilityName.ToLowerInvariant())
        {
            case "fs.read":
                manifest.AddFsRead(item);
                break;
            case "fs.write":
                manifest.AddFsWrite(item);
                break;
            case "net.http":
            case "net":
                manifest.AddNetHttp(item);
                break;
            case "env":
                manifest.AddEnv(item);
                break;
            case "proc.exec":
            case "process":
                manifest.AddProcExec(item);
                break;
        }
    }
}
