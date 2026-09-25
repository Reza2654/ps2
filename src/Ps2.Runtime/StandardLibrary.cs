using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text.Json;
using Ps2.Core;

namespace Ps2.Runtime;

public static class StandardLibrary
{
    private static readonly SocketsHttpHandler SafeHttpHandler = new()
    {
        AllowAutoRedirect = false,
        ConnectTimeout = TimeSpan.FromSeconds(10)
    };

    private static readonly HttpClient SafeHttpClient = new(SafeHttpHandler)
    {
        Timeout = TimeSpan.FromSeconds(15)
    };

    private static HttpResponseMessage SendHttpRequestWithValidatedRedirects(
        CapabilityManifest manifest,
        Func<string, HttpRequestMessage> requestFactory,
        string initialUrl,
        int maxRedirects = 5)
    {
        string currentUrl = initialUrl;
        for (int i = 0; i <= maxRedirects; i++)
        {
            manifest.EnsureNetHttpAllowed(currentUrl);
            using var request = requestFactory(currentUrl);
            var response = SafeHttpClient.Send(request);

            int statusCode = (int)response.StatusCode;
            if (statusCode is 301 or 302 or 303 or 307 or 308)
            {
                var location = response.Headers.Location;
                if (location == null) return response;

                Uri nextUri = location.IsAbsoluteUri ? location : new Uri(new Uri(currentUrl), location);
                currentUrl = nextUri.ToString();
                response.Dispose();
                continue;
            }

            return response;
        }

        throw new InvalidOperationException("Too many HTTP redirects (exceeded limit).");
    }

    public static void Register(
        EnvironmentScope scope,
        CapabilityManifest manifest,
        string scriptDirectory,
        IReadOnlyList<string> scriptArgs,
        Func<Ps2Value, IReadOnlyList<Ps2Value>, Ps2Value> invokeFunction)
    {
        // 1. Output functions
        scope.Define("println", Ps2Value.CreateNativeFunction("println", args =>
        {
            var output = string.Join(" ", args.Select(a => EvaluatorSecretScrubber.Scrub(a.AsString())));
            Console.WriteLine(output);
            return Ps2Value.Null;
        }), isMutable: false);

        scope.Define("print", Ps2Value.CreateNativeFunction("print", args =>
        {
            var output = string.Join(" ", args.Select(a => EvaluatorSecretScrubber.Scrub(a.AsString())));
            Console.Write(output);
            return Ps2Value.Null;
        }), isMutable: false);

        // 2. Option & Result constructors
        scope.Define("Some", Ps2Value.CreateNativeFunction("Some", args =>
        {
            return Ps2Value.Some(args.Count > 0 ? args[0] : Ps2Value.Null);
        }), isMutable: false);

        scope.Define("None", Ps2Value.CreateNativeFunction("None", _ => Ps2Value.None()), isMutable: false);

        scope.Define("Ok", Ps2Value.CreateNativeFunction("Ok", args =>
        {
            return Ps2Value.Ok(args.Count > 0 ? args[0] : Ps2Value.Null);
        }), isMutable: false);

        scope.Define("Err", Ps2Value.CreateNativeFunction("Err", args =>
        {
            return Ps2Value.Err(args.Count > 0 ? args[0] : Ps2Value.Null);
        }), isMutable: false);

        scope.Define("unwrap", Ps2Value.CreateNativeFunction("unwrap", args =>
        {
            if (args.Count == 0) throw new ArgumentException("unwrap expects 1 argument");
            var item = args[0];
            if (item.Type == Ps2ValueType.Option)
            {
                var opt = item.AsOption();
                if (!opt.HasValue) throw new InvalidOperationException("Called unwrap() on a None Option.");
                return opt.Value ?? Ps2Value.Null;
            }
            if (item.Type == Ps2ValueType.Result)
            {
                var res = item.AsResult();
                if (!res.IsOk) throw new InvalidOperationException($"Called unwrap() on an Err Result: {res.Value}");
                return res.Value;
            }
            return item;
        }), isMutable: false);

        scope.Define("unwrap_or", Ps2Value.CreateNativeFunction("unwrap_or", args =>
        {
            if (args.Count < 2) throw new ArgumentException("unwrap_or expects 2 arguments: (item, default)");
            var item = args[0];
            var def = args[1];
            if (item.Type == Ps2ValueType.Option)
            {
                var opt = item.AsOption();
                return opt.HasValue ? (opt.Value ?? def) : def;
            }
            if (item.Type == Ps2ValueType.Result)
            {
                var res = item.AsResult();
                return res.IsOk ? res.Value : def;
            }
            return item;
        }), isMutable: false);

        scope.Define("is_some", Ps2Value.CreateNativeFunction("is_some", args =>
            Ps2Value.From(args.Count > 0 && args[0].Type == Ps2ValueType.Option && args[0].AsOption().HasValue)), isMutable: false);

        scope.Define("is_none", Ps2Value.CreateNativeFunction("is_none", args =>
            Ps2Value.From(args.Count > 0 && args[0].Type == Ps2ValueType.Option && !args[0].AsOption().HasValue)), isMutable: false);

        scope.Define("is_ok", Ps2Value.CreateNativeFunction("is_ok", args =>
            Ps2Value.From(args.Count > 0 && args[0].Type == Ps2ValueType.Result && args[0].AsResult().IsOk)), isMutable: false);

        scope.Define("is_err", Ps2Value.CreateNativeFunction("is_err", args =>
            Ps2Value.From(args.Count > 0 && args[0].Type == Ps2ValueType.Result && !args[0].AsResult().IsOk)), isMutable: false);

        // 3. Functional and Pipeline utilities
        scope.Define("len", Ps2Value.CreateNativeFunction("len", args =>
        {
            if (args.Count == 0) return Ps2Value.From(0);
            var target = args[0];
            return target.Type switch
            {
                Ps2ValueType.String => Ps2Value.From(target.AsString().Length),
                Ps2ValueType.List => Ps2Value.From(target.AsList().Count),
                Ps2ValueType.Map => Ps2Value.From(target.AsMap().Count),
                _ => Ps2Value.From(0)
            };
        }), isMutable: false);

        scope.Define("map", Ps2Value.CreateNativeFunction("map", args =>
        {
            if (args.Count < 2) throw new ArgumentException("map expects 2 arguments: (collection, fn)");
            var list = args[0].AsList();
            var fn = args[1];
            var results = new List<Ps2Value>(list.Count);
            foreach (var item in list)
            {
                results.Add(invokeFunction(fn, new[] { item }));
            }
            return Ps2Value.From(results);
        }), isMutable: false);

        scope.Define("filter", Ps2Value.CreateNativeFunction("filter", args =>
        {
            if (args.Count < 2) throw new ArgumentException("filter expects 2 arguments: (collection, fn)");
            var list = args[0].AsList();
            var fn = args[1];
            var results = new List<Ps2Value>();
            foreach (var item in list)
            {
                var cond = invokeFunction(fn, new[] { item });
                if (cond.IsTruthy)
                {
                    results.Add(item);
                }
            }
            return Ps2Value.From(results);
        }), isMutable: false);

        scope.Define("reduce", Ps2Value.CreateNativeFunction("reduce", args =>
        {
            if (args.Count < 3) throw new ArgumentException("reduce expects 3 arguments: (collection, fn, initial)");
            var list = args[0].AsList();
            var fn = args[1];
            var acc = args[2];
            foreach (var item in list)
            {
                acc = invokeFunction(fn, new[] { acc, item });
            }
            return acc;
        }), isMutable: false);

        scope.Define("take", Ps2Value.CreateNativeFunction("take", args =>
        {
            if (args.Count < 2) throw new ArgumentException("take expects 2 arguments: (collection, count)");
            var list = args[0].AsList();
            int count = (int)args[1].AsInt();
            return Ps2Value.From(list.Take(count).ToList());
        }), isMutable: false);

        scope.Define("sort", Ps2Value.CreateNativeFunction("sort", args =>
        {
            if (args.Count == 0) return Ps2Value.From(new List<Ps2Value>());
            var list = new List<Ps2Value>(args[0].AsList());
            list.Sort((a, b) =>
            {
                if (a.Type == Ps2ValueType.Int && b.Type == Ps2ValueType.Int)
                    return a.AsInt().CompareTo(b.AsInt());
                if (a.Type == Ps2ValueType.Float || b.Type == Ps2ValueType.Float)
                    return a.AsFloat().CompareTo(b.AsFloat());
                return string.Compare(a.AsString(), b.AsString(), StringComparison.Ordinal);
            });
            return Ps2Value.From(list);
        }), isMutable: false);

        // 4. fs Module
        var fsMap = new Dictionary<string, Ps2Value>
        {
            ["read_file"] = Ps2Value.CreateNativeFunction("fs.read_file", args =>
            {
                if (args.Count == 0) throw new ArgumentException("fs.read_file expects a file path");
                var path = args[0].AsString();
                var resolvedPath = manifest.EnsureFsReadAllowed(path, scriptDirectory);
                return Ps2Value.From(File.ReadAllText(resolvedPath));
            }),
            ["write_file"] = Ps2Value.CreateNativeFunction("fs.write_file", args =>
            {
                if (args.Count < 2) throw new ArgumentException("fs.write_file expects (path, content)");
                var path = args[0].AsString();
                var content = args[1].AsString();
                var resolvedPath = manifest.EnsureFsWriteAllowed(path, scriptDirectory);
                var dir = Path.GetDirectoryName(resolvedPath);
                if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                File.WriteAllText(resolvedPath, content);
                return Ps2Value.True;
            }),
            ["exists"] = Ps2Value.CreateNativeFunction("fs.exists", args =>
            {
                if (args.Count == 0) return Ps2Value.False;
                var path = args[0].AsString();
                var resolvedPath = manifest.EnsureFsReadAllowed(path, scriptDirectory);
                return Ps2Value.From(File.Exists(resolvedPath) || Directory.Exists(resolvedPath));
            }),
            ["list_dir"] = Ps2Value.CreateNativeFunction("fs.list_dir", args =>
            {
                var path = args.Count > 0 ? args[0].AsString() : ".";
                var resolvedPath = manifest.EnsureFsReadAllowed(path, scriptDirectory);
                var entries = Directory.GetFileSystemEntries(resolvedPath).Select(Path.GetFileName).Select(e => Ps2Value.From(e!)).ToList();
                return Ps2Value.From(entries);
            }),
            ["create_dir"] = Ps2Value.CreateNativeFunction("fs.create_dir", args =>
            {
                if (args.Count == 0) return Ps2Value.False;
                var path = args[0].AsString();
                var resolvedPath = manifest.EnsureFsWriteAllowed(path, scriptDirectory);
                if (!Directory.Exists(resolvedPath))
                {
                    Directory.CreateDirectory(resolvedPath);
                }
                return Ps2Value.True;
            }),
            ["delete_file"] = Ps2Value.CreateNativeFunction("fs.delete_file", args =>
            {
                if (args.Count == 0) return Ps2Value.False;
                var path = args[0].AsString();
                var resolvedPath = manifest.EnsureFsWriteAllowed(path, scriptDirectory);
                if (File.Exists(resolvedPath))
                {
                    File.Delete(resolvedPath);
                    return Ps2Value.True;
                }
                return Ps2Value.False;
            })
        };
        scope.Define("fs", Ps2Value.From(fsMap), isMutable: false);

        // 5. net Module
        var netMap = new Dictionary<string, Ps2Value>
        {
            ["http_get"] = Ps2Value.CreateNativeFunction("net.http_get", args =>
            {
                if (args.Count == 0) throw new ArgumentException("net.http_get expects a URL");
                var url = args[0].AsString();
                using var response = SendHttpRequestWithValidatedRedirects(manifest, u => new HttpRequestMessage(HttpMethod.Get, u), url);
                var resp = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                return Ps2Value.From(resp);
            }),
            ["http_post"] = Ps2Value.CreateNativeFunction("net.http_post", args =>
            {
                if (args.Count < 2) throw new ArgumentException("net.http_post expects (url, body)");
                var url = args[0].AsString();
                var body = args[1].AsString();
                using var response = SendHttpRequestWithValidatedRedirects(manifest, u =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Post, u);
                    req.Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json");
                    return req;
                }, url);
                var result = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                return Ps2Value.From(result);
            })
        };
        scope.Define("net", Ps2Value.From(netMap), isMutable: false);

        // 6. json Module (AOT-safe)
        var jsonMap = new Dictionary<string, Ps2Value>
        {
            ["parse"] = Ps2Value.CreateNativeFunction("json.parse", args =>
            {
                if (args.Count == 0) return Ps2Value.Null;
                return Ps2JsonEngine.Parse(args[0].AsString());
            }),
            ["stringify"] = Ps2Value.CreateNativeFunction("json.stringify", args =>
            {
                if (args.Count == 0) return Ps2Value.From("null");
                return Ps2Value.From(Ps2JsonEngine.Stringify(args[0], indented: true));
            }),
            ["encode"] = Ps2Value.CreateNativeFunction("json.encode", args =>
            {
                if (args.Count == 0) return Ps2Value.From("null");
                return Ps2Value.From(Ps2JsonEngine.Stringify(args[0], indented: false));
            })
        };
        scope.Define("json", Ps2Value.From(jsonMap), isMutable: false);

        // 7. str Module
        var strMap = new Dictionary<string, Ps2Value>
        {
            ["split"] = Ps2Value.CreateNativeFunction("str.split", args =>
            {
                if (args.Count < 2) throw new ArgumentException("str.split expects (string, separator)");
                var s = args[0].AsString();
                var sep = args[1].AsString();
                var parts = s.Split(new[] { sep }, StringSplitOptions.None).Select(Ps2Value.From).ToList();
                return Ps2Value.From(parts);
            }),
            ["trim"] = Ps2Value.CreateNativeFunction("str.trim", args =>
            {
                return Ps2Value.From(args.Count > 0 ? args[0].AsString().Trim() : string.Empty);
            }),
            ["to_upper"] = Ps2Value.CreateNativeFunction("str.to_upper", args =>
            {
                return Ps2Value.From(args.Count > 0 ? args[0].AsString().ToUpperInvariant() : string.Empty);
            }),
            ["to_lower"] = Ps2Value.CreateNativeFunction("str.to_lower", args =>
            {
                return Ps2Value.From(args.Count > 0 ? args[0].AsString().ToLowerInvariant() : string.Empty);
            }),
            ["contains"] = Ps2Value.CreateNativeFunction("str.contains", args =>
            {
                if (args.Count < 2) return Ps2Value.False;
                return Ps2Value.From(args[0].AsString().Contains(args[1].AsString()));
            }),
            ["replace"] = Ps2Value.CreateNativeFunction("str.replace", args =>
            {
                if (args.Count < 3) throw new ArgumentException("str.replace expects (source, old, new)");
                return Ps2Value.From(args[0].AsString().Replace(args[1].AsString(), args[2].AsString()));
            }),
            ["starts_with"] = Ps2Value.CreateNativeFunction("str.starts_with", args =>
            {
                if (args.Count < 2) return Ps2Value.False;
                return Ps2Value.From(args[0].AsString().StartsWith(args[1].AsString()));
            }),
            ["ends_with"] = Ps2Value.CreateNativeFunction("str.ends_with", args =>
            {
                if (args.Count < 2) return Ps2Value.False;
                return Ps2Value.From(args[0].AsString().EndsWith(args[1].AsString()));
            })
        };
        scope.Define("str", Ps2Value.From(strMap), isMutable: false);

        // 8. sys Module
        var sysMap = new Dictionary<string, Ps2Value>
        {
            ["env"] = Ps2Value.CreateNativeFunction("sys.env", args =>
            {
                if (args.Count == 0) return Ps2Value.Null;
                var varName = args[0].AsString();
                manifest.EnsureEnvAllowed(varName);
                var val = Environment.GetEnvironmentVariable(varName);
                return val != null ? Ps2Value.Some(Ps2Value.From(val)) : Ps2Value.None();
            }),
            ["secret"] = Ps2Value.CreateNativeFunction("sys.secret", args =>
            {
                if (args.Count == 0) throw new ArgumentException("sys.secret expects environment variable name");
                var varName = args[0].AsString();
                manifest.EnsureEnvAllowed(varName);
                var val = Environment.GetEnvironmentVariable(varName);
                if (val == null) return Ps2Value.None();
                EvaluatorSecretScrubber.RegisterSecret(val);
                return Ps2Value.Some(Ps2Value.Secret(val));
            }),
            ["args"] = Ps2Value.CreateNativeFunction("sys.args", _ =>
            {
                return Ps2Value.From(scriptArgs.Select(Ps2Value.From).ToList());
            }),
            ["os"] = Ps2Value.CreateNativeFunction("sys.os", _ =>
            {
                return Ps2Value.From(Environment.OSVersion.ToString());
            }),
            ["time_ms"] = Ps2Value.CreateNativeFunction("sys.time_ms", _ =>
            {
                return Ps2Value.From(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            }),
            ["exec"] = Ps2Value.CreateNativeFunction("sys.exec", args =>
            {
                if (args.Count == 0) throw new ArgumentException("sys.exec expects command binary");
                var cmd = args[0].AsString();
                manifest.EnsureProcExecAllowed(cmd);

                var psi = new ProcessStartInfo(cmd)
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                if (args.Count > 1)
                {
                    foreach (var argVal in args[1].AsList())
                    {
                        psi.ArgumentList.Add(argVal.AsString());
                    }
                }

                using var proc = Process.Start(psi);
                if (proc == null) throw new InvalidOperationException($"Failed to start process '{cmd}'.");

                var stdout = proc.StandardOutput.ReadToEnd();
                var stderr = proc.StandardError.ReadToEnd();
                proc.WaitForExit();

                return Ps2Value.From(new Dictionary<string, Ps2Value>
                {
                    ["exit_code"] = Ps2Value.From(proc.ExitCode),
                    ["stdout"] = Ps2Value.From(stdout),
                    ["stderr"] = Ps2Value.From(stderr)
                });
            })
        };
        scope.Define("sys", Ps2Value.From(sysMap), isMutable: false);

        // Secret Module
        var secretMap = new Dictionary<string, Ps2Value>
        {
            ["mask"] = Ps2Value.CreateNativeFunction("secret.mask", args =>
            {
                if (args.Count == 0) return Ps2Value.Secret(string.Empty);
                var raw = args[0].AsString();
                EvaluatorSecretScrubber.RegisterSecret(raw);
                return Ps2Value.Secret(raw);
            }),
            ["reveal"] = Ps2Value.CreateNativeFunction("secret.reveal", args =>
            {
                if (args.Count == 0) return Ps2Value.From(string.Empty);
                if (args[0].Type == Ps2ValueType.Secret)
                {
                    return Ps2Value.From(args[0].AsSecret().Unmask());
                }
                return args[0];
            })
        };
        scope.Define("secret", Ps2Value.From(secretMap), isMutable: false);

        // 9. path Module
        var pathMap = new Dictionary<string, Ps2Value>
        {
            ["join"] = Ps2Value.CreateNativeFunction("path.join", args =>
            {
                var parts = args.Select(a => a.AsString()).ToArray();
                return Ps2Value.From(Path.Combine(parts).Replace('\\', '/'));
            }),
            ["basename"] = Ps2Value.CreateNativeFunction("path.basename", args =>
            {
                return Ps2Value.From(args.Count > 0 ? Path.GetFileName(args[0].AsString()) : string.Empty);
            }),
            ["dirname"] = Ps2Value.CreateNativeFunction("path.dirname", args =>
            {
                var dir = args.Count > 0 ? Path.GetDirectoryName(args[0].AsString()) : string.Empty;
                return Ps2Value.From((dir ?? string.Empty).Replace('\\', '/'));
            }),
            ["extname"] = Ps2Value.CreateNativeFunction("path.extname", args =>
            {
                return Ps2Value.From(args.Count > 0 ? Path.GetExtension(args[0].AsString()) : string.Empty);
            }),
            ["is_absolute"] = Ps2Value.CreateNativeFunction("path.is_absolute", args =>
            {
                return Ps2Value.From(args.Count > 0 && Path.IsPathRooted(args[0].AsString()));
            })
        };
        scope.Define("path", Ps2Value.From(pathMap), isMutable: false);

        // 10. time Module
        var timeMap = new Dictionary<string, Ps2Value>
        {
            ["now"] = Ps2Value.CreateNativeFunction("time.now", _ =>
            {
                return Ps2Value.From(DateTime.UtcNow.ToString("o"));
            }),
            ["epoch_ms"] = Ps2Value.CreateNativeFunction("time.epoch_ms", _ =>
            {
                return Ps2Value.From(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            }),
            ["sleep"] = Ps2Value.CreateNativeFunction("time.sleep", args =>
            {
                int ms = args.Count > 0 ? (int)args[0].AsInt() : 0;
                if (ms > 0) System.Threading.Thread.Sleep(ms);
                return Ps2Value.Null;
            }),
            ["benchmark"] = Ps2Value.CreateNativeFunction("time.benchmark", args =>
            {
                if (args.Count == 0) throw new ArgumentException("time.benchmark expects a function");
                var fn = args[0];
                var sw = Stopwatch.StartNew();
                var result = invokeFunction(fn, Array.Empty<Ps2Value>());
                sw.Stop();
                return Ps2Value.From(new Dictionary<string, Ps2Value>
                {
                    ["elapsed_ms"] = Ps2Value.From(sw.Elapsed.TotalMilliseconds),
                    ["result"] = result
                });
            })
        };
        scope.Define("time", Ps2Value.From(timeMap), isMutable: false);

        // 11. env Module
        var envMap = new Dictionary<string, Ps2Value>
        {
            ["get"] = Ps2Value.CreateNativeFunction("env.get", args =>
            {
                if (args.Count == 0) return Ps2Value.None();
                var name = args[0].AsString();
                manifest.EnsureEnvAllowed(name);
                var val = Environment.GetEnvironmentVariable(name);
                return val != null ? Ps2Value.Some(Ps2Value.From(val)) : Ps2Value.None();
            }),
            ["has"] = Ps2Value.CreateNativeFunction("env.has", args =>
            {
                if (args.Count == 0) return Ps2Value.False;
                var name = args[0].AsString();
                manifest.EnsureEnvAllowed(name);
                return Ps2Value.From(Environment.GetEnvironmentVariable(name) != null);
            }),
            ["set"] = Ps2Value.CreateNativeFunction("env.set", args =>
            {
                if (args.Count < 2) throw new ArgumentException("env.set expects (name, value)");
                var name = args[0].AsString();
                var val = args[1].AsString();
                manifest.EnsureEnvAllowed(name);
                Environment.SetEnvironmentVariable(name, val);
                return Ps2Value.True;
            })
        };
        scope.Define("env", Ps2Value.From(envMap), isMutable: false);

        // 12. table Module
        var tableMap = new Dictionary<string, Ps2Value>
        {
            ["print"] = Ps2Value.CreateNativeFunction("table.print", args =>
            {
                if (args.Count > 0)
                {
                    TableFormatter.Print(args[0]);
                }
                return Ps2Value.Null;
            })
        };
        scope.Define("table", Ps2Value.From(tableMap), isMutable: false);

        // 13. math Module
        var mathMap = new Dictionary<string, Ps2Value>
        {
            ["abs"] = Ps2Value.CreateNativeFunction("math.abs", args =>
            {
                if (args.Count == 0) return Ps2Value.From(0);
                return args[0].Type == Ps2ValueType.Int ? Ps2Value.From(Math.Abs(args[0].AsInt())) : Ps2Value.From(Math.Abs(args[0].AsFloat()));
            }),
            ["sqrt"] = Ps2Value.CreateNativeFunction("math.sqrt", args =>
            {
                return Ps2Value.From(Math.Sqrt(args.Count > 0 ? args[0].AsFloat() : 0));
            }),
            ["pow"] = Ps2Value.CreateNativeFunction("math.pow", args =>
            {
                if (args.Count < 2) return Ps2Value.From(0);
                return Ps2Value.From(Math.Pow(args[0].AsFloat(), args[1].AsFloat()));
            }),
            ["min"] = Ps2Value.CreateNativeFunction("math.min", args =>
            {
                if (args.Count < 2) return Ps2Value.From(0);
                return Ps2Value.From(Math.Min(args[0].AsFloat(), args[1].AsFloat()));
            }),
            ["max"] = Ps2Value.CreateNativeFunction("math.max", args =>
            {
                if (args.Count < 2) return Ps2Value.From(0);
                return Ps2Value.From(Math.Max(args[0].AsFloat(), args[1].AsFloat()));
            }),
            ["round"] = Ps2Value.CreateNativeFunction("math.round", args =>
            {
                return Ps2Value.From(Math.Round(args.Count > 0 ? args[0].AsFloat() : 0));
            })
        };
        scope.Define("math", Ps2Value.From(mathMap), isMutable: false);
    }
}
