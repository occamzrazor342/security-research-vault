# When Live .NET Reflection Is Blocked, Exfiltrate the DLL and Decompile It Offline

Live `System.Reflection` against a running .NET/CLR process from inside an
RCE shell is a normal way to answer "what does this exact method actually
check" — until it isn't. A CLR-version mismatch between the attacking
tooling's assumptions and the live process can make abstract-interface
methods, dynamically-generated concrete types (common in ORM/POCO-mapping
layers like LiteDB), or JIT-specific internals unreachable via reflection
even with full code-execution access to the process's own account. When
that wall shows up, stop trying to work around it live — exfiltrate the
DLL and decompile it offline instead.

## Recognizing the wall

Signs this is a real CLR-introspection block, not a permissions problem:
`MethodInfo.IsAbstract == true` on a method that should have a concrete
implementation reachable, `GetInterfaces()`/`GetMethods()` sweeps across
every DLL in the install directory finding zero types implementing an
interface that's clearly used somewhere, or reflection calls that simply
throw with no clear permission-denied signature. If several structurally
different reflection approaches all hit the same kind of wall, that's the
signal to switch techniques rather than try a fourth reflection variant.

## Exfiltrating the target assembly

Any RCE-only channel that can read a file and push bytes out (even a
narrow beacon/upload primitive, not a full file-transfer tool) is enough:

```powershell
$bytes = [System.IO.File]::ReadAllBytes("C:\Path\To\Target.dll")
# base64-encode and exfil in chunks over whatever channel exists, or
# use System.Net.WebClient.UploadFile() against a raw HTTP receiver on
# the attacker box if the target has outbound HTTP
```

If exfil goes through a `multipart/form-data` upload wrapper, strip the
boundary headers on the receiving end to recover an exact byte-for-byte
copy — verify by comparing the received file's size against
`(Get-Item ...).Length` on the target and confirming it identifies as a
valid PE32+/.NET assembly (`file <output>`).

## Decompiling

`ilspycmd` ([ILSpy — GitHub](https://github.com/icsharpcode/ILSpy)), the
CLI front-end for the ILSpy decompiler, needs no target-side CLR
compatibility at all since it runs entirely on the attacker's own .NET
install:

```
ilspycmd -l c <assembly.dll>              # list all types
ilspycmd -t <Full.Namespace.TypeName> <assembly.dll>   # decompile one type to real C#
```

This gets you the actual source of the method/class in question — not a
reconstruction from behavior, not another guess at a request schema, the
real logic including every field name, validation order, and conditional
branch. Once you have it, stop guessing entirely and read the code for the
exact answer (a missing required field, an undocumented flag, an
alternate success path).

## Seen on

- [[DanglingTree#Privesc|DanglingTree]] — four sessions of guessing at
  SmarterMail's `show-password` gate (each fixing a different settings
  flag, each still blocked) never found the real cause because it wasn't a
  settings flag at all. Exfiltrating `MailService.dll` (26MB) and
  decompiling `DomainSettingsController`/`UserSettingsHelper` with
  `ilspycmd` found it in one pass: a request-body `token` field the
  client-side JS sends transparently that every prior raw-HTTP attempt had
  simply never populated.
