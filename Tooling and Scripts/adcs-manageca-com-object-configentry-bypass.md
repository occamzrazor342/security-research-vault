# AD CS: When `ManageCA` Is Real But `certutil`/Registry Writes Are Denied, Call `ICertAdmin2::SetConfigEntry` Directly via COM

An account holding native `ManageCA` (+ `ManageCertificates`) rights on an
Enterprise CA is the textbook ESC7 condition — see
[Certified Pre-Owned (SpecterOps)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
and [ESC7 (SpecterOps docs)](https://docs.specterops.io/ghostpack-docs/Certify.wik-mdx/esc7-vulnerable-certificate-authority-access-control).
The standard weaponization path (submit a request to a
`Domain-Admins`-only, `EnrolleeSuppliesSubject=True` template, then use
`ManageCertificates` to retroactively `-issue-request` the denied one) can
fail even with confirmed `ManageCA`, if the request was denied with
disposition 31 ("Denied by Policy Module") — that specific denial reason is
non-resubmittable regardless of rights held. When that's the case, the
fallback is ESC6: flip `EDITF_ATTRIBUTESUBJECTALTNAME2` CA-wide so *any*
enrollable template honors an attacker-supplied SAN/UPN, even one whose own
`EnrolleeSuppliesSubject` is `False`.

## The trap: two client-side gates that look like server-side denials

Both of the "obvious" ways to flip that flag can fail even for an account
that genuinely holds `ManageCA`:

```
Set-ItemProperty -Path "HKLM:\...\Policy" -Name EditFlags -Value <new>
# Requested registry access is not allowed.

certutil -config "<CA>" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
# Administrator permissions are needed to use the selected options.
# CertUtil: The requested operation requires elevation.
```

Neither failure is proof the CA itself would refuse the write:

- `Set-ItemProperty` fails because that registry key's ACL requires
  local-Administrators-group membership on the CA host — an **OS-level**
  restriction, unrelated to the AD-level `ManageCA` right.
- `certutil -setreg` fails because `certutil.exe` performs its own
  **client-side elevation check** before it will even attempt the RPC call
  that would otherwise invoke `ICertAdmin2::SetConfigEntry` — it never
  reaches the CA to find out whether the CA would have honored it.

Both are gates in the *tooling*, not gates the CA's own `ManageCA`
authorization actually imposes at the RPC layer.

## The bypass: call the same RPC method through the COM object instead

`ICertAdmin2::SetConfigEntry` — [documented under MS-CSRA on Microsoft
Learn](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/a31ea036-eaec-4b35-a50d-c4fe11843a4b) —
is exactly the RPC method both `certutil -setreg` and (indirectly) the
registry write are trying to reach. The `CertificateAuthority.Admin` COM
object exposes this method directly, with none of `certutil.exe`'s
client-side gatekeeping in front of it:

```powershell
$CA = New-Object -ComObject CertificateAuthority.Admin
$Config = "<host>\<CA name>"
$current = $CA.GetConfigEntry($Config, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags")
$new = $current -bor 0x00040000   # EDITF_ATTRIBUTESUBJECTALTNAME2
$CA.SetConfigEntry($Config, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags", $new)
```

If `ManageCA` genuinely authorizes the write at the CA/server level (which
is what the AD ACL claims to grant), this call succeeds outright with no
exception — confirming the two earlier "denials" were tooling artifacts, not
real authorization gaps.

## The flag doesn't take effect until the CA service restarts

The CA's policy module caches `EditFlags` at service startup. If the account
also has no general Service Control Manager access (a `Get-Service`/`net
start`/`net stop`/`schtasks.exe`-blocking hardening posture is common
alongside this exact scenario), don't assume the service can't be
restarted — a **targeted** `sc.exe <verb> <service-name>` call can succeed
where a general SCM handle is denied, if the account's BUILTIN group
membership (e.g. `Certificate Service DCOM Access`) grants rights on that
one specific service rather than general manager access:

```
net stop certsvc     # Access is denied — uses NetServiceControl, needs general SCM access
sc.exe stop CertSvc  # succeeds — OpenService+ControlService against one named service
sc.exe start CertSvc
```

## Restoring state precisely afterward

Restoring a registry `REG_MULTI_SZ` value to **empty** (as opposed to
absent) via the COM object can be its own trap: `SetConfigEntry(..., @())`
throws `ERROR_INVALID_PARAMETER`, and `SetConfigEntry(..., $null)` deletes
the value entirely rather than leaving it present-but-empty. If exact
byte-for-byte restoration matters (a shared lab box), finish the revert with
a direct registry write once real Administrator access is available:

```powershell
New-ItemProperty -Path $regPath -Name DisableExtensionList -Value ([string[]]@()) -PropertyType MultiString -Force
```

## Seen on

- [[fries#Privesc|Fries]] and [[fries#Root|Fries]] — `certutil`/registry
  writes were independently diagnosed as blocked by client-side/OS-level
  gates across an earlier session (the "why" was genuinely derived on this
  box); the specific COM-object fix itself was cross-checked against
  external material rather than independently rediscovered — see the
  writeup's Root section for the full attribution note. Also disabled the
  CVE-2022-26923 SID security extension
  (`DisableExtensionList = 1.3.6.1.4.1.311.25.2`) via the same mechanism,
  which is required for a forged-SAN certificate to still authenticate on a
  DC patched per
  [KB5014754](https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16).
