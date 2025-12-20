# LDIFToBloodHound

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![.NET](https://img.shields.io/badge/.NET-8.0-purple.svg)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows-blue.svg)]()

A Windows tool that converts LDIF files (from `ldapsearch`) to BloodHound CE compatible JSON files **with full ACL parsing**.

## Why This Tool?

When performing Active Directory assessments through restricted network paths (SOCKS proxies, port forwarding, etc.), tools like SharpHound or bloodhound-python often fail due to DNS resolution issues or connectivity problems.

**ldapsearch works reliably through proxies**, but its output (LDIF format) isn't compatible with BloodHound. This tool bridges that gap by:

1. Parsing LDIF files from `ldapsearch`
2. Decoding binary `nTSecurityDescriptor` attributes using Windows APIs
3. Extracting ACEs (Access Control Entries) for attack path analysis
4. Outputting BloodHound CE v6 compatible JSON files

## Features

| Feature | Description |
|---------|-------------|
| **Full ACL Parsing** | Extracts Owns, GenericAll, WriteDacl, DCSync, AddMember, etc. |
| **Binary SD Decoding** | Uses Windows `RawSecurityDescriptor` for accurate parsing |
| **BloodHound CE v6** | Outputs modern BloodHound format |
| **All Object Types** | Users, Computers, Groups, Domains, OUs, GPOs, Containers |
| **ADCS Support** | Enterprise CAs, Root CAs, AIA CAs, NTAuth Stores, Certificate Templates |
| **Group Memberships** | Resolves member DNs to SIDs |
| **UAC Flag Parsing** | Delegation, Kerberoastable, AS-REP roastable detection |

## Prerequisites

- Windows OS (required for ACL parsing)
- [.NET 8 Runtime](https://dotnet.microsoft.com/download/dotnet/8.0)
- LDIF file with `nTSecurityDescriptor` attribute

## Quick Start

### Step 1: Collect LDIF with ACLs

From your Linux attack box (through proxychains/SOCKS):

```bash
proxychains ldapsearch -x -H ldap://DC_IP -D "user@domain.com" -w 'password' \
  -b "DC=domain,DC=com" \
  -E pr=10000/noprompt \
  -E '!1.2.840.113556.1.4.801=::MAMCAQc=' \
  "(objectClass=*)" "*" nTSecurityDescriptor > ad_dump.ldif
```

**Important flags:**
- `-E pr=10000/noprompt` - Paged results (handles large domains)
- `-E '!1.2.840.113556.1.4.801=::MAMCAQc='` - SD_FLAGS control to retrieve security descriptors
- `nTSecurityDescriptor` - Explicitly request the ACL attribute

### Step 2: Transfer and Convert

Transfer the LDIF file to a Windows machine and run:

```powershell
LDIFToBloodHound.exe ad_dump.ldif ./bloodhound_output
```

### Step 3: Import into BloodHound

Import the generated JSON files into BloodHound CE.

## Usage

```
LDIFToBloodHound.exe <ldif_file> [output_dir]

Arguments:
  ldif_file    Path to the LDIF file from ldapsearch
  output_dir   Output directory for JSON files (default: ./bloodhound_output)

Example:
  LDIFToBloodHound.exe ad_dump.ldif C:\temp\bloodhound
```

## Output Files

```
bloodhound_output/
├── 20231201120000_users.json
├── 20231201120000_computers.json
├── 20231201120000_groups.json
├── 20231201120000_domains.json
├── 20231201120000_ous.json
├── 20231201120000_gpos.json
├── 20231201120000_containers.json
├── 20231201120000_certtemplates.json
├── 20231201120000_enterprisecas.json
├── 20231201120000_rootcas.json
├── 20231201120000_aiacas.json
└── 20231201120000_ntauthstores.json
```

## ACL Rights Extracted

| Right | Description |
|-------|-------------|
| **Owns** | Object ownership |
| **GenericAll** | Full control |
| **GenericWrite** | Write all properties |
| **WriteDacl** | Modify permissions |
| **WriteOwner** | Change ownership |
| **AllExtendedRights** | All extended rights (includes ForceChangePassword) |
| **ForceChangePassword** | Reset password without knowing current |
| **GetChanges** | DCSync (partial) |
| **GetChangesAll** | DCSync (full) |
| **AddMember** | Add members to group |
| **AddSelf** | Add self to group |
| **AddKeyCredentialLink** | Shadow Credentials attack |
| **WriteSPN** | Targeted Kerberoasting |
| **Enroll** | Certificate enrollment rights |
| **AutoEnroll** | Automatic certificate enrollment |
| **ManageCA** | CA management rights |
| **ManageCertificates** | Certificate management rights |

## Building from Source

```powershell
git clone https://github.com/kypvas/LDIFToBloodHound.git
cd LDIFToBloodHound
dotnet build -c Release
```

Output: `bin/Release/net8.0-windows/win-x64/LDIFToBloodHound.exe`

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                      LDIFToBloodHound                           │
├─────────────────────────────────────────────────────────────────┤
│  1. Parse LDIF file                                             │
│     └─ Handle base64 encoded attributes                         │
│     └─ Handle multi-valued attributes                           │
│     └─ Handle continuation lines                                │
├─────────────────────────────────────────────────────────────────┤
│  2. Build DN → SID mappings                                     │
│     └─ Resolve group members                                    │
│     └─ Determine object types                                   │
├─────────────────────────────────────────────────────────────────┤
│  3. Parse nTSecurityDescriptor (Windows API)                    │
│     └─ RawSecurityDescriptor class                              │
│     └─ Extract Owner SID                                        │
│     └─ Process DACL entries                                     │
│        └─ CommonAce: GenericAll, WriteDacl, WriteOwner          │
│        └─ ObjectAce: Extended rights, Property writes           │
├─────────────────────────────────────────────────────────────────┤
│  4. Output BloodHound v6 JSON                                   │
│     └─ Users, Computers, Groups, Domains, OUs, GPOs, Containers │
│     └─ ADCS: CertTemplates, EnterpriseCAs, RootCAs, AIACAs      │
│     └─ Full ACE arrays for attack path analysis                 │
└─────────────────────────────────────────────────────────────────┘
```

## ADCS Support

The tool fully supports Active Directory Certificate Services (ADCS) objects for ESC attack path analysis:

| Object Type | Description | Key Properties |
|-------------|-------------|----------------|
| **Certificate Templates** | PKI certificate templates | EKUs, enrollment flags, name flags, schema version |
| **Enterprise CAs** | Issuing certificate authorities | Enabled templates, hosting computer, CA security |
| **Root CAs** | Root certificate authorities | Certificate chain, thumbprints |
| **AIA CAs** | Authority Information Access CAs | Cross-certificate pairs, cert chain |
| **NTAuth Stores** | NTAuth certificate store | Trusted CA thumbprints |

### ADCS Properties Parsed

- **Certificate Templates**: `enrolleesuppliessubject`, `nosecurityextension`, `authenticationenabled`, `requiresmanagerapproval`, EKUs
- **Enterprise CAs**: `HostingComputer`, `CARegistryData`, `EnabledCertTemplates`, certificate thumbprints
- **All ADCS Objects**: Full ACL parsing including Enroll, AutoEnroll, ManageCA rights

## Use Cases

1. **Restricted Network Access** - When you only have SOCKS proxy access and other tools fail
2. **Stealth** - ldapsearch generates less suspicious traffic than specialized AD tools
3. **Offline Analysis** - Collect LDIF once, convert and analyze later
4. **Backup Collection** - Secondary collection method when primary tools fail

## Limitations

- Requires Windows for ACL parsing (uses .NET `RawSecurityDescriptor`)
- LDIF must include `nTSecurityDescriptor` attribute (use the SD_FLAGS control)
- No session collection (requires SMB access to computers)
- No local group collection (requires remote registry/SAM access)

## Troubleshooting

### "No ACLs in output"

Make sure your ldapsearch command includes:
- `-E '!1.2.840.113556.1.4.801=::MAMCAQc='` - SD_FLAGS control
- `nTSecurityDescriptor` - Explicit attribute request

### "Failed to parse ACL for..."

Some objects may have malformed security descriptors. These are logged and skipped.

### "No objects parsed"

Check your LDIF file:
- Remove any "ProxyChains" header lines
- Ensure entries are separated by blank lines
- Verify DN attributes are present

## Legal Disclaimer

This tool is provided for **authorized security testing and research only**. Unauthorized access to computer systems is illegal. Always obtain proper authorization before using this tool.

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).

## Credits

Inspired by the need to bridge the gap between reliable LDAP collection through restricted networks and BloodHound's powerful attack path analysis.
