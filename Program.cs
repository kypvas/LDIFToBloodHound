using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace LDIFToBloodHound;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.WriteLine("Usage: LDIFToBloodHound.exe <ldif_file> [output_dir]");
            Console.WriteLine("Example: LDIFToBloodHound.exe ad_dump.ldif ./bloodhound_output");
            return;
        }

        var ldifFile = args[0];
        var outputDir = args.Length > 1 ? args[1] : "./bloodhound_output";

        Console.WriteLine($"[*] Parsing LDIF file: {ldifFile}");
        var parser = new LDIFParser(ldifFile);
        var objects = parser.Parse();
        Console.WriteLine($"[*] Parsed {objects.Count} LDAP entries");

        Console.WriteLine("[*] Converting to BloodHound format with ACLs...");
        var converter = new BloodHoundConverter(objects);
        var bhData = converter.Convert();

        Console.WriteLine($"[*] Writing JSON files to {outputDir}");
        WriteBloodHoundJson(bhData, outputDir);

        Console.WriteLine("[+] Done! Import the JSON files into BloodHound CE");
    }

    static void WriteBloodHoundJson(Dictionary<string, List<object>> data, string outputDir)
    {
        Directory.CreateDirectory(outputDir);
        var timestamp = DateTime.Now.ToString("yyyyMMddHHmmss");

        foreach (var (objType, objects) in data)
        {
            if (objects.Count == 0)
            {
                Console.WriteLine($"[-] No {objType} found");
                continue;
            }

            var output = new
            {
                data = objects,
                meta = new
                {
                    methods = 0,
                    type = objType,
                    count = objects.Count,
                    version = 6
                }
            };

            var filename = $"{timestamp}_{objType}.json";
            var filepath = Path.Combine(outputDir, filename);

            File.WriteAllText(filepath, JsonConvert.SerializeObject(output, new JsonSerializerSettings
            {
                NullValueHandling = NullValueHandling.Ignore
            }));

            Console.WriteLine($"[+] Written {objects.Count} {objType} to {filename}");
        }
    }
}

public class LDIFParser
{
    private readonly string _ldifFile;

    public LDIFParser(string ldifFile)
    {
        _ldifFile = ldifFile;
    }

    public List<LDAPObject> Parse()
    {
        var objects = new List<LDAPObject>();
        var seenDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var currentEntry = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        string? currentAttr = null;
        StringBuilder? currentValue = null;
        int duplicateCount = 0;

        foreach (var line in File.ReadLines(_ldifFile))
        {
            // Skip comments and ProxyChains header
            if (line.StartsWith("#") || line.StartsWith("ProxyChains"))
                continue;

            // Empty line = end of entry
            if (string.IsNullOrWhiteSpace(line))
            {
                if (currentEntry.Count > 0 && currentEntry.ContainsKey("dn"))
                {
                    var dn = currentEntry["dn"]?.ToString() ?? "";
                    if (!seenDns.Contains(dn))
                    {
                        seenDns.Add(dn);
                        objects.Add(new LDAPObject(currentEntry));
                    }
                    else
                    {
                        duplicateCount++;
                    }
                    currentEntry = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                }
                currentAttr = null;
                currentValue = null;
                continue;
            }

            // Continuation line
            if (line.StartsWith(" "))
            {
                currentValue?.Append(line.Substring(1));
                continue;
            }

            // Save previous attribute
            if (currentAttr != null && currentValue != null)
            {
                SaveAttribute(currentEntry, currentAttr, currentValue.ToString());
            }

            // Parse attribute: value
            var colonIdx = line.IndexOf(':');
            if (colonIdx > 0)
            {
                currentAttr = line.Substring(0, colonIdx).ToLowerInvariant();
                var valueStr = line.Substring(colonIdx + 1).TrimStart();

                // Base64 encoded value (::)
                if (valueStr.StartsWith(":"))
                {
                    valueStr = valueStr.Substring(1).Trim();
                    try
                    {
                        var decoded = Convert.FromBase64String(valueStr);
                        // Store as bytes for binary attributes
                        if (currentAttr == "objectsid" || currentAttr == "objectguid" ||
                            currentAttr == "ntsecuritydescriptor" || currentAttr == "sidhistory")
                        {
                            SaveAttribute(currentEntry, currentAttr, decoded);
                            currentAttr = null;
                            currentValue = null;
                            continue;
                        }
                        valueStr = Encoding.UTF8.GetString(decoded);
                    }
                    catch { }
                }

                currentValue = new StringBuilder(valueStr);
            }
        }

        // Don't forget last entry
        if (currentAttr != null && currentValue != null)
        {
            SaveAttribute(currentEntry, currentAttr, currentValue.ToString());
        }
        if (currentEntry.Count > 0 && currentEntry.ContainsKey("dn"))
        {
            var dn = currentEntry["dn"]?.ToString() ?? "";
            if (!seenDns.Contains(dn))
            {
                objects.Add(new LDAPObject(currentEntry));
            }
            else
            {
                duplicateCount++;
            }
        }

        if (duplicateCount > 0)
        {
            Console.WriteLine($"[*] Skipped {duplicateCount} duplicate entries");
        }

        return objects;
    }

    private void SaveAttribute(Dictionary<string, object> entry, string attr, object value)
    {
        if (entry.TryGetValue(attr, out var existing))
        {
            if (existing is List<object> list)
            {
                list.Add(value);
            }
            else
            {
                entry[attr] = new List<object> { existing, value };
            }
        }
        else
        {
            entry[attr] = value;
        }
    }
}

public class LDAPObject
{
    public Dictionary<string, object> Properties { get; }

    public LDAPObject(Dictionary<string, object> props)
    {
        Properties = props;
    }

    public string? GetString(string key)
    {
        if (Properties.TryGetValue(key, out var val))
        {
            if (val is string s) return s;
            if (val is List<object> list && list.Count > 0) return list[0]?.ToString();
            return val?.ToString();
        }
        return null;
    }

    public byte[]? GetBytes(string key)
    {
        if (Properties.TryGetValue(key, out var val))
        {
            if (val is byte[] b) return b;
            if (val is string s)
            {
                try { return Convert.FromBase64String(s); } catch { }
            }
        }
        return null;
    }

    public int? GetInt(string key)
    {
        var s = GetString(key);
        if (s != null && int.TryParse(s, out var i)) return i;
        return null;
    }

    public long? GetLong(string key)
    {
        var s = GetString(key);
        if (s != null && long.TryParse(s, out var l)) return l;
        return null;
    }

    public List<string> GetStringList(string key)
    {
        if (Properties.TryGetValue(key, out var val))
        {
            if (val is List<object> list)
                return list.Select(x => x?.ToString() ?? "").Where(x => !string.IsNullOrEmpty(x)).ToList();
            if (val is string s)
                return new List<string> { s };
        }
        return new List<string>();
    }

    public List<string> ObjectClasses => GetStringList("objectclass").Select(x => x.ToLowerInvariant()).ToList();
    public string? DN => GetString("dn");
    public string? SamAccountName => GetString("samaccountname");
    public string? Name => GetString("name") ?? GetString("cn");
    public string? DisplayName => GetString("displayname");
    public string? Description => GetString("description");
    public string? DnsHostName => GetString("dnshostname");
    public string? OperatingSystem => GetString("operatingsystem");
    public int? UserAccountControl => GetInt("useraccountcontrol");
    public int? PrimaryGroupId => GetInt("primarygroupid");
    public int? AdminCount => GetInt("admincount");
    public string? GpcFileSysPath => GetString("gpcfilesyspath");
    public string? GpLink => GetString("gplink");
    public int? GpOptions => GetInt("gpoptions");

    // ADCS Properties
    public int? MsPKIEnrollmentFlag => GetInt("mspki-enrollment-flag");
    public int? MsPKICertNameFlag => GetInt("mspki-certificate-name-flag");
    public int? MsPKIPrivateKeyFlag => GetInt("mspki-private-key-flag");
    public int? MsPKIRASignature => GetInt("mspki-ra-signature");
    public int? MsPKITemplateSchemaVersion => GetInt("mspki-template-schema-version");
    public int? MsPKIMinimalKeySize => GetInt("mspki-minimal-key-size");
    public string? MsPKICertTemplateOID => GetString("mspki-cert-template-oid");
    public List<string> PKIExtendedKeyUsage => GetStringList("pkiextendedkeyusage");
    public List<string> CertificateTemplates => GetStringList("certificatetemplates");
    public byte[]? CACertificate => GetBytes("cacertificate");
    public byte[]? PKIExpirationPeriod => GetBytes("pkiexpirationperiod");
    public byte[]? PKIOverlapPeriod => GetBytes("pkioverlapperiod");
    public List<byte[]> CACertificateList => GetBytesList("cacertificate");

    public List<byte[]> GetBytesList(string key)
    {
        var result = new List<byte[]>();
        if (Properties.TryGetValue(key, out var val))
        {
            if (val is byte[] b)
            {
                result.Add(b);
            }
            else if (val is List<object> list)
            {
                foreach (var item in list)
                {
                    if (item is byte[] bytes)
                        result.Add(bytes);
                    else if (item is string s)
                    {
                        try { result.Add(Convert.FromBase64String(s)); } catch { }
                    }
                }
            }
        }
        return result;
    }

    public bool IsUser => ObjectClasses.Contains("user") && !ObjectClasses.Contains("computer");
    public bool IsComputer => ObjectClasses.Contains("computer");
    public bool IsGroup => ObjectClasses.Contains("group");
    public bool IsDomain => ObjectClasses.Contains("domaindns") ||
                           (ObjectClasses.Contains("domain") && (DN?.ToUpper().StartsWith("DC=") ?? false));
    public bool IsOU => ObjectClasses.Contains("organizationalunit");
    public bool IsGPO => ObjectClasses.Contains("grouppolicycontainer");
    public bool IsContainer => ObjectClasses.Contains("container") && !IsGPO;

    // ADCS Object Types
    public bool IsCertTemplate => ObjectClasses.Contains("pkicertificatetemplate");
    public bool IsEnterpriseCA => ObjectClasses.Contains("pkienrollmentservice");
    public bool IsRootCA => ObjectClasses.Contains("certificationauthority") &&
                           (DN?.ToUpperInvariant().Contains("CN=CERTIFICATION AUTHORITIES") ?? false);
    public bool IsAIACA => ObjectClasses.Contains("certificationauthority") &&
                          (DN?.ToUpperInvariant().Contains("CN=AIA") ?? false);
    public bool IsNTAuthStore => (DN?.ToUpperInvariant().Contains("CN=NTAUTHCERTIFICATES") ?? false);

    public string? GetSidString()
    {
        var sidBytes = GetBytes("objectsid");
        if (sidBytes == null || sidBytes.Length < 8) return null;
        try
        {
            var sid = new SecurityIdentifier(sidBytes, 0);
            return sid.Value;
        }
        catch { return null; }
    }

    public Guid? GetGuid()
    {
        var guidBytes = GetBytes("objectguid");
        if (guidBytes == null || guidBytes.Length != 16) return null;
        try { return new Guid(guidBytes); }
        catch { return null; }
    }

    public string? GetPrimaryGroupSid(string? domainSid)
    {
        var pgid = PrimaryGroupId ?? 513;
        return domainSid != null ? $"{domainSid}-{pgid}" : null;
    }
}

public class BloodHoundConverter
{
    private readonly List<LDAPObject> _objects;
    private readonly Dictionary<string, (string Id, string Type)> _dnToId = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _sidToType = new(StringComparer.OrdinalIgnoreCase);
    private string? _domainSid;
    private string? _domainName;
    private string? _domainDn;

    // Well-known AD GUIDs for extended rights
    private static readonly Dictionary<Guid, string> ExtendedRightsMap = new()
    {
        { new Guid("00299570-246d-11d0-a768-00aa006e0529"), "ForceChangePassword" },
        { new Guid("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"), "GetChanges" },
        { new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"), "GetChangesAll" },
        { new Guid("89e95b76-444d-4c62-991a-0facbeda640c"), "GetChangesInFilteredSet" },
        { new Guid("00000000-0000-0000-0000-000000000000"), "AllExtendedRights" },
        // ADCS Extended Rights
        { new Guid("0e10c968-78fb-11d2-90d4-00c04f79dc55"), "Enroll" },
        { new Guid("a05b8cc2-17bc-4802-a710-e7c15ab866a2"), "AutoEnroll" },
        // CA Management Rights
        { new Guid("ee138b9f-f72d-4bfc-9e4f-f9459ef0c4a7"), "ManageCA" },
        { new Guid("0e10c96c-78fb-11d2-90d4-00c04f79dc55"), "ManageCertificates" }
    };

    // Property GUIDs
    private static readonly Dictionary<Guid, string> PropertyMap = new()
    {
        { new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2"), "Member" },
        { new Guid("f30e3bc1-9ff0-11d1-b603-0000f80367c1"), "GpcFileSysPath" },
        { new Guid("5f202010-79a5-11d0-9020-00c04fc2d4cf"), "AddKeyCredentialLink" }
    };

    public BloodHoundConverter(List<LDAPObject> objects)
    {
        _objects = objects;
        BuildMappings();
    }

    private void BuildMappings()
    {
        // First pass: find domain and get domain SID
        foreach (var obj in _objects)
        {
            if (obj.IsDomain)
            {
                var sid = obj.GetSidString();
                if (sid != null && _domainSid == null)
                {
                    _domainSid = sid; // Domain SID is the full SID for domain object
                    _domainName = GetDomainFromDn(obj.DN ?? "");
                    _domainDn = obj.DN?.ToUpperInvariant();
                }
            }
        }

        // Second pass: build all mappings
        foreach (var obj in _objects)
        {
            var dn = obj.DN;
            var sid = obj.GetSidString();
            var guid = obj.GetGuid()?.ToString().ToUpperInvariant();

            string type = "Base";
            if (obj.IsComputer) type = "Computer";
            else if (obj.IsUser) type = "User";
            else if (obj.IsGroup) type = "Group";
            else if (obj.IsDomain) type = "Domain";
            else if (obj.IsOU) type = "OU";
            else if (obj.IsGPO) type = "GPO";
            else if (obj.IsContainer) type = "Container";
            // ADCS Types
            else if (obj.IsCertTemplate) type = "CertTemplate";
            else if (obj.IsEnterpriseCA) type = "EnterpriseCA";
            else if (obj.IsRootCA) type = "RootCA";
            else if (obj.IsAIACA) type = "AIACA";
            else if (obj.IsNTAuthStore) type = "NTAuthStore";

            if (dn != null && sid != null)
            {
                _dnToId[dn] = (sid, type);
                _sidToType[sid] = type;
            }
            else if (dn != null && guid != null)
            {
                _dnToId[dn] = (guid, type);
            }
        }
    }

    private object? GetContainedBy(string? dn)
    {
        if (string.IsNullOrEmpty(dn)) return null;

        // Get parent DN by removing first component
        var commaIdx = dn.IndexOf(',');
        if (commaIdx < 0) return null;

        var parentDn = dn.Substring(commaIdx + 1);

        // Check if parent is domain
        if (parentDn.Equals(_domainDn, StringComparison.OrdinalIgnoreCase))
        {
            return new
            {
                ObjectIdentifier = _domainSid,
                ObjectType = "Domain"
            };
        }

        // Check if parent exists in our mappings
        if (_dnToId.TryGetValue(parentDn, out var parentInfo))
        {
            return new
            {
                ObjectIdentifier = parentInfo.Id,
                ObjectType = parentInfo.Type
            };
        }

        return null;
    }

    public Dictionary<string, List<object>> Convert()
    {
        var users = new List<object>();
        var groups = new List<object>();
        var computers = new List<object>();
        var domains = new List<object>();
        var ous = new List<object>();
        var gpos = new List<object>();
        var containers = new List<object>();
        // ADCS collections
        var certtemplates = new List<object>();
        var enterprisecas = new List<object>();
        var rootcas = new List<object>();
        var aiacas = new List<object>();
        var ntauthstores = new List<object>();

        var seenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var obj in _objects)
        {
            string? objectId = null;

            if (obj.IsDomain)
            {
                objectId = obj.GetSidString();
                if (objectId != null && seenIds.Add(objectId))
                    domains.Add(ConvertDomain(obj));
            }
            else if (obj.IsUser)
            {
                objectId = obj.GetSidString();
                if (objectId != null && seenIds.Add(objectId))
                    users.Add(ConvertUser(obj));
            }
            else if (obj.IsComputer)
            {
                objectId = obj.GetSidString();
                if (objectId != null && seenIds.Add(objectId))
                    computers.Add(ConvertComputer(obj));
            }
            else if (obj.IsGroup)
            {
                objectId = obj.GetSidString();
                if (objectId != null && seenIds.Add(objectId))
                    groups.Add(ConvertGroup(obj));
            }
            else if (obj.IsOU)
            {
                objectId = obj.GetGuid()?.ToString().ToUpperInvariant();
                if (objectId != null && seenIds.Add(objectId))
                    ous.Add(ConvertOU(obj));
            }
            else if (obj.IsGPO)
            {
                objectId = obj.GetGuid()?.ToString().ToUpperInvariant();
                if (objectId != null && seenIds.Add(objectId))
                    gpos.Add(ConvertGPO(obj));
            }
            else if (obj.IsContainer)
            {
                objectId = obj.GetGuid()?.ToString().ToUpperInvariant();
                if (objectId != null && seenIds.Add(objectId))
                    containers.Add(ConvertContainer(obj));
            }
            // ADCS Object Types
            else if (obj.IsCertTemplate)
            {
                objectId = obj.GetGuid()?.ToString().ToUpperInvariant();
                if (objectId != null && seenIds.Add(objectId))
                    certtemplates.Add(ConvertCertTemplate(obj));
            }
            else if (obj.IsEnterpriseCA)
            {
                objectId = obj.GetGuid()?.ToString().ToUpperInvariant();
                if (objectId != null && seenIds.Add(objectId))
                    enterprisecas.Add(ConvertEnterpriseCA(obj));
            }
            else if (obj.IsRootCA)
            {
                objectId = obj.GetGuid()?.ToString().ToUpperInvariant();
                if (objectId != null && seenIds.Add(objectId))
                    rootcas.Add(ConvertRootCA(obj));
            }
            else if (obj.IsAIACA)
            {
                objectId = obj.GetGuid()?.ToString().ToUpperInvariant();
                if (objectId != null && seenIds.Add(objectId))
                    aiacas.Add(ConvertAIACA(obj));
            }
            else if (obj.IsNTAuthStore)
            {
                objectId = obj.GetGuid()?.ToString().ToUpperInvariant();
                if (objectId != null && seenIds.Add(objectId))
                    ntauthstores.Add(ConvertNTAuthStore(obj));
            }
        }

        return new Dictionary<string, List<object>>
        {
            ["users"] = users,
            ["groups"] = groups,
            ["computers"] = computers,
            ["domains"] = domains,
            ["ous"] = ous,
            ["gpos"] = gpos,
            ["containers"] = containers,
            // ADCS
            ["certtemplates"] = certtemplates,
            ["enterprisecas"] = enterprisecas,
            ["rootcas"] = rootcas,
            ["aiacas"] = aiacas,
            ["ntauthstores"] = ntauthstores
        };
    }

    private object ConvertUser(LDAPObject obj)
    {
        var sid = obj.GetSidString();
        var domain = GetDomainFromDn(obj.DN ?? "");
        var uac = ParseUAC(obj.UserAccountControl ?? 0);
        var spns = obj.GetStringList("serviceprincipalname");

        return new
        {
            ObjectIdentifier = sid,
            PrimaryGroupSID = obj.GetPrimaryGroupSid(_domainSid),
            ContainedBy = GetContainedBy(obj.DN),
            Properties = new
            {
                name = $"{obj.SamAccountName}@{domain}".ToUpperInvariant(),
                domain = domain.ToUpperInvariant(),
                domainsid = _domainSid,
                distinguishedname = obj.DN,
                highvalue = false,
                unconstraineddelegation = uac.TrustedForDelegation,
                trustedtoauth = uac.TrustedToAuthForDelegation,
                passwordnotreqd = uac.PasswordNotRequired,
                enabled = uac.Enabled,
                lastlogon = FileTimeToUnix(obj.GetLong("lastlogon")),
                lastlogontimestamp = FileTimeToUnix(obj.GetLong("lastlogontimestamp")),
                pwdlastset = FileTimeToUnix(obj.GetLong("pwdlastset")),
                dontreqpreauth = uac.DontReqPreauth,
                pwdneverexpires = uac.PasswordNeverExpires,
                sensitive = uac.Sensitive,
                serviceprincipalnames = spns.ToArray(),
                hasspn = spns.Count > 0,
                displayname = obj.DisplayName,
                email = obj.GetString("mail"),
                description = obj.Description,
                admincount = (obj.AdminCount ?? 0) > 0,
                samaccountname = obj.SamAccountName,
                whencreated = ParseWhenCreated(obj.GetString("whencreated")),
                sidhistory = new string[0],
                isaclprotected = false
            },
            AllowedToDelegate = new object[0],
            Aces = ParseACL(obj),
            SPNTargets = new object[0],
            HasSIDHistory = new object[0],
            IsDeleted = false,
            IsACLProtected = false
        };
    }

    private object ConvertComputer(LDAPObject obj)
    {
        var sid = obj.GetSidString();
        var domain = GetDomainFromDn(obj.DN ?? "");
        var uac = ParseUAC(obj.UserAccountControl ?? 0);
        var name = obj.DnsHostName ?? $"{obj.SamAccountName?.TrimEnd('$')}.{domain}";

        return new
        {
            ObjectIdentifier = sid,
            PrimaryGroupSID = obj.GetPrimaryGroupSid(_domainSid),
            ContainedBy = GetContainedBy(obj.DN),
            DumpSMSAPassword = new object[0],
            Properties = new
            {
                name = name.ToUpperInvariant(),
                domain = domain.ToUpperInvariant(),
                domainsid = _domainSid,
                distinguishedname = obj.DN,
                highvalue = false,
                unconstraineddelegation = uac.TrustedForDelegation,
                trustedtoauth = uac.TrustedToAuthForDelegation,
                enabled = uac.Enabled,
                samaccountname = obj.SamAccountName,
                haslaps = obj.GetString("ms-mcs-admpwdexpirationtime") != null,
                lastlogon = FileTimeToUnix(obj.GetLong("lastlogon")),
                lastlogontimestamp = FileTimeToUnix(obj.GetLong("lastlogontimestamp")),
                pwdlastset = FileTimeToUnix(obj.GetLong("pwdlastset")),
                whencreated = ParseWhenCreated(obj.GetString("whencreated")),
                operatingsystem = obj.OperatingSystem,
                description = obj.Description,
                serviceprincipalnames = obj.GetStringList("serviceprincipalname").ToArray(),
                sidhistory = new string[0],
                isaclprotected = false
            },
            LocalGroups = new object[0],
            UserRights = new object[0],
            AllowedToDelegate = new object[0],
            AllowedToAct = new object[0],
            Sessions = new { Collected = false, FailureReason = (string?)null, Results = new object[0] },
            PrivilegedSessions = new { Collected = false, FailureReason = (string?)null, Results = new object[0] },
            RegistrySessions = new { Collected = false, FailureReason = (string?)null, Results = new object[0] },
            Aces = ParseACL(obj),
            HasSIDHistory = new object[0],
            IsDeleted = false,
            Status = (string?)null,
            IsACLProtected = false
        };
    }

    private object ConvertGroup(LDAPObject obj)
    {
        var sid = obj.GetSidString();
        var domain = GetDomainFromDn(obj.DN ?? "");

        var members = new List<object>();
        foreach (var memberDn in obj.GetStringList("member"))
        {
            if (_dnToId.TryGetValue(memberDn, out var info))
            {
                members.Add(new { ObjectIdentifier = info.Id, ObjectType = info.Type });
            }
        }

        return new
        {
            ObjectIdentifier = sid,
            ContainedBy = GetContainedBy(obj.DN),
            Properties = new
            {
                name = $"{obj.SamAccountName}@{domain}".ToUpperInvariant(),
                domain = domain.ToUpperInvariant(),
                domainsid = _domainSid,
                distinguishedname = obj.DN,
                highvalue = false,
                admincount = (obj.AdminCount ?? 0) > 0,
                description = obj.Description,
                samaccountname = obj.SamAccountName,
                whencreated = ParseWhenCreated(obj.GetString("whencreated")),
                isaclprotected = false
            },
            Members = members.ToArray(),
            Aces = ParseACL(obj),
            IsDeleted = false,
            IsACLProtected = false
        };
    }

    private object ConvertDomain(LDAPObject obj)
    {
        var sid = obj.GetSidString();
        var domain = GetDomainFromDn(obj.DN ?? "");

        var funcLevel = obj.GetInt("msds-behavior-version") ?? 0;
        var funcLevelStr = funcLevel switch
        {
            0 => "2000",
            1 => "2003 Interim",
            2 => "2003",
            3 => "2008",
            4 => "2008 R2",
            5 => "2012",
            6 => "2012 R2",
            7 => "2016",
            _ => "Unknown"
        };

        return new
        {
            ObjectIdentifier = sid,
            Properties = new
            {
                name = domain.ToUpperInvariant(),
                domain = domain.ToUpperInvariant(),
                domainsid = _domainSid,
                distinguishedname = obj.DN,
                description = obj.Description,
                functionallevel = funcLevelStr,
                highvalue = true,
                whencreated = ParseWhenCreated(obj.GetString("whencreated")),
                isaclprotected = false,
                collected = true
            },
            Trusts = new object[0],
            Aces = ParseACL(obj),
            Links = ParseGpLink(obj.GpLink),
            ChildObjects = new object[0],
            GPOChanges = new
            {
                AffectedComputers = new object[0],
                DcomUsers = new object[0],
                LocalAdmins = new object[0],
                PSRemoteUsers = new object[0],
                RemoteDesktopUsers = new object[0]
            },
            IsDeleted = false,
            IsACLProtected = false
        };
    }

    private object ConvertOU(LDAPObject obj)
    {
        var guid = obj.GetGuid()?.ToString().ToUpperInvariant();
        var domain = GetDomainFromDn(obj.DN ?? "");

        return new
        {
            ObjectIdentifier = guid,
            ContainedBy = GetContainedBy(obj.DN),
            Properties = new
            {
                name = $"{obj.Name}@{domain}".ToUpperInvariant(),
                domain = domain.ToUpperInvariant(),
                domainsid = _domainSid,
                distinguishedname = obj.DN,
                highvalue = false,
                blocksinheritance = obj.GpOptions == 1,
                description = obj.Description,
                whencreated = ParseWhenCreated(obj.GetString("whencreated")),
                isaclprotected = false
            },
            Aces = ParseACL(obj),
            Links = ParseGpLink(obj.GpLink),
            ChildObjects = new object[0],
            GPOChanges = new
            {
                AffectedComputers = new object[0],
                DcomUsers = new object[0],
                LocalAdmins = new object[0],
                PSRemoteUsers = new object[0],
                RemoteDesktopUsers = new object[0]
            },
            IsDeleted = false,
            IsACLProtected = false
        };
    }

    private object ConvertGPO(LDAPObject obj)
    {
        var guid = obj.GetGuid()?.ToString().ToUpperInvariant();
        var domain = GetDomainFromDn(obj.DN ?? "");

        return new
        {
            ObjectIdentifier = guid,
            ContainedBy = GetContainedBy(obj.DN),
            Properties = new
            {
                name = $"{obj.Name}@{domain}".ToUpperInvariant(),
                domain = domain.ToUpperInvariant(),
                domainsid = _domainSid,
                distinguishedname = obj.DN,
                highvalue = false,
                gpcpath = obj.GpcFileSysPath,
                description = obj.Description,
                whencreated = ParseWhenCreated(obj.GetString("whencreated")),
                isaclprotected = false
            },
            Aces = ParseACL(obj),
            IsDeleted = false,
            IsACLProtected = false
        };
    }

    private object ConvertContainer(LDAPObject obj)
    {
        var guid = obj.GetGuid()?.ToString().ToUpperInvariant();
        var domain = GetDomainFromDn(obj.DN ?? "");

        return new
        {
            ObjectIdentifier = guid,
            ContainedBy = GetContainedBy(obj.DN),
            Properties = new
            {
                name = $"{obj.Name}@{domain}".ToUpperInvariant(),
                domain = domain.ToUpperInvariant(),
                domainsid = _domainSid,
                distinguishedname = obj.DN,
                highvalue = false,
                description = obj.Description,
                whencreated = ParseWhenCreated(obj.GetString("whencreated")),
                isaclprotected = false
            },
            Aces = ParseACL(obj),
            ChildObjects = new object[0],
            IsDeleted = false,
            IsACLProtected = false
        };
    }

    // ==================== ADCS CONVERTERS ====================

    private object ConvertCertTemplate(LDAPObject obj)
    {
        var guid = obj.GetGuid()?.ToString().ToUpperInvariant();
        var domain = GetDomainFromDn(obj.DN ?? "");
        var enrollFlag = obj.MsPKIEnrollmentFlag ?? 0;
        var nameFlag = obj.MsPKICertNameFlag ?? 0;
        var schemaVersion = obj.MsPKITemplateSchemaVersion ?? 1;

        // Check for authentication EKUs
        var ekus = obj.PKIExtendedKeyUsage;
        var authenticationEnabled = ekus.Any(e =>
            e.Contains("1.3.6.1.5.5.7.3.2") ||  // Client Authentication
            e.Contains("1.3.6.1.5.2.3.4") ||    // PKINIT Client Authentication
            e.Contains("1.3.6.1.4.1.311.20.2.2") || // Smart Card Logon
            e.Contains("2.5.29.37.0"));         // Any Purpose

        return new
        {
            ObjectIdentifier = guid,
            ContainedBy = GetContainedBy(obj.DN),
            Properties = new
            {
                name = $"{obj.Name}@{domain}".ToUpperInvariant(),
                domain = domain.ToUpperInvariant(),
                domainsid = _domainSid,
                distinguishedname = obj.DN,
                displayname = obj.DisplayName ?? obj.Name,
                validityperiod = ParsePkiPeriod(obj.PKIExpirationPeriod),
                renewalperiod = ParsePkiPeriod(obj.PKIOverlapPeriod),
                schemaversion = schemaVersion,
                enrollmentflag = FormatEnrollmentFlag(enrollFlag),
                certificatenameflag = FormatCertNameFlag(nameFlag),
                requiresmanagerapproval = (enrollFlag & 0x2) != 0,
                enrolleesuppliessubject = (nameFlag & 0x1) != 0,
                subjectaltrequireupn = (nameFlag & 0x2000000) != 0,
                subjectaltrequiredns = (nameFlag & 0x8000000) != 0,
                subjectaltrequireemail = (nameFlag & 0x4000000) != 0,
                subjectaltrequirespn = (nameFlag & 0x800000) != 0,
                nosecurityextension = (enrollFlag & 0x80000) != 0,
                authenticationenabled = authenticationEnabled,
                ekus = ekus.ToArray(),
                certificateapplicationpolicy = obj.GetStringList("mspki-certificate-application-policy").ToArray(),
                authorizedsignatures = obj.MsPKIRASignature ?? 0,
                applicationpolicies = obj.GetStringList("mspki-ra-application-policies").ToArray(),
                issuancepolicies = obj.GetStringList("mspki-ra-policies").ToArray(),
                effectiveekus = ekus.ToArray(),
                highvalue = false,
                whencreated = ParseWhenCreated(obj.GetString("whencreated")),
                isaclprotected = false
            },
            Aces = ParseACL(obj),
            IsDeleted = false,
            IsACLProtected = false
        };
    }

    private object ConvertEnterpriseCA(LDAPObject obj)
    {
        var guid = obj.GetGuid()?.ToString().ToUpperInvariant();
        var domain = GetDomainFromDn(obj.DN ?? "");
        var certThumbprint = ComputeCertThumbprint(obj.CACertificate);
        var certChain = BuildCertChain(obj);

        // Build enabled cert templates list
        var enabledTemplates = obj.CertificateTemplates
            .Select(t => new { ObjectIdentifier = ResolveTemplateGuid(t), ObjectType = "CertTemplate" })
            .Where(t => t.ObjectIdentifier != null)
            .ToArray();

        return new
        {
            ObjectIdentifier = guid,
            ContainedBy = GetContainedBy(obj.DN),
            HostingComputer = ResolveHostingComputer(obj.DnsHostName),
            EnabledCertTemplates = enabledTemplates,
            CARegistryData = new
            {
                CASecurity = new { Collected = false, Data = Array.Empty<object>(), FailureReason = (string?)null },
                EnrollmentAgentRestrictions = new { Collected = false, Restrictions = Array.Empty<object>(), FailureReason = (string?)null },
                IsUserSpecifiesSanEnabled = new { Collected = false, Value = false, FailureReason = (string?)null }
            },
            Properties = new
            {
                name = $"{obj.Name}@{domain}".ToUpperInvariant(),
                domain = domain.ToUpperInvariant(),
                domainsid = _domainSid,
                distinguishedname = obj.DN,
                description = obj.Description,
                whencreated = ParseWhenCreated(obj.GetString("whencreated")),
                flags = obj.GetString("flags") ?? "",
                caname = obj.Name,
                dnshostname = obj.DnsHostName,
                certificatesubject = obj.GetString("cacertificatedn"),
                certificateserialnumber = "",
                certthumbprint = certThumbprint,
                certname = certThumbprint,
                certchain = certChain,
                hasbasicconstraints = true,
                basicconstraintpathlength = 0,
                casecuritycollected = false,
                enrollmentagentrestrictionscollected = false,
                isuserspecifiessanenabledcollected = false,
                highvalue = true,
                isaclprotected = false
            },
            Aces = ParseACL(obj),
            IsDeleted = false,
            IsACLProtected = false
        };
    }

    private object ConvertRootCA(LDAPObject obj)
    {
        var guid = obj.GetGuid()?.ToString().ToUpperInvariant();
        var domain = GetDomainFromDn(obj.DN ?? "");
        var certThumbprint = ComputeCertThumbprint(obj.CACertificate);
        var certChain = BuildCertChain(obj);

        return new
        {
            ObjectIdentifier = guid,
            DomainSID = _domainSid,
            ContainedBy = GetContainedBy(obj.DN),
            Properties = new
            {
                name = $"{obj.Name}@{domain}".ToUpperInvariant(),
                domain = domain.ToUpperInvariant(),
                domainsid = _domainSid,
                distinguishedname = obj.DN,
                description = obj.Description,
                whencreated = ParseWhenCreated(obj.GetString("whencreated")),
                certthumbprint = certThumbprint,
                certname = certThumbprint,
                certchain = certChain,
                hasbasicconstraints = true,
                basicconstraintpathlength = 0,
                highvalue = true,
                isaclprotected = false
            },
            Aces = ParseACL(obj),
            IsDeleted = false,
            IsACLProtected = false
        };
    }

    private object ConvertAIACA(LDAPObject obj)
    {
        var guid = obj.GetGuid()?.ToString().ToUpperInvariant();
        var domain = GetDomainFromDn(obj.DN ?? "");
        var certThumbprint = ComputeCertThumbprint(obj.CACertificate);
        var certChain = BuildCertChain(obj);

        return new
        {
            ObjectIdentifier = guid,
            ContainedBy = GetContainedBy(obj.DN),
            Properties = new
            {
                name = $"{obj.Name}@{domain}".ToUpperInvariant(),
                domain = domain.ToUpperInvariant(),
                domainsid = _domainSid,
                distinguishedname = obj.DN,
                description = obj.Description,
                whencreated = ParseWhenCreated(obj.GetString("whencreated")),
                crosscertificatepair = Array.Empty<string>(),
                hascrosscertificatepair = false,
                certthumbprint = certThumbprint,
                certname = certThumbprint,
                certchain = certChain,
                hasbasicconstraints = true,
                basicconstraintpathlength = 0,
                highvalue = false,
                isaclprotected = false
            },
            Aces = ParseACL(obj),
            IsDeleted = false,
            IsACLProtected = false
        };
    }

    private object ConvertNTAuthStore(LDAPObject obj)
    {
        var guid = obj.GetGuid()?.ToString().ToUpperInvariant() ?? "NTAUTH-STORE-0001";
        var domain = GetDomainFromDn(obj.DN ?? "");

        // Extract all cert thumbprints from cACertificate attribute
        var certThumbprints = obj.CACertificateList
            .Select(ComputeCertThumbprint)
            .Where(t => !string.IsNullOrEmpty(t))
            .ToArray();

        return new
        {
            ObjectIdentifier = guid,
            DomainSID = _domainSid,
            ContainedBy = GetContainedBy(obj.DN),
            Properties = new
            {
                name = $"NTAUTHCERTIFICATES@{domain}".ToUpperInvariant(),
                domain = domain.ToUpperInvariant(),
                domainsid = _domainSid,
                distinguishedname = obj.DN,
                description = obj.Description,
                whencreated = ParseWhenCreated(obj.GetString("whencreated")),
                certthumbprints = certThumbprints,
                highvalue = true,
                isaclprotected = false
            },
            Aces = ParseACL(obj),
            IsDeleted = false,
            IsACLProtected = false
        };
    }

    // ==================== ADCS HELPER METHODS ====================

    private static string ParsePkiPeriod(byte[]? periodBytes)
    {
        if (periodBytes == null || periodBytes.Length < 8)
            return "Unknown";

        try
        {
            var ticks = BitConverter.ToInt64(periodBytes, 0);
            var span = TimeSpan.FromTicks(-ticks);

            if (span.TotalDays >= 365)
            {
                var years = (int)(span.TotalDays / 365);
                return years == 1 ? "1 year" : $"{years} years";
            }
            if (span.TotalDays >= 30)
            {
                var months = (int)(span.TotalDays / 30);
                return months == 1 ? "1 month" : $"{months} months";
            }
            if (span.TotalDays >= 7)
            {
                var weeks = (int)(span.TotalDays / 7);
                return weeks == 1 ? "1 week" : $"{weeks} weeks";
            }
            return span.TotalDays >= 1 ? $"{(int)span.TotalDays} days" : "Unknown";
        }
        catch
        {
            return "Unknown";
        }
    }

    private static string ComputeCertThumbprint(byte[]? certBytes)
    {
        if (certBytes == null || certBytes.Length == 0)
            return "";

        try
        {
            using var sha1 = System.Security.Cryptography.SHA1.Create();
            var hash = sha1.ComputeHash(certBytes);
            return BitConverter.ToString(hash).Replace("-", "").ToUpperInvariant();
        }
        catch
        {
            return "";
        }
    }

    private string[] BuildCertChain(LDAPObject obj)
    {
        var chain = new List<string>();
        var thumbprint = ComputeCertThumbprint(obj.CACertificate);
        if (!string.IsNullOrEmpty(thumbprint))
            chain.Add(thumbprint);
        return chain.ToArray();
    }

    private string? ResolveHostingComputer(string? dnsHostname)
    {
        if (string.IsNullOrEmpty(dnsHostname))
            return null;

        // Try to find computer by DNS hostname
        foreach (var (dn, info) in _dnToId)
        {
            if (info.Type == "Computer" &&
                dn.ToUpperInvariant().Contains($"CN={dnsHostname.Split('.')[0].ToUpperInvariant()}"))
            {
                return info.Id;
            }
        }
        return null;
    }

    private string? ResolveTemplateGuid(string templateName)
    {
        // Try to find template by name in our mappings
        foreach (var (dn, info) in _dnToId)
        {
            if (dn.ToUpperInvariant().Contains($"CN={templateName.ToUpperInvariant()}") &&
                dn.ToUpperInvariant().Contains("CERTIFICATE TEMPLATES"))
            {
                return info.Id;
            }
        }
        // Return the template name as-is if not found (will need manual resolution)
        return templateName;
    }

    private static string FormatEnrollmentFlag(int flag)
    {
        var flags = new List<string>();
        if ((flag & 0x1) != 0) flags.Add("INCLUDE_SYMMETRIC_ALGORITHMS");
        if ((flag & 0x2) != 0) flags.Add("PEND_ALL_REQUESTS");
        if ((flag & 0x4) != 0) flags.Add("PUBLISH_TO_KRA_CONTAINER");
        if ((flag & 0x8) != 0) flags.Add("PUBLISH_TO_DS");
        if ((flag & 0x10) != 0) flags.Add("AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE");
        if ((flag & 0x20) != 0) flags.Add("AUTO_ENROLLMENT");
        if ((flag & 0x40) != 0) flags.Add("CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED");
        if ((flag & 0x100) != 0) flags.Add("PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT");
        if ((flag & 0x200) != 0) flags.Add("USER_INTERACTION_REQUIRED");
        if ((flag & 0x400) != 0) flags.Add("ADD_TEMPLATE_NAME");
        if ((flag & 0x800) != 0) flags.Add("REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE");
        if ((flag & 0x1000) != 0) flags.Add("ALLOW_ENROLL_ON_BEHALF_OF");
        if ((flag & 0x2000) != 0) flags.Add("ADD_OCSP_NOCHECK");
        if ((flag & 0x4000) != 0) flags.Add("ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL");
        if ((flag & 0x8000) != 0) flags.Add("NOREVOCATIONINFOINISSUEDCERTS");
        if ((flag & 0x10000) != 0) flags.Add("INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS");
        if ((flag & 0x20000) != 0) flags.Add("ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT");
        if ((flag & 0x40000) != 0) flags.Add("ISSUANCE_POLICIES_FROM_REQUEST");
        if ((flag & 0x80000) != 0) flags.Add("SKIP_AUTO_RENEWAL");
        if ((flag & 0x100000) != 0) flags.Add("NO_SECURITY_EXTENSION");
        return string.Join(", ", flags);
    }

    private static string FormatCertNameFlag(int flag)
    {
        var flags = new List<string>();
        if ((flag & 0x1) != 0) flags.Add("ENROLLEE_SUPPLIES_SUBJECT");
        if ((flag & 0x10000) != 0) flags.Add("SUBJECT_ALT_REQUIRE_DOMAIN_DNS");
        if ((flag & 0x400000) != 0) flags.Add("SUBJECT_ALT_REQUIRE_DIRECTORY_GUID");
        if ((flag & 0x800000) != 0) flags.Add("SUBJECT_ALT_REQUIRE_SPN");
        if ((flag & 0x1000000) != 0) flags.Add("SUBJECT_REQUIRE_DNS_AS_CN");
        if ((flag & 0x2000000) != 0) flags.Add("SUBJECT_ALT_REQUIRE_UPN");
        if ((flag & 0x4000000) != 0) flags.Add("SUBJECT_ALT_REQUIRE_EMAIL");
        if ((flag & 0x8000000) != 0) flags.Add("SUBJECT_ALT_REQUIRE_DNS");
        if ((flag & 0x10000000) != 0) flags.Add("SUBJECT_REQUIRE_EMAIL");
        if ((flag & 0x20000000) != 0) flags.Add("SUBJECT_REQUIRE_COMMON_NAME");
        if ((flag & 0x40000000) != 0) flags.Add("SUBJECT_REQUIRE_DIRECTORY_PATH");
        if ((flag & unchecked((int)0x80000000)) != 0) flags.Add("OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME");
        return string.Join(", ", flags);
    }

    private object[] ParseACL(LDAPObject obj)
    {
        var aces = new List<object>();
        var sdBytes = obj.GetBytes("ntsecuritydescriptor");

        if (sdBytes == null || sdBytes.Length == 0)
            return aces.ToArray();

        try
        {
            var sd = new RawSecurityDescriptor(sdBytes, 0);

            // Owner ACE
            if (sd.Owner != null)
            {
                var ownerSid = sd.Owner.Value;
                var ownerType = ResolveSidType(ownerSid);
                aces.Add(new
                {
                    RightName = "Owns",
                    IsInherited = false,
                    PrincipalSID = ownerSid,
                    PrincipalType = ownerType
                });
            }

            // DACL ACEs
            if (sd.DiscretionaryAcl != null)
            {
                foreach (var ace in sd.DiscretionaryAcl)
                {
                    if (ace is CommonAce commonAce)
                    {
                        ProcessCommonAce(commonAce, aces);
                    }
                    else if (ace is ObjectAce objectAce)
                    {
                        ProcessObjectAce(objectAce, aces);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            // Skip objects with invalid security descriptors
            Console.WriteLine($"[!] Failed to parse ACL for {obj.DN}: {ex.Message}");
        }

        return aces.ToArray();
    }

    private void ProcessCommonAce(CommonAce ace, List<object> aces)
    {
        // Only process Allow ACEs
        if (ace.AceType != AceType.AccessAllowed && ace.AceType != AceType.AccessAllowedCallback)
            return;

        var principalSid = ace.SecurityIdentifier.Value;
        var principalType = ResolveSidType(principalSid);
        var isInherited = (ace.AceFlags & AceFlags.Inherited) != 0;
        var mask = ace.AccessMask;

        // GenericAll
        if ((mask & 0x10000000) != 0 || (mask & 0xF01FF) == 0xF01FF)
        {
            aces.Add(new { RightName = "GenericAll", IsInherited = isInherited, PrincipalSID = principalSid, PrincipalType = principalType });
        }
        else
        {
            // GenericWrite
            if ((mask & 0x40000000) != 0 || (mask & 0x20028) == 0x20028)
            {
                aces.Add(new { RightName = "GenericWrite", IsInherited = isInherited, PrincipalSID = principalSid, PrincipalType = principalType });
            }

            // WriteDacl
            if ((mask & 0x40000) != 0)
            {
                aces.Add(new { RightName = "WriteDacl", IsInherited = isInherited, PrincipalSID = principalSid, PrincipalType = principalType });
            }

            // WriteOwner
            if ((mask & 0x80000) != 0)
            {
                aces.Add(new { RightName = "WriteOwner", IsInherited = isInherited, PrincipalSID = principalSid, PrincipalType = principalType });
            }

            // AllExtendedRights
            if ((mask & 0x100) != 0)
            {
                aces.Add(new { RightName = "AllExtendedRights", IsInherited = isInherited, PrincipalSID = principalSid, PrincipalType = principalType });
            }
        }
    }

    private void ProcessObjectAce(ObjectAce ace, List<object> aces)
    {
        // Only process Allow ACEs
        if (ace.AceType != AceType.AccessAllowedObject && ace.AceType != AceType.AccessAllowedCallbackObject)
            return;

        var principalSid = ace.SecurityIdentifier.Value;
        var principalType = ResolveSidType(principalSid);
        var isInherited = (ace.AceFlags & AceFlags.Inherited) != 0;
        var mask = ace.AccessMask;
        var objectType = ace.ObjectAceType;

        // Extended Rights (ControlAccess)
        if ((mask & 0x100) != 0)
        {
            if (objectType == Guid.Empty)
            {
                aces.Add(new { RightName = "AllExtendedRights", IsInherited = isInherited, PrincipalSID = principalSid, PrincipalType = principalType });
            }
            else if (ExtendedRightsMap.TryGetValue(objectType, out var rightName))
            {
                aces.Add(new { RightName = rightName, IsInherited = isInherited, PrincipalSID = principalSid, PrincipalType = principalType });
            }
        }

        // WriteProperty
        if ((mask & 0x20) != 0)
        {
            if (objectType == Guid.Empty)
            {
                aces.Add(new { RightName = "GenericWrite", IsInherited = isInherited, PrincipalSID = principalSid, PrincipalType = principalType });
            }
            else if (PropertyMap.TryGetValue(objectType, out var propName))
            {
                if (propName == "Member")
                {
                    aces.Add(new { RightName = "AddMember", IsInherited = isInherited, PrincipalSID = principalSid, PrincipalType = principalType });
                }
                else if (propName == "AddKeyCredentialLink")
                {
                    aces.Add(new { RightName = "AddKeyCredentialLink", IsInherited = isInherited, PrincipalSID = principalSid, PrincipalType = principalType });
                }
            }
            else if (objectType == new Guid("f3a64788-5306-11d1-a9c5-0000f80367c1"))
            {
                // servicePrincipalName
                aces.Add(new { RightName = "WriteSPN", IsInherited = isInherited, PrincipalSID = principalSid, PrincipalType = principalType });
            }
        }

        // Self (for AddSelf to groups)
        if ((mask & 0x8) != 0 && objectType == new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2"))
        {
            aces.Add(new { RightName = "AddSelf", IsInherited = isInherited, PrincipalSID = principalSid, PrincipalType = principalType });
        }
    }

    private string ResolveSidType(string sid)
    {
        if (_sidToType.TryGetValue(sid, out var type))
            return type;

        // Well-known SIDs
        if (sid.EndsWith("-512") || sid.EndsWith("-519") || sid.EndsWith("-544") ||
            sid.EndsWith("-548") || sid.EndsWith("-551") || sid.EndsWith("-526") ||
            sid.EndsWith("-527"))
            return "Group";

        if (sid.StartsWith("S-1-5-21-") && sid.Split('-').Length == 8)
        {
            var rid = int.Parse(sid.Split('-').Last());
            if (rid >= 1000) return "User"; // Most RIDs > 1000 are users
        }

        return "Group"; // Default to Group for unknown
    }

    private static string GetDomainFromDn(string dn)
    {
        var parts = Regex.Matches(dn, @"DC=([^,]+)", RegexOptions.IgnoreCase)
            .Cast<Match>()
            .Select(m => m.Groups[1].Value);
        return string.Join(".", parts);
    }

    private static long FileTimeToUnix(long? fileTime)
    {
        if (fileTime == null || fileTime <= 0 || fileTime > 2650467743990000000)
            return -1;
        return (fileTime.Value - 116444736000000000) / 10000000;
    }

    private static long ParseWhenCreated(string? whenCreated)
    {
        if (string.IsNullOrEmpty(whenCreated)) return -1;
        try
        {
            // Format: 20141012164633.0Z
            var dateStr = whenCreated.Split('.')[0];
            var dt = DateTime.ParseExact(dateStr, "yyyyMMddHHmmss", null);
            return ((DateTimeOffset)dt).ToUnixTimeSeconds();
        }
        catch { return -1; }
    }

    private static (bool Enabled, bool TrustedForDelegation, bool TrustedToAuthForDelegation,
        bool PasswordNotRequired, bool DontReqPreauth, bool PasswordNeverExpires, bool Sensitive) ParseUAC(int uac)
    {
        return (
            Enabled: (uac & 0x2) == 0,
            TrustedForDelegation: (uac & 0x80000) != 0,
            TrustedToAuthForDelegation: (uac & 0x1000000) != 0,
            PasswordNotRequired: (uac & 0x20) != 0,
            DontReqPreauth: (uac & 0x400000) != 0,
            PasswordNeverExpires: (uac & 0x10000) != 0,
            Sensitive: (uac & 0x100000) != 0
        );
    }

    private static object[] ParseGpLink(string? gpLink)
    {
        if (string.IsNullOrEmpty(gpLink)) return Array.Empty<object>();

        var links = new List<object>();
        var parts = gpLink.Split('[', StringSplitOptions.RemoveEmptyEntries);

        foreach (var part in parts)
        {
            var clean = part.TrimEnd(']');
            var split = clean.Split(';');
            if (split.Length >= 2)
            {
                var ldapPath = split[0];
                var status = int.TryParse(split[1], out var s) ? s : 0;

                var guidStart = ldapPath.IndexOf('{');
                var guidEnd = ldapPath.IndexOf('}');
                if (guidStart >= 0 && guidEnd > guidStart)
                {
                    var guid = ldapPath.Substring(guidStart + 1, guidEnd - guidStart - 1);
                    links.Add(new
                    {
                        GUID = guid.ToUpperInvariant(),
                        IsEnforced = (status & 2) == 2
                    });
                }
            }
        }

        return links.ToArray();
    }
}
