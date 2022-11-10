//
//  Commons.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using DiME;
using DiME.Capability;

namespace DiME_test;

[TestClass]
public class Commons
{
    #region -- PUBLIC --

    public const string SystemName = "io.dimeformat.ref";
    public const string Payload = "Racecar is racecar backwards.";
    public const string Mimetype = "text/plain";
    public const string Context = "test-context";
    public const string SignKeyContext = "id-key";
    public const string IssuerUrl = "https://example.dimeformat.io";
        
    public static string FullHeaderFor(string itemIdentifier) {
        return $"{Envelope.ItemHeader}:{itemIdentifier}";
    }
        
    public static Key TrustedKey => _trustedKey ??= Item.Import<Key>(EncodedTrustedKey);
    public static Identity TrustedIdentity => _trustedIdentity ??= Item.Import<Identity>(EncodedTrustedIdentity);
    public static Key IntermediateKey => _intermediateKey ??= Item.Import<Key>(EncodedIntermediateKey);
    public static Identity IntermediateIdentity => _intermediateIdentity ??= Item.Import<Identity>(EncodedIntermediateIdentity);
    public static Key IssuerKey => _issuerKey ??= Item.Import<Key>(EncodedIssuerKey);
    public static Identity IssuerIdentity => _issuerIdentity ??= Item.Import<Identity>(EncodedIssuerIdentity);
    public static Key AudienceKey => _audienceKey ??= Item.Import<Key>(EncodedAudienceKey);
    public static Identity AudienceIdentity => _audienceIdentity ??= Item.Import<Identity>(EncodedAudienceIdentity);

    public static void InitializeKeyRing()
    {
        Dime.KeyRing.Put(TrustedIdentity);
    }
    
    public static void ClearKeyRing()
    {
        Dime.KeyRing.Clear();
    }
    
    #endregion
    
    /// TESTS ///

    [TestMethod]
    public void GenerateCommons() 
    {
        Commons.ClearKeyRing();
        var trustedKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var trustedIdentity = GenerateIdentity(trustedKey, trustedKey, null, Dime.ValidFor1Year * 10, new List<IdentityCapability>() { IdentityCapability.Generic, IdentityCapability.Issue });
        Console.WriteLine("#region -- TRUSTED IDENTITY --");
        Console.WriteLine("private const string EncodedTrustedKey = \"" + trustedKey.Export() + "\";");
        Console.WriteLine("private const string EncodedTrustedIdentity = \"" + trustedIdentity.Export() + "\";\n");

        Dime.KeyRing.Put(trustedIdentity);
        var intermediateKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var intermediateIdentity = GenerateIdentity(intermediateKey, trustedKey, trustedIdentity, Dime.ValidFor1Year * 5, new List<IdentityCapability>() { IdentityCapability.Generic, IdentityCapability.Identify, IdentityCapability.Issue });
        Console.WriteLine("#region -- INTERMEDIATE IDENTITY ---");
        Console.WriteLine("private const string EncodedIntermediateKey = \"" + intermediateKey.Export() + "\";");
        Console.WriteLine("private const string EncodedIntermediateIdentity = \""+ intermediateIdentity.Export() + "\";\n");

        var issuerKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var issuerIdentity = GenerateIdentity(issuerKey, intermediateKey, intermediateIdentity, Dime.ValidFor1Year, new List<IdentityCapability>() { IdentityCapability.Generic, IdentityCapability.Identify });
        Console.WriteLine("#region -- ISSUER IDENTITY (SENDER) --");
        Console.WriteLine("private const string EncodedIssuerKey = \"" + issuerKey.Export() + "\";");
        Console.WriteLine("private const string EncodedIssuerIdentity = \""+ issuerIdentity.Export() +"\";\n");

        var audienceKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var audienceIdentity = GenerateIdentity(audienceKey, intermediateKey, intermediateIdentity, Dime.ValidFor1Year, new List<IdentityCapability>() { IdentityCapability.Generic, IdentityCapability.Identify });

        Console.WriteLine("#region -- AUDIENCE IDENTITY (RECEIVER) --");
        Console.WriteLine("private const string EncodedAudienceKey = \"" + audienceKey.Export() + "\";");
        Console.WriteLine("private const string EncodedAudienceIdentity = \""+ audienceIdentity.Export() +"\";\n");
    }

    #region -- TRUSTED IDENTITY --

    private const string EncodedTrustedKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjM1OjQ0LjA2MjA2OFoiLCJrZXkiOiJEU0MuQm50U1BuMkNlcW15MisrYUtuaVpCdk1HYkhYMCtYMkhKNUw1WkJSNDN0bEdQOGIzYkMrc0l6Z21MOVhwaFJaWHBNRGZpQWE2K3F2dzl3RU4wckVWWXciLCJwdWIiOiJEU0MuUmovRzkyd3ZyQ000SmkvVjZZVVdWNlRBMzRnR3V2cXI4UGNCRGRLeEZXTSIsInVpZCI6ImE1MTFiYjJmLTJjMGEtNDlmYy1hYjZiLWMwN2I0NjcxNGFlMyJ9";
    private const string EncodedTrustedIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDMyLTEwLTIxVDIyOjM1OjQ0LjA4MTc4NFoiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjM1OjQ0LjA4MTc4NFoiLCJpc3MiOiJlMGU2Y2JhNi1iZDRkLTQ1ZGQtODIzNC0wM2FmZGVhZTkwNGEiLCJwdWIiOiJEU0MuUmovRzkyd3ZyQ000SmkvVjZZVVdWNlRBMzRnR3V2cXI4UGNCRGRLeEZXTSIsInN1YiI6ImUwZTZjYmE2LWJkNGQtNDVkZC04MjM0LTAzYWZkZWFlOTA0YSIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiYjlkOTM2ZGYtMjU4ZS00ZjJmLTkyZDUtN2JmYTE0YmFjMzhkIn0.ZWVjODgzYmZiNGNhODVkMC5hNDhjYzM2ZjhkN2Y1MmIxYmIxNTczZjA1YTk1NTVlYzM0NjU2MDVlZDkxZjk3OWM2ZTA5MDlkN2E2OTRiNjk3YzY5NzY5ZjkxNGQ0NzgyZGJhY2Y0YTg1Mjg4ZjNlYWYzMzQwMmI3NmUyMTI0M2I2MjQzOWE1ZmY2YjlkYzQwYg";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;
    #endregion

    #region -- INTERMEDIATE IDENTITY --

    private const string EncodedIntermediateKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjM1OjQ0LjA4MzIwMloiLCJrZXkiOiJEU0MublAyNS9VM1pKU0IrNHUvZFJZL0RWTm1pL0NFUWZFVDZPV1M0WldrU2ZrSVpHSXNJRzlNK04vZnRhdDJKZnJZRjFmN0JkZFBrSmJJZVIxeWkveDB1OFEiLCJwdWIiOiJEU0MuR1JpTENCdlRQamYzN1dyZGlYNjJCZFgrd1hYVDVDV3lIa2Rjb3Y4ZEx2RSIsInVpZCI6IjAxZjgzNDhlLWNhZGUtNDgzZS1hNmY0LTY3YjY3MjkyOTA1MCJ9";
    private const string EncodedIntermediateIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiZXhwIjoiMjAyNy0xMC0yM1QyMjozNTo0NC4wODU0MThaIiwiaWF0IjoiMjAyMi0xMC0yNFQyMjozNTo0NC4wODU0MThaIiwiaXNzIjoiZTBlNmNiYTYtYmQ0ZC00NWRkLTgyMzQtMDNhZmRlYWU5MDRhIiwicHViIjoiRFNDLkdSaUxDQnZUUGpmMzdXcmRpWDYyQmRYK3dYWFQ1Q1d5SGtkY292OGRMdkUiLCJzdWIiOiIxNzVjNmEyOC00Njk5LTRjYTMtOTFjMC05NTU1NjlhYzkxNjkiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6IjZjYzIyMmMzLWU1ZGMtNDIyYS1iOWZjLTMwOGU4ZDc2ZTc5YiJ9.ZWVjODgzYmZiNGNhODVkMC4xYTRiZDM1NTg1NTFkMGUyMDNlZjdiYmZjYzFhZmM0MDIzMmZjNWEwNmI2ZDZkODQxYWJiMGM2MzNjMzc3NmJiMzc4MjRlMGE2MmUzOWMzYjY1NTNjODM2MDgwZTg1MzU4MDdjMTJiODViNTYxYmY0N2IxOWMyOTIwNGM0MTUwMw";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;
    #endregion

    #region -- ISSUER IDENTITY (SENDER) --

    private const string EncodedIssuerKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjM1OjQ0LjA4NTgzOVoiLCJrZXkiOiJEU0MuNXlFblAxck5LaHZ3MnRoOUs0Qm0rRU1kWlc2QStkT2FlYWN6cGhmNlNMRytjN2JnQ2ZYYm5ORitUemtXZmpHLzk4ejhSRFg3VFNId0dYbVNTUFpraEEiLCJwdWIiOiJEU0Mudm5PMjRBbjEyNXpSZms4NUZuNHh2L2ZNL0VRMSswMGg4Qmw1a2tqMlpJUSIsInVpZCI6IjUxY2FhNGQxLTAzYjEtNGFkYS1hOGVkLTk2MmYzY2Y0NTIzMiJ9";
    private const string EncodedIssuerIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMjRUMjI6MzU6NDQuMDg1OTUyWiIsImlhdCI6IjIwMjItMTAtMjRUMjI6MzU6NDQuMDg1OTUyWiIsImlzcyI6IjE3NWM2YTI4LTQ2OTktNGNhMy05MWMwLTk1NTU2OWFjOTE2OSIsInB1YiI6IkRTQy52bk8yNEFuMTI1elJmazg1Rm40eHYvZk0vRVExKzAwaDhCbDVra2oyWklRIiwic3ViIjoiMTAzMDU3MmYtNmI4Mi00MzZkLTlkNTEtNzkwMjBlNjJmODUzIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiJhMzZlNTZkZS04ODNjLTRhNGYtODk2Mi1mZWZiNzVhYTRiMDIifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB5TTFReU1qb3pOVG8wTkM0d09EVTBNVGhhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB5TkZReU1qb3pOVG8wTkM0d09EVTBNVGhhSWl3aWFYTnpJam9pWlRCbE5tTmlZVFl0WW1RMFpDMDBOV1JrTFRneU16UXRNRE5oWm1SbFlXVTVNRFJoSWl3aWNIVmlJam9pUkZORExrZFNhVXhEUW5aVVVHcG1NemRYY21ScFdEWXlRbVJZSzNkWVdGUTFRMWQ1U0d0a1kyOTJPR1JNZGtVaUxDSnpkV0lpT2lJeE56VmpObUV5T0MwME5qazVMVFJqWVRNdE9URmpNQzA1TlRVMU5qbGhZemt4TmpraUxDSnplWE1pT2lKcGJ5NWthVzFsWm05eWJXRjBMbkpsWmlJc0luVnBaQ0k2SWpaall6SXlNbU16TFdVMVpHTXROREl5WVMxaU9XWmpMVE13T0dVNFpEYzJaVGM1WWlKOS5aV1ZqT0RnelltWmlOR05oT0RWa01DNHhZVFJpWkRNMU5UZzFOVEZrTUdVeU1ETmxaamRpWW1aall6RmhabU0wTURJek1tWmpOV0V3Tm1JMlpEWmtPRFF4WVdKaU1HTTJNek5qTXpjM05tSmlNemM0TWpSbE1HRTJNbVV6T1dNellqWTFOVE5qT0RNMk1EZ3daVGcxTXpVNE1EZGpNVEppT0RWaU5UWXhZbVkwTjJJeE9XTXlPVEl3TkdNME1UVXdNdw.NDFlNmM2ODI5Y2VmNjdmZS42YmNlMzg2MmJjNWY5NzM2OGFjMTQxMWVmYmIxYTcxN2JiZGVhOGEyODNjZWYzODJjOTAzNTNjOTU2NTEwMjA0MTlkNWU5MzJkNDM4NDNmMmMyYzUyMDE3ZTIzZjYyZjM5MTBmMmExZmZkMjlkYzZiMjZmMTNkZGFmODFhYTEwMQ";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;
    #endregion

    #region -- AUDIENCE IDENTITY (RECEIVER) --

    private const string EncodedAudienceKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjM1OjQ0LjA4NjM3M1oiLCJrZXkiOiJEU0MuOHphU3ZyQU4xbXR2ekcvTDQzUEdmM3VxeGg3VDhOWEwzak41NU4rYUc2S0dSWjA0TnMxUHRnRFp2S0hHZU9WN2lIYUVIVFBXMm1UazFjd2FzRnF1K2ciLCJwdWIiOiJEU0MuaGtXZE9EYk5UN1lBMmJ5aHhuamxlNGgyaEIwejF0cGs1TlhNR3JCYXJ2byIsInVpZCI6IjBiNDc1MTYyLWQ1ODItNDg1OS04MmY4LTAzYWJhYmU3OGZjZCJ9";
    private const string EncodedAudienceIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMjRUMjI6MzU6NDQuMDg2NDU0WiIsImlhdCI6IjIwMjItMTAtMjRUMjI6MzU6NDQuMDg2NDU0WiIsImlzcyI6IjE3NWM2YTI4LTQ2OTktNGNhMy05MWMwLTk1NTU2OWFjOTE2OSIsInB1YiI6IkRTQy5oa1dkT0RiTlQ3WUEyYnloeG5qbGU0aDJoQjB6MXRwazVOWE1HckJhcnZvIiwic3ViIjoiOWQwYzZjMDMtNWU1Zi00NGNiLWIxZWYtYjMwNDAzZTUwNmYwIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiI2ODBjMTA4MS02NWQyLTRmNWQtOTBhNS03ZWFmMWZjMDE5MzAifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB5TTFReU1qb3pOVG8wTkM0d09EVTBNVGhhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB5TkZReU1qb3pOVG8wTkM0d09EVTBNVGhhSWl3aWFYTnpJam9pWlRCbE5tTmlZVFl0WW1RMFpDMDBOV1JrTFRneU16UXRNRE5oWm1SbFlXVTVNRFJoSWl3aWNIVmlJam9pUkZORExrZFNhVXhEUW5aVVVHcG1NemRYY21ScFdEWXlRbVJZSzNkWVdGUTFRMWQ1U0d0a1kyOTJPR1JNZGtVaUxDSnpkV0lpT2lJeE56VmpObUV5T0MwME5qazVMVFJqWVRNdE9URmpNQzA1TlRVMU5qbGhZemt4TmpraUxDSnplWE1pT2lKcGJ5NWthVzFsWm05eWJXRjBMbkpsWmlJc0luVnBaQ0k2SWpaall6SXlNbU16TFdVMVpHTXROREl5WVMxaU9XWmpMVE13T0dVNFpEYzJaVGM1WWlKOS5aV1ZqT0RnelltWmlOR05oT0RWa01DNHhZVFJpWkRNMU5UZzFOVEZrTUdVeU1ETmxaamRpWW1aall6RmhabU0wTURJek1tWmpOV0V3Tm1JMlpEWmtPRFF4WVdKaU1HTTJNek5qTXpjM05tSmlNemM0TWpSbE1HRTJNbVV6T1dNellqWTFOVE5qT0RNMk1EZ3daVGcxTXpVNE1EZGpNVEppT0RWaU5UWXhZbVkwTjJJeE9XTXlPVEl3TkdNME1UVXdNdw.NDFlNmM2ODI5Y2VmNjdmZS5iZGE5M2UwMWMyOWM3NWQ2N2NmNTVhMDFiNDg2OTgzMGNjOTMxMGYxZWZiY2FhM2I4MzRhYTE4M2Q3YTgyNjRiMjU5M2UzNWI2ODIwZjM1NjJiYTI5YjNhOWMyZjQ0M2M5YTBlM2ZiNTIyNDgyMGQ4OGU5YTA4NWU5ZTU5N2QwZA";
    private static Key _audienceKey;
    private static Identity _audienceIdentity;
    #endregion

    private static Identity GenerateIdentity(Key subjectKey, Key issuerKey, Identity issuerIdentity, long validFor, List<IdentityCapability> capabilities) {
        var subjectId = Guid.NewGuid();
        var iir = IdentityIssuingRequest.Generate(subjectKey, capabilities);
        var identity = issuerIdentity == null ? iir.SelfIssue(subjectId, validFor, issuerKey, SystemName) : iir.Issue(subjectId, validFor, issuerKey, issuerIdentity, true, capabilities);
        return identity;
    }
}