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

    private const string EncodedTrustedKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc3MzEwMDVaIiwia2V5IjoiTmFDbC5UU1ZHVUx1bld1M3BQbmQ0MWhoa3Mzc2s2bDBCRGhVcGlvelIveTdVKy9oQ3dETkN0a2crTTc0MTJMK3dMMGNWcm9NVUhRVjh3ZWlRNnJVMW1qUCs5QSIsInB1YiI6Ik5hQ2wuUXNBelFyWklQak8rTmRpL3NDOUhGYTZERkIwRmZNSG9rT3ExTlpvei92USIsInVpZCI6IjEzNzRkNTIwLTM2NzEtNGY2OC1iODg1LTdiZTM3NTViY2Y0OCJ9";
    private const string EncodedTrustedIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDM0LTAxLTIzVDE0OjQ2OjE1Ljc5MTc4NFoiLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5MTc4NFoiLCJpc3MiOiI2NTQ5OGYxNy1jMzI1LTQ3OWMtYmY5Yy04NWE0ZmJlOGEwYjAiLCJwdWIiOiJOYUNsLlFzQXpRclpJUGpPK05kaS9zQzlIRmE2REZCMEZmTUhva09xMU5ab3ovdlEiLCJzdWIiOiI2NTQ5OGYxNy1jMzI1LTQ3OWMtYmY5Yy04NWE0ZmJlOGEwYjAiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6ImMyNGFjM2U2LTZlN2MtNDNiOS1iNjUzLTAxY2E3MmM0N2Y2MCJ9.MWZhODZlZWQzYmEzNTczOC41NTkyYzM3Mjc0MGY4MjQxZWMzZTg0ZmMyY2U5YzU5MGY1MjdmNmZlMjhhMjY4YWEzNzM4NWI5MTljMzEzM2ZlMjc5MmYwNjNhOWE5NWYzMmEwODBkOWYyYzk1NjQ0MGQ1NzIxODRhOGEzYzViNDIyYjE1ZjgyNjkwMzNiNmUwNA";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;
    #endregion

    #region -- INTERMEDIATE IDENTITY --

    private const string EncodedIntermediateKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5MzUwNzNaIiwia2V5IjoiTmFDbC5VQ216YmV0TVpZa3hvTlRSZFRSblJqRzZGSHhHdnlmRGRqeWdKT0lRTWVDWFl1cDdEeHV1T0dRa2dDN09NKzZnc2RMZkttQ1h0bjVnUUNWMEtTWXY2dyIsInB1YiI6Ik5hQ2wubDJMcWV3OGJyamhrSklBdXpqUHVvTEhTM3lwZ2w3WitZRUFsZENrbUwrcyIsInVpZCI6IjA4ZDE0OWIyLTNiOTUtNGJiZS1hNzFkLTdlY2VjNDg2OTMxMCJ9";
    private const string EncodedIntermediateIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiZXhwIjoiMjAyOS0wMS0yNFQxNDo0NjoxNS43OTU2MzQyWiIsImlhdCI6IjIwMjQtMDEtMjZUMTQ6NDY6MTUuNzk1NjM0MloiLCJpc3MiOiI2NTQ5OGYxNy1jMzI1LTQ3OWMtYmY5Yy04NWE0ZmJlOGEwYjAiLCJwdWIiOiJOYUNsLmwyTHFldzhicmpoa0pJQXV6alB1b0xIUzN5cGdsN1orWUVBbGRDa21MK3MiLCJzdWIiOiIyZjFkMGM0Mi0zYjhhLTQ3YTgtYjM3ZC0wOTE3Yjc2YjY2MzkiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6IjEyOTA0MGIxLTE5ODAtNDcxMi04NDllLTk4NTc1Mjk5ZGJjZCJ9.MWZhODZlZWQzYmEzNTczOC5kMGUyMjg0M2JkZGM5ZTgwZmY2MzUxZGVmNjg3M2FmOGZhYTE4YWQyMmU0Y2I1Yzc0YWY2NjA3MzllNGEzNmNlMGNmM2FmYjVkYTQ3YzUzZTlmODlhYWI4MDg1OTY0YjM2NWFkMWI5ZDU4MmI3ZDMxMjYxMmRlMmQxZDFmMTIwOQ";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;
    #endregion

    #region -- ISSUER IDENTITY (SENDER) --

    private const string EncodedIssuerKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5NjQwMDNaIiwia2V5IjoiTmFDbC5oeHFXRXlTQ2VGV0VvYlFEQm9CNndOdGZvZGtrSDFnbU5uc0pvUDAzVk9BVWNNaUg5Q09sWWdTKzJkWlVDR2drQkNUN0laaDhZTXRmT0dHS1hvK2o4USIsInB1YiI6Ik5hQ2wuRkhESWgvUWpwV0lFdnRuV1ZBaG9KQVFrK3lHWWZHRExYemhoaWw2UG8vRSIsInVpZCI6ImY2OTQ2Njk2LTliYTItNDJiOS1hODIzLWJjZjcyZjZmYjg1NSJ9";
    public const string EncodedIssuerIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjUtMDEtMjVUMTQ6NDY6MTUuNzk2NDQwMVoiLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5NjQ0MDFaIiwiaXNzIjoiMmYxZDBjNDItM2I4YS00N2E4LWIzN2QtMDkxN2I3NmI2NjM5IiwicHViIjoiTmFDbC5GSERJaC9RanBXSUV2dG5XVkFob0pBUWsreUdZZkdETFh6aGhpbDZQby9FIiwic3ViIjoiMzBiYjEwZGItY2QzNS00ZjNkLWIyNmEtYjdkZjBjNTgyNzljIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiIxYjYyYmY0ZC05Yjk3LTQyOGMtYWJkNC04NzI1MGM1Y2MzNmMifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU9TMHdNUzB5TkZReE5EbzBOam94TlM0M09UVTJNelF5V2lJc0ltbGhkQ0k2SWpJd01qUXRNREV0TWpaVU1UUTZORFk2TVRVdU56azFOak0wTWxvaUxDSnBjM01pT2lJMk5UUTVPR1l4Tnkxak16STFMVFEzT1dNdFltWTVZeTA0TldFMFptSmxPR0V3WWpBaUxDSndkV0lpT2lKT1lVTnNMbXd5VEhGbGR6aGljbXBvYTBwSlFYVjZhbEIxYjB4SVV6TjVjR2RzTjFvcldVVkJiR1JEYTIxTUszTWlMQ0p6ZFdJaU9pSXlaakZrTUdNME1pMHpZamhoTFRRM1lUZ3RZak0zWkMwd09URTNZamMyWWpZMk16a2lMQ0p6ZVhNaU9pSnBieTVrYVcxbFptOXliV0YwTG5KbFppSXNJblZwWkNJNklqRXlPVEEwTUdJeExURTVPREF0TkRjeE1pMDRORGxsTFRrNE5UYzFNams1WkdKalpDSjkuTVdaaE9EWmxaV1F6WW1Fek5UY3pPQzVrTUdVeU1qZzBNMkprWkdNNVpUZ3dabVkyTXpVeFpHVm1OamczTTJGbU9HWmhZVEU0WVdReU1tVTBZMkkxWXpjMFlXWTJOakEzTXpsbE5HRXpObU5sTUdObU0yRm1ZalZrWVRRM1l6VXpaVGxtT0RsaFlXSTRNRGcxT1RZMFlqTTJOV0ZrTVdJNVpEVTRNbUkzWkRNeE1qWXhNbVJsTW1ReFpERm1NVEl3T1E.YzBlZWJhNGRiZTZhYjNjNy5mMWNlMzllNmZmOWM4NmUzNmU0Mzk2ZjkxNmMyYjcxMGJjNzY1MThjNTc2NmJiYjUwNzZmMGUxMGVlNTVjZjhhMGZlYWIxODgzZjM5NDYyZWMzMmU2ZTE0NDE4YWFhOWZmYjNjOTYzMDViMDdkN2FjMTk3ODQ4NjQ4ZjYxZDEwMQ";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;
    #endregion

    #region -- AUDIENCE IDENTITY (RECEIVER) --

    private const string EncodedAudienceKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5NjU0OVoiLCJrZXkiOiJOYUNsLkVDUW9YTkRvaEp4MlhNTUVQVTZPWEQ4bVZTclE3eE0wa3M0UDBiQ1MxRDA5enhRYUppY2RSM0tEUit0S2V2UTdvYk43TUl3OVNIUFphbXRXWVQyTjFnIiwicHViIjoiTmFDbC5QYzhVR2lZbkhVZHlnMGZyU25yME82R3plekNNUFVoejJXcHJWbUU5amRZIiwidWlkIjoiYTZhNzAyYzItODQ1ZS00NGVlLThlZWMtODgyOGQzYTQ2ZDc0In0";
    private const string EncodedAudienceIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjUtMDEtMjVUMTQ6NDY6MTUuNzk2NTc2NFoiLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5NjU3NjRaIiwiaXNzIjoiMmYxZDBjNDItM2I4YS00N2E4LWIzN2QtMDkxN2I3NmI2NjM5IiwicHViIjoiTmFDbC5QYzhVR2lZbkhVZHlnMGZyU25yME82R3plekNNUFVoejJXcHJWbUU5amRZIiwic3ViIjoiOTc3Yjc1ZTctYmFlMC00YmMzLTkxMzYtZTNkY2M0YzEwODk5Iiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiI1MzI3YTY3Mi1iYzk1LTQ2MWYtYmRkZS0yZDgwY2UxZTM5MmYifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU9TMHdNUzB5TkZReE5EbzBOam94TlM0M09UVTJNelF5V2lJc0ltbGhkQ0k2SWpJd01qUXRNREV0TWpaVU1UUTZORFk2TVRVdU56azFOak0wTWxvaUxDSnBjM01pT2lJMk5UUTVPR1l4Tnkxak16STFMVFEzT1dNdFltWTVZeTA0TldFMFptSmxPR0V3WWpBaUxDSndkV0lpT2lKT1lVTnNMbXd5VEhGbGR6aGljbXBvYTBwSlFYVjZhbEIxYjB4SVV6TjVjR2RzTjFvcldVVkJiR1JEYTIxTUszTWlMQ0p6ZFdJaU9pSXlaakZrTUdNME1pMHpZamhoTFRRM1lUZ3RZak0zWkMwd09URTNZamMyWWpZMk16a2lMQ0p6ZVhNaU9pSnBieTVrYVcxbFptOXliV0YwTG5KbFppSXNJblZwWkNJNklqRXlPVEEwTUdJeExURTVPREF0TkRjeE1pMDRORGxsTFRrNE5UYzFNams1WkdKalpDSjkuTVdaaE9EWmxaV1F6WW1Fek5UY3pPQzVrTUdVeU1qZzBNMkprWkdNNVpUZ3dabVkyTXpVeFpHVm1OamczTTJGbU9HWmhZVEU0WVdReU1tVTBZMkkxWXpjMFlXWTJOakEzTXpsbE5HRXpObU5sTUdObU0yRm1ZalZrWVRRM1l6VXpaVGxtT0RsaFlXSTRNRGcxT1RZMFlqTTJOV0ZrTVdJNVpEVTRNbUkzWkRNeE1qWXhNbVJsTW1ReFpERm1NVEl3T1E.YzBlZWJhNGRiZTZhYjNjNy44YzcxMjdiNzQ5ZTBlOGQ5NzdmYzZiNGFjYTcxNjc2N2I2MjYwMmVkOTQ1ODBmNjA5NDkzZmM3ZDg2M2M2MjdjMjk2NDA4YjFhM2E4YjViYzMzYTk2NmMzMDM1MTY4MTdhMTU2MDdlMzgxNzU2MzAyMzc1NzA3MGMyOTJhOTEwNw";    
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