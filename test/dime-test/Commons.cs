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

    private const string EncodedTrustedKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTE3VDE4OjUzOjM1LjM3MjMyMloiLCJrZXkiOiJTVE4uOGRkUWI0dzFSS3JkZ3FRRmdOMnNjNk5LRUtyWWdzckpRdVEzcU13d3ZoQURqM2FUU2l3NExVWXdISllOcjhneTNScWZRVEF1M3J5M2pUZlRrMm1GcUhvRkVxd281IiwicHViIjoiU1ROLjJpQVVOOWg1VlBaM2lMcVNhOG1xQXR0cktGQXFuZEV5ZnBrOXU1SndWS0c0ZmpvYmM0IiwidWlkIjoiYjhmNzg2YzctZWVkOS00NDZlLTkwMTUtYjJhNDE5ODA2MTM4In0";
    private const string EncodedTrustedIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDMyLTEwLTE0VDE4OjUzOjM1LjM5Mzk2M1oiLCJpYXQiOiIyMDIyLTEwLTE3VDE4OjUzOjM1LjM5Mzk2M1oiLCJpc3MiOiJkNGI2MDg0Ni0wMjg1LTQ2M2MtYjQ2NS05Yjc1ODczM2E0MWYiLCJwdWIiOiJTVE4uMmlBVU45aDVWUFozaUxxU2E4bXFBdHRyS0ZBcW5kRXlmcGs5dTVKd1ZLRzRmam9iYzQiLCJzdWIiOiJkNGI2MDg0Ni0wMjg1LTQ2M2MtYjQ2NS05Yjc1ODczM2E0MWYiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6IjViNjc1OGNmLTc3NWMtNDliNS1hMzY5LTY2NjA2NmRkYzE3ZiJ9.NjEwYmE2NGQ0MzFiZGI2YS5lYjUzNjMzNDYwMWJlYmFmYzQyNzAzYjNkMDRmY2QwZDcwMGIzNDVlMzlhOTM5ZWRiZGQ1OTE1Zjk4YWIxOWJiNTQ5NGVlYzJlNTBlY2RhN2U1Nzk0ZmNlOTI5NmY0YWRhNGE2NzQ2YTM0NjRlZTQxZWFiMDFlOTZiYTdlYjUwMg";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;
    #endregion

    #region -- INTERMEDIATE IDENTITY --

    private const string EncodedIntermediateKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTE3VDE4OjUzOjM1LjM5NTA0WiIsImtleSI6IlNUTi5aUFF2RE50TEd2NVY2TWRoYWVIRXZhQkJ3M1JMMXkyUUdwNkdpU2k3ZVozY0dKSFMyeFE4N0dLN1NvbWJMTlBGTnREdTJCZDRuY3JyUWlKb0NKTXRmZDgyYW5ON0giLCJwdWIiOiJTVE4uaGVmWExrVVNGdkF5Uld0RUFYaHZuWUdLZWF0UzhYVWp2YW85Y2N2UkJSRWJvMnNGSCIsInVpZCI6IjU3NTc2NmNjLTMwYTQtNGQxYS1iZDE5LTk5ODNlYTc3MGNlMSJ9";
    private const string EncodedIntermediateIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiZXhwIjoiMjAyNy0xMC0xNlQxODo1MzozNS4zOTcxMTlaIiwiaWF0IjoiMjAyMi0xMC0xN1QxODo1MzozNS4zOTcxMTlaIiwiaXNzIjoiZDRiNjA4NDYtMDI4NS00NjNjLWI0NjUtOWI3NTg3MzNhNDFmIiwicHViIjoiU1ROLmhlZlhMa1VTRnZBeVJXdEVBWGh2bllHS2VhdFM4WFVqdmFvOWNjdlJCUkVibzJzRkgiLCJzdWIiOiJjZWRmMmI2YS0yOWUyLTQ0ZTUtOTYxYS1jNDczZTRiNTYzNzgiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6ImQ4MTM4N2MzLWEzMjktNDNjMC05MDU5LWJhM2FlZjVlOWVkZSJ9.NjEwYmE2NGQ0MzFiZGI2YS4zNWIyNjg0NzJlNWJlMWMwY2QzMDQwMjdhNzNkMzgzMmQyNzRiMWY1ZGRiZmI0ZGNhOGRhMzkyMjcxODBlMTVlOWY4YWUxY2I0ZjllZTJlMWZhYjgyZDQ4ZWEwYzgwM2Y0MTIzZTgyMmI0MzlmNzA4YjcwNzYxYTMxY2Q3NTgwMA";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;
    #endregion

    #region -- ISSUER IDENTITY (SENDER) --

    private const string EncodedIssuerKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTE3VDE4OjUzOjM1LjM5NzM1NVoiLCJrZXkiOiJTVE4uNm1GdmtCNUFlckc0RUZMR29hcFYxYXVZQXJuSGsxRlhpd1RkeHRVTnZIdmNxYWQ5MUVwMWE4QXpBNXRkcmdMSlVCNURucVFQdUtDMzFzdmVSWWdWYTU3dmczZ3B0IiwicHViIjoiU1ROLkFQR1dFSFNGZXF4M3dvUVR4NzNMUEJpRTd1czQ5ZHI4VGprR0pwc3J4amdTcmhhRDIiLCJ1aWQiOiJkZmU0NTllOS02MzgwLTQ4NjEtOTVhOC1hYWUyMWNiMTg1OWEifQ";
    private const string EncodedIssuerIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMTdUMTg6NTM6MzUuMzk3NThaIiwiaWF0IjoiMjAyMi0xMC0xN1QxODo1MzozNS4zOTc1OFoiLCJpc3MiOiJjZWRmMmI2YS0yOWUyLTQ0ZTUtOTYxYS1jNDczZTRiNTYzNzgiLCJwdWIiOiJTVE4uQVBHV0VIU0ZlcXgzd29RVHg3M0xQQmlFN3VzNDlkcjhUamtHSnBzcnhqZ1NyaGFEMiIsInN1YiI6IjNiMDFkNzIyLWU2NmItNDY4My1hNWI2LTkzZGM2ZTYwZTAxNyIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiZjhkN2RlODUtNzFiNS00ZDM4LWIwZWYtODBlYTZiOTllMGQ2In0.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB4TmxReE9EbzFNem96TlM0ek9UY3hNVGxhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB4TjFReE9EbzFNem96TlM0ek9UY3hNVGxhSWl3aWFYTnpJam9pWkRSaU5qQTRORFl0TURJNE5TMDBOak5qTFdJME5qVXRPV0kzTlRnM016TmhOREZtSWl3aWNIVmlJam9pVTFST0xtaGxabGhNYTFWVFJuWkJlVkpYZEVWQldHaDJibGxIUzJWaGRGTTRXRlZxZG1Gdk9XTmpkbEpDVWtWaWJ6SnpSa2dpTENKemRXSWlPaUpqWldSbU1tSTJZUzB5T1dVeUxUUTBaVFV0T1RZeFlTMWpORGN6WlRSaU5UWXpOemdpTENKemVYTWlPaUpwYnk1a2FXMWxabTl5YldGMExuSmxaaUlzSW5WcFpDSTZJbVE0TVRNNE4yTXpMV0V6TWprdE5ETmpNQzA1TURVNUxXSmhNMkZsWmpWbE9XVmtaU0o5Lk5qRXdZbUUyTkdRME16RmlaR0kyWVM0ek5XSXlOamcwTnpKbE5XSmxNV013WTJRek1EUXdNamRoTnpOa016Z3pNbVF5TnpSaU1XWTFaR1JpWm1JMFpHTmhPR1JoTXpreU1qY3hPREJsTVRWbE9XWTRZV1V4WTJJMFpqbGxaVEpsTVdaaFlqZ3laRFE0WldFd1l6Z3dNMlkwTVRJelpUZ3lNbUkwTXpsbU56QTRZamN3TnpZeFlUTXhZMlEzTlRnd01B.NDFjNjlmZDZkYzk5NjkyOC5mZGIxMWFjMDgxNGY5YzIxMzYxY2VhZGY4YmViN2M2Mjc0ZTU3MmYyNjI4NWUwNjY3NTdlYjAwYTcxNTQ3ZmM1ODhhZWQ0ODg4MjE1YWJlMGY4Nzk2NTczMDRmZDZhZGZiZGExMDExMjlmNzFjYzlmOGFhZWYzYzgxNGNiNGEwNQ";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;
    #endregion

    #region -- AUDIENCE IDENTITY (RECEIVER) --

    private const string EncodedAudienceKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTE3VDE4OjUzOjM1LjM5ODAxOVoiLCJrZXkiOiJTVE4uajhxeldKazlTb285TnJXaFpMYjl2YU1qQ3BvRmE0R1NWb0hidXJMckNOREFvemlDTmNiRkF4Z3h3VE5zQXBLaVA2c2VKYWpWSGFDYXlLZ1VLM1ZNTnhEOWM0RVciLCJwdWIiOiJTVE4uTGlMZ0FCN0p5cVVLcHplZ2tETkJ6MmNiYTc2ejhuZTFrV2tiYUF5eXRrblV4Q2thZSIsInVpZCI6ImQ3YjhhYWU3LTkyM2EtNGU3MS1hZjQyLTQ4ZjBjYWZlOWMzOSJ9";
    private const string EncodedAudienceIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMTdUMTg6NTM6MzUuMzk4MjE0WiIsImlhdCI6IjIwMjItMTAtMTdUMTg6NTM6MzUuMzk4MjE0WiIsImlzcyI6ImNlZGYyYjZhLTI5ZTItNDRlNS05NjFhLWM0NzNlNGI1NjM3OCIsInB1YiI6IlNUTi5MaUxnQUI3SnlxVUtwemVna0ROQnoyY2JhNzZ6OG5lMWtXa2JhQXl5dGtuVXhDa2FlIiwic3ViIjoiOGZkZGMyNDItNjcwZS00YzczLTg0YmUtODI3NjFhMzkyN2VmIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiIxMTdmY2Q3MC0wZWUwLTRjZTAtYmQ3OC1kOTdjMjk1YjczODAifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB4TmxReE9EbzFNem96TlM0ek9UY3hNVGxhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB4TjFReE9EbzFNem96TlM0ek9UY3hNVGxhSWl3aWFYTnpJam9pWkRSaU5qQTRORFl0TURJNE5TMDBOak5qTFdJME5qVXRPV0kzTlRnM016TmhOREZtSWl3aWNIVmlJam9pVTFST0xtaGxabGhNYTFWVFJuWkJlVkpYZEVWQldHaDJibGxIUzJWaGRGTTRXRlZxZG1Gdk9XTmpkbEpDVWtWaWJ6SnpSa2dpTENKemRXSWlPaUpqWldSbU1tSTJZUzB5T1dVeUxUUTBaVFV0T1RZeFlTMWpORGN6WlRSaU5UWXpOemdpTENKemVYTWlPaUpwYnk1a2FXMWxabTl5YldGMExuSmxaaUlzSW5WcFpDSTZJbVE0TVRNNE4yTXpMV0V6TWprdE5ETmpNQzA1TURVNUxXSmhNMkZsWmpWbE9XVmtaU0o5Lk5qRXdZbUUyTkdRME16RmlaR0kyWVM0ek5XSXlOamcwTnpKbE5XSmxNV013WTJRek1EUXdNamRoTnpOa016Z3pNbVF5TnpSaU1XWTFaR1JpWm1JMFpHTmhPR1JoTXpreU1qY3hPREJsTVRWbE9XWTRZV1V4WTJJMFpqbGxaVEpsTVdaaFlqZ3laRFE0WldFd1l6Z3dNMlkwTVRJelpUZ3lNbUkwTXpsbU56QTRZamN3TnpZeFlUTXhZMlEzTlRnd01B.NDFjNjlmZDZkYzk5NjkyOC45ZmQzMGYwMGI1ZWE2ZWMxOTBkZTU4Zjc1NThjZjRjNWYwZGU1YWU1NDk0M2M2ZjhmZGRkM2RhOWRjYjI4MjNhMTUyMWI2YzU0ZTBmYWJkMzU3NWNhMGVmMGU0MTI1ZmRhOTEyZDU5YWM2OWIzZDEzNGUxMTVlMjg2YWFhMmIwYQ";
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