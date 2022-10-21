//
//  DimeTest.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Text;
using DiME;
using DiME.Capability;
using DiME.KeyRing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DiME_test;

[TestClass]
public class DimeTest
{
    
    [TestInitialize]
    public void BeforeAll()
    {
        Dime.GracePeriod = 0L;
        Dime.TimeModifier = 0L;
    }
    
    [TestMethod]
    public void VersionTest1() 
    {
        Assert.AreEqual(1, Dime.Version);
    }
    
    [TestMethod]
    public void GlobalsTest1() 
    {
        Assert.AreEqual(-1L, Dime.NoExpiration);
        Assert.AreEqual(60L, Dime.ValidFor1Minute);
        Assert.AreEqual(3600L, Dime.ValidFor1Hour);
        Assert.AreEqual(86400L, Dime.ValidFor1Day);
        Assert.AreEqual(31536000L, Dime.ValidFor1Year);
        Assert.AreEqual(84, Dime.MaxContextLength);
    }
    
    [TestMethod]
    public void SetTimeModifierTest1() {
        Dime.TimeModifier = 0L;
        Assert.AreEqual(0L, Dime.TimeModifier);
        Dime.TimeModifier = 10L;
        Assert.AreEqual(10L, Dime.TimeModifier);
    }

    [TestMethod]
    public void CreateDateTimeTest1() {
        Dime.TimeModifier = 0L;
        var reference = DateTime.UtcNow;
        var timestamp = Utility.CreateDateTime();
        var duration = timestamp - reference;
        Assert.AreEqual(0L, duration.Seconds);
    }

    [TestMethod]
    public void CreateDateTimeTest2() {
        var reference = DateTime.UtcNow;
        Dime.TimeModifier = 10L;
        var timestamp = Utility.CreateDateTime();
        var duration = timestamp - reference;
        Assert.AreEqual(10L, duration.Seconds);
    }

    [TestMethod]
    public void CreateDateTimeTest3() {
        var reference = Utility.CreateDateTime();
        Dime.TimeModifier = -10L;
        var timestamp = Utility.CreateDateTime();
        var duration = reference - timestamp;
        Assert.IsTrue(duration.Seconds >= 9L && duration.Seconds <= 10L);
    }

    [TestMethod]
    public void CreateDateTimeTest4() {
        var reference = DateTime.UtcNow.AddSeconds(-2L);
        Dime.TimeModifier = -2L;
        var timestamp = Utility.CreateDateTime();
        var duration = timestamp - reference;
        Assert.AreEqual(0L, duration.Seconds);
    }

    [TestMethod]
    public void GracefulDateTimeCompareTest1() 
    {
        Dime.GracePeriod = 2L;
        var now = DateTime.UtcNow;
        var remoteTimestamp1 = now.AddSeconds(-2L);
        var result = Utility.GracefulDateTimeCompare(now, remoteTimestamp1);
        Assert.AreEqual(0, result);
        var remoteTimestamp2 = now.AddSeconds(2L);
        result = Utility.GracefulDateTimeCompare(now, remoteTimestamp2);
        Assert.AreEqual(0, result);
    }

    [TestMethod]
    public void GracefulDateTimeCompareTest2() 
    {
        Dime.GracePeriod = 1L;
        var now = DateTime.UtcNow;
        var remoteTimestamp1 = now.AddSeconds(-2L);
        var result = Utility.GracefulDateTimeCompare(Utility.CreateDateTime(), remoteTimestamp1);
        Assert.AreEqual(1, result);
        var remoteTimestamp2 = now.AddSeconds(2L);
        result = Utility.GracefulDateTimeCompare(now, remoteTimestamp2);
        Assert.AreEqual(-1, result);
    }

    [TestMethod]
    public void GracefulDateTimeCompareTest3() 
    {
        Dime.GracePeriod = 2L;
        var iat = DateTime.Parse("2022-01-01T23:43:34.8755323Z").ToUniversalTime();
        var exp = DateTime.Parse("2022-01-01T23:43:32.8755323Z").ToUniversalTime();
        var res = DateTime.Parse("2022-01-01T23:43:33.968000Z").ToUniversalTime();
        var now = DateTime.Parse("2022-01-01T23:43:33.052000Z").ToUniversalTime();
        Assert.IsTrue(Utility.GracefulDateTimeCompare(iat, now) <= 0); // checks so it passes
        Assert.IsTrue(Utility.GracefulDateTimeCompare(res, now) <= 0); // checks so it passes
        Assert.IsTrue(Utility.GracefulDateTimeCompare(exp, now) >= 0); // checks so it passes
        // Issued at and expires at are created by same entity and should not be compared with grace period
        Dime.GracePeriod = 0L;
        Assert.IsTrue(Utility.GracefulDateTimeCompare(iat, exp) > 0); // check so it fails
    }

    [TestMethod]
    public void GracefulDateTimeCompareTest4() 
    {
        Dime.GracePeriod = 1L;
        Assert.AreEqual(0, Utility.GracefulDateTimeCompare(null, DateTime.UtcNow));
        Assert.AreEqual(0, Utility.GracefulDateTimeCompare(DateTime.UtcNow, null));
    }

    [TestMethod]
    public void JsonCanonicailzerTest1()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, Dime.ValidFor1Minute, Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Commons.Context);
        var encoded = key.Export();
        var claims = new List<string>() { Claim.Cap.ToString().ToLower(), 
            Claim.Ctx.ToString().ToLower(), 
            Claim.Exp.ToString().ToLower(), 
            Claim.Iat.ToString().ToLower(), 
            Claim.Iss.ToString().ToLower(), 
            Claim.Key.ToString().ToLower(), 
            Claim.Pub.ToString().ToLower(), 
            Claim.Uid.ToString().ToLower() };
        var jsonString = Encoding.UTF8.GetString(Utility.FromBase64(encoded.Split(".")[1]));
        var previousIndex = 0;
        foreach (var claim in claims)
        {
            var foundIndex = jsonString.IndexOf(claim, StringComparison.Ordinal);
            Assert.IsTrue(previousIndex < foundIndex);
            previousIndex = foundIndex;
        }
    }
    
    // LEGACY TESTS //

    private const string LegacyTrustedIdentity = "Di:ID.eyJ1aWQiOiI0MDViZDZhOC0wM2JmLTRjNDctOWNiYS0xNmNhODM5OGI1YzgiLCJzdWIiOiIxZmNkNWY4OC00YTc1LTQ3OTktYmQ0OC0yNWI2ZWEwNjQwNTMiLCJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJpc3MiOiIxZmNkNWY4OC00YTc1LTQ3OTktYmQ0OC0yNWI2ZWEwNjQwNTMiLCJzeXMiOiJkaW1lLWphdmEtcmVmIiwiZXhwIjoiMjAzMS0xMS0xOFQxMjoxMTowMi43NjEwMDdaIiwicHViIjoiMlREWGRvTnZaUldoVUZYemVQam5nanlpbVlMUXNFWVl3ekV6ZDJlNjJqeHdGNHJkdTQzdml4bURKIiwiaWF0IjoiMjAyMS0xMS0yMFQxMjoxMTowMi43NjEwMDdaIn0.KE3hbTLB7+BzzEeGSFyauy2PMgXBIYpGqRFZ2n+xQQsAOxC45xYgeFvILtqLeVYKA8T5lcQvZdyuiHBPVMpxBw";

    [TestMethod]
    public void LegacyIdentityIssuingRequestImportTest1() 
    {
        const string exported = "Di:IIR.eyJ1aWQiOiIzZTViZGU0YS02Mjc3LTRkYTUtODY2NC0xZDNmMDQzYTkwMjgiLCJjYXAiOlsiZ2VuZXJpYyJdLCJwdWIiOiIyVERYZG9OdlNVTnlMRFNVaU1ocExDZEViRGF6NXp1bUQzNXRYMURBdUE4Q0U0MXhvREdnU2QzVUUiLCJpYXQiOiIyMDIxLTExLTE4VDEyOjAzOjUzLjM4MTY2MVoifQ.13/fVQLNOMbnHQXIE//T9PWnE0reDR0LVJUugy3SZ8J7g68idwutFqEGUiTwlPz/t0Ci1IU46kI+ftA83cc2AA";
        var iir = Item.Import<IdentityIssuingRequest>(exported);
        Assert.IsNotNull(iir);
        Assert.AreEqual(Guid.Parse("3e5bde4a-6277-4da5-8664-1d3f043a9028"), iir.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(DateTime.Parse("2021-11-18T12:03:53.381661Z").ToUniversalTime(), iir.GetClaim<DateTime>(Claim.Iat));
        Assert.IsTrue(iir.WantsCapability(IdentityCapability.Generic));
        Assert.IsNotNull(iir.PublicKey);
        Assert.AreEqual("2TDXdoNvSUNyLDSUiMhpLCdEbDaz5zumD35tX1DAuA8CE41xoDGgSd3UE", iir.PublicKey.Public);
        Assert.AreEqual(IntegrityState.Complete, iir.Verify(iir.PublicKey));
    }

    [TestMethod]
    public void LegacyIdentityImportTest1() 
    {
        Commons.ClearKeyRing();
        Dime.KeyRing.Put(Item.Import<Identity>(LegacyTrustedIdentity));
        const string legacyExported = "Di:ID.eyJ1aWQiOiIyYTdkNDJhMy02YjQ1LTRhNGEtYmIzZC1lYzk0ZWMzNzlmMWYiLCJzdWIiOiJiZTRhZjVmMy1lODM4LTQ3MzItYTBmYy1mZmEyYzMyOGVhMTAiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6ImJkMjhkYjhmLTEzNjItNGFmZC1hZWQ3LTRjYTM5ZjY1OTc1ZSIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIyLTExLTIwVDEyOjExOjAyLjc2NTI1OVoiLCJwdWIiOiIyVERYZG9OdzF3WlF0ZVU1MzI1czZSbVJYVnBUa1lXdlR1RXpSMWpOZFZ2WWpFUjZiNmJZYUR6dEYiLCJpYXQiOiIyMDIxLTExLTIwVDEyOjExOjAyLjc2NTI1OVoifQ.SUQuZXlKMWFXUWlPaUl5TTJRNVpXUmtaaTFtWXpoa0xUUmpNemN0WW1NNU1pMDNNVFF6TkRVMFlUSTBaRFVpTENKemRXSWlPaUppWkRJNFpHSTRaaTB4TXpZeUxUUmhabVF0WVdWa055MDBZMkV6T1dZMk5UazNOV1VpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pTVdaalpEVm1PRGd0TkdFM05TMDBOems1TFdKa05EZ3RNalZpTm1WaE1EWTBNRFV6SWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNall0TVRFdE1UbFVNVEk2TVRFNk1ESXVOell6TmpVeVdpSXNJbkIxWWlJNklqSlVSRmhrYjA1MlJEaGpRemwxZUZOaU5FcEdTSEpyTVdaUVNGZDNjWEZUUTFWS1IyVTRWbWRXUm5OaFZ6VkxjVVl5ZDJ0WVlsVlFUaUlzSW1saGRDSTZJakl3TWpFdE1URXRNakJVTVRJNk1URTZNREl1TnpZek5qVXlXaUo5LjU2djVMeVg4anRLQ3N0eTdnbTZOczJjWStiTUlYNHBxNDRnODBTRXB1NjF2QklzUlZ6UTFOZFY5Q1BXaHRTdHZEM3d3N01hOFg3QlZvMWxrMjZjMkRn.7H3RwTTeDcI3pGMIWMPbAjpDnCN2O91JG4lKu3JJbxlLNwTbgTB/03xrwi28wl0iMReJ4zUPc3cCqbymAlxwAw";
        var identity =  Item.Import<Identity>(legacyExported);
        Assert.IsNotNull(identity);
        Assert.AreEqual("dime-java-ref", identity.GetClaim<string>(Claim.Sys));
        Assert.AreEqual(Guid.Parse("2a7d42a3-6b45-4a4a-bb3d-ec94ec379f1f"), identity.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(Guid.Parse("be4af5f3-e838-4732-a0fc-ffa2c328ea10"), identity.GetClaim<Guid>(Claim.Sub));
        Assert.AreEqual(DateTime.Parse("2021-11-20T12:11:02.765259Z").ToUniversalTime(), identity.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual(DateTime.Parse("2022-11-20T12:11:02.765259Z").ToUniversalTime(), identity.GetClaim<DateTime>(Claim.Exp));
        Assert.AreEqual(Guid.Parse("bd28db8f-1362-4afd-aed7-4ca39f65975e"), identity.GetClaim<Guid>(Claim.Iss));
        Assert.IsNotNull(identity.PublicKey);
        Assert.AreEqual("2TDXdoNw1wZQteU5325s6RmRXVpTkYWvTuEzR1jNdVvYjER6b6bYaDztF", identity.PublicKey.Public);
        Assert.IsTrue(identity.HasCapability(IdentityCapability.Generic));
        Assert.IsTrue(identity.HasCapability(IdentityCapability.Identify));
        Assert.IsNotNull(identity.TrustChain);
        Assert.AreEqual(IntegrityState.Complete, identity.Verify());
    }

    [TestMethod]
    public void LegacyKeyImport1() 
    {
        const string exported = "Di:KEY.eyJ1aWQiOiIzZjAwY2QxMy00NDc0LTRjMDQtOWI2Yi03MzgzZDQ5MGYxN2YiLCJwdWIiOiJTMjFUWlNMMXV2RjVtVFdLaW9tUUtOaG1rY1lQdzVYWjFWQmZiU1BxbXlxRzVHYU5DVUdCN1BqMTlXU2h1SnVMa2hSRUVKNGtMVGhlaHFSa2FkSkxTVEFrTDlEdHlobUx4R2ZuIiwiaWF0IjoiMjAyMS0xMS0xOFQwODo0ODoyNS4xMzc5MThaIiwia2V5IjoiUzIxVGtnb3p4aHprNXR0RmdIaGdleTZ0MTQxOVdDTVVVTTk4WmhuaVZBamZUNGluaVVrbmZVck5xZlBxZEx1YTJTdnhGZjhTWGtIUzFQVEJDcmRrWVhONnFURW03TXdhMkxSZCJ9";
        var key =  Item.Import<Key>(exported);
        Assert.IsNotNull(key);
        Assert.IsTrue(key.HasCapability(KeyCapability.Sign));
        Assert.AreEqual(Guid.Parse("3f00cd13-4474-4c04-9b6b-7383d490f17f"), key.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(DateTime.Parse("2021-11-18T08:48:25.137918Z").ToUniversalTime(), key.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual("S21Tkgozxhzk5ttFgHhgey6t1419WCMUUM98ZhniVAjfT4iniUknfUrNqfPqdLua2SvxFf8SXkHS1PTBCrdkYXN6qTEm7Mwa2LRd", key.Secret);
        Assert.AreEqual("S21TZSL1uvF5mTWKiomQKNhmkcYPw5XZ1VBfbSPqmyqG5GaNCUGB7Pj19WShuJuLkhREEJ4kLThehqRkadJLSTAkL9DtyhmLxGfn", key.Public);
    }

    [TestMethod] 
    public void LegacyKeyExportImport1() 
    {
        var exportKey = Key.Generate(KeyCapability.Sign);
        Assert.IsFalse(exportKey.IsLegacy);
        exportKey.ConvertToLegacy();
        Assert.IsTrue(exportKey.IsLegacy);
        var encoded = exportKey.Export();
        var importKey =  Item.Import<Key>(encoded);
        Assert.IsNotNull(importKey);
        Assert.IsTrue(importKey.IsLegacy);
        Assert.IsTrue(importKey.Public.StartsWith("2TD"));
    }

    [TestMethod] 
    public void LegacyMessageImport1() 
    {
        const string exported = "Di:MSG.eyJ1aWQiOiIwY2VmMWQ4Zi01NGJlLTRjZTAtYTY2OS1jZDI4OTdhYzY0ZTAiLCJhdWQiOiJhNjkwMjE4NC0yYmEwLTRiYTAtYWI5MS1jYTc3ZGE3ZDA1ZDMiLCJpc3MiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJleHAiOiIyMDIxLTExLTE4VDE4OjA2OjAyLjk3NDM5NVoiLCJpYXQiOiIyMDIxLTExLTE4VDE4OjA1OjUyLjk3NDM5NVoifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.vWWk/1Ny6FzsVRNSEsqjhRrSEDvmbfLIE9CmADySp/pa3hqNau0tnhwH3YwRPPEpSl4wXpw0Uqkf56EQJI2TDQ";
        var message =  Item.Import<Message>(exported);
        Assert.IsNotNull(message);
        Assert.AreEqual(Guid.Parse("0cef1d8f-54be-4ce0-a669-cd2897ac64e0"), message.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(Guid.Parse("a6902184-2ba0-4ba0-ab91-ca77da7d05d3"), message.GetClaim<Guid>(Claim.Aud));
        Assert.AreEqual(Guid.Parse("0aa56133-78b0-4dd9-928d-5d7ff9da5445"), message.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message.GetPayload()));
        Assert.AreEqual(DateTime.Parse("2021-11-18T18:05:52.974395Z").ToUniversalTime(), message.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual(DateTime.Parse("2021-11-18T18:06:02.974395Z").ToUniversalTime(), message.GetClaim<DateTime>(Claim.Exp));
    }

    [TestMethod] 
    public void LegacyKeyConvertToLegacyTest1() 
    {
        var key = Key.Generate(KeyCapability.Sign);
        var message = new Message(Guid.NewGuid());
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(key);
        var currentExport = key.Export();
        Assert.IsNotNull(currentExport);
        key.ConvertToLegacy();
        var legacyExport = key.Export();
        Assert.IsNotNull(legacyExport);
        var legacyKey = Item.Import<Key>(legacyExport);
        Assert.IsNotNull(legacyKey);
        Assert.IsTrue(legacyKey.IsLegacy);
        message.Verify(legacyKey);
    }

    [TestMethod] 
    public void LegacyIirConvertToLegacyTest1() 
    {
        Key key = Key.Generate(KeyCapability.Sign);
        IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(key);
        String exported = iir.Export();
        Assert.IsNotNull(exported);
        iir.Strip();
        iir.ConvertToLegacy();
        iir.Sign(key);
        Assert.IsTrue(iir.IsLegacy);
        var legacyExported = iir.Export();
        Assert.IsNotNull(legacyExported);
    }

    [TestMethod]
    public void LegacyIirConvertToLegacyTest2() {
        var key = Key.Generate(KeyCapability.Sign);
        key.ConvertToLegacy();
        var iir = IdentityIssuingRequest.Generate(key);
        Assert.IsTrue(iir.IsLegacy);
        Assert.IsNotNull(iir.PublicKey);
        Assert.IsTrue(iir.PublicKey.Public.StartsWith("2TD"));
    }

    [TestMethod]
    public void LegacyIdentityImportTest2() {
        const string exported = "Di:ID.eyJzeXMiOiJkaW1lLWRvdG5ldC1yZWYiLCJ1aWQiOiI1NjZkYjliZC03M2Q5LTQ0NmMtODlmZC00ZmU2OTA3NDk3Y2UiLCJzdWIiOiI1MjNiZWZmNC1mYzE1LTRiNzctODNiNC05NzdkNWY1YzZkYTEiLCJpc3MiOiJlODQ5YWQ5OS05YWM4LTQ2ZTktYjUyNS1lZWNiMWEwNjE3NDUiLCJpYXQiOiIyMDIyLTA2LTAyVDE3OjQ0OjU2LjgyNDA4N1oiLCJleHAiOiIyMDIyLTA2LTAyVDE5OjA4OjE2LjgyNDA4N1oiLCJwdWIiOiIyVERYZG9OdzVrOHJpZlVwV3ROMjFKdlJhUHRlcjJ6amIxMjJ6ZHdxOTVnZWJxRHhQM2pZZlhLcWEiLCJjYXAiOlsiZ2VuZXJpYyJdfQ.SUQuZXlKemVYTWlPaUprYVcxbExXUnZkRzVsZEMxeVpXWWlMQ0oxYVdRaU9pSTNNV1k1TkdGa055MDNaakF6TFRRMk5EVXRPVEl3WWkwd1pEaGtPV0V5WVRGa01XSWlMQ0p6ZFdJaU9pSmxPRFE1WVdRNU9TMDVZV000TFRRMlpUa3RZalV5TlMxbFpXTmlNV0V3TmpFM05EVWlMQ0pwYzNNaU9pSTRNVGN4TjJWa09DMDNOMkZsTFRRMk16TXRZVEE1WVMwMllXTTFaRGswWldZeU9HUWlMQ0pwWVhRaU9pSXlNREl4TFRFeUxUQXlWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0psZUhBaU9pSXlNREkyTFRFeUxUQXhWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0p3ZFdJaU9pSXlWRVJZWkc5T2RsWnpSMVpJT0VNNVZWcDFaSEJpUW5aV1Uwc3hSbVZwTlhJMFdWUmFUWGhoUW1GNmIzTnZNbkJNY0ZCWFZFMW1ZMDRpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLjc5SjlldTNxZXJqMW4xdEpSaUJQenNURHNBNWlqWG41REs3ZlVuNEpRcmhzZUJXN0lrYWRBekNFRGtQcktoUG1lMGtzanVhMjhUQitVTGh4bGEybkNB.AIdmgrX5nsOD8Uo5wdS2tUzcNqTeyG2f8XlCxO20jn+7DSqABMREBqBPlFTD9oO4jcWNDAV4oE2hVaPN+PwFDA";
        var identity =  Item.Import<Identity>(exported);
        Assert.IsNotNull(identity);
        Assert.IsTrue(identity.IsLegacy);
        Assert.IsNotNull(identity.PublicKey);
        var pub = identity.PublicKey.Public;
        Assert.IsNotNull(pub);
        Assert.IsFalse(pub.StartsWith(Dime.Crypto.DefaultSuiteName));
    }

    [TestMethod] 
    public void LegacySelfIssueTest1() {
        var key = Key.Generate(KeyCapability.Sign);
        key.ConvertToLegacy();
        var iir = IdentityIssuingRequest.Generate(key);
        var identity = iir.SelfIssue(Guid.NewGuid(), Dime.ValidFor1Minute, key, Commons.SystemName);
        Assert.IsTrue(identity.IsLegacy);
        Assert.IsNotNull(identity.PublicKey);
        Assert.IsTrue(identity.PublicKey.Public.StartsWith("2TD"));
    }
    
}