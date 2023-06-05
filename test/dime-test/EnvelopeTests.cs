//
//  EnvelopeTests.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using DiME;
using DiME.Capability;

namespace DiME_test;

[TestClass]
public class EnvelopeTests
{
    
    [TestMethod]
    public void GetHeaderTest1() 
    {
        var envelope = new Envelope();
        Assert.AreEqual("Di", envelope.Header);
        Assert.AreEqual("Di", Envelope.ItemHeader);
    }

    [TestMethod]
    public void ClaimTest1() 
    {
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), envelope.GetClaim<Guid>(Claim.Iss));
    }

    [TestMethod]
    public void ClaimTest2() 
    {
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Commons.Context);
        Assert.AreEqual(Commons.Context, envelope.GetClaim<string>(Claim.Ctx));
        envelope.RemoveClaim(Claim.Ctx);
        Assert.AreEqual(default, envelope.GetClaim<string>(Claim.Ctx));
    }

    [TestMethod]
    public void ClaimTest3() 
    {
        var envelope = new Envelope();
        envelope.PutClaim(Claim.Amb, new List<string>() { "one", "two" });
        Assert.IsNotNull(envelope.GetClaim<List<string>>(Claim.Amb));
        envelope.PutClaim(Claim.Aud, Guid.NewGuid());
        Assert.IsNotNull(envelope.GetClaim<Guid>(Claim.Aud));
        Assert.AreNotEqual(default, envelope.GetClaim<Guid>(Claim.Aud));
        envelope.PutClaim(Claim.Ctx, Commons.Context);
        Assert.IsNotNull(envelope.GetClaim<string>(Claim.Ctx));
        envelope.PutClaim(Claim.Exp, DateTime.UtcNow);
        Assert.IsNotNull(envelope.GetClaim<DateTime>(Claim.Exp));
        Assert.AreNotEqual(default, envelope.GetClaim<DateTime>(Claim.Exp));
        envelope.PutClaim(Claim.Iat, DateTime.UtcNow);
        Assert.IsNotNull(envelope.GetClaim<DateTime>(Claim.Iat));
        Assert.AreNotEqual(default, envelope.GetClaim<DateTime>(Claim.Iat));
        envelope.PutClaim(Claim.Iss, Guid.NewGuid());
        Assert.IsNotNull(envelope.GetClaim<Guid>(Claim.Iss));
        Assert.AreNotEqual(default, envelope.GetClaim<Guid>(Claim.Iss));
        envelope.PutClaim(Claim.Isu, Commons.IssuerUrl);
        Assert.IsNotNull(envelope.GetClaim<string>(Claim.Isu));
        envelope.PutClaim(Claim.Kid, Guid.NewGuid());
        Assert.IsNotNull(envelope.GetClaim<Guid>(Claim.Kid));
        Assert.AreNotEqual(default, envelope.GetClaim<Guid>(Claim.Kid));
        envelope.PutClaim(Claim.Mtd, new List<string>() { "abc", "def" });
        Assert.IsNotNull(envelope.GetClaim<List<string>>(Claim.Mtd));
        envelope.PutClaim(Claim.Sub, Guid.NewGuid());
        Assert.IsNotNull(envelope.GetClaim<Guid>(Claim.Sub));
        Assert.AreNotEqual(default, envelope.GetClaim<Guid>(Claim.Sub));
        envelope.PutClaim(Claim.Sys, Commons.SystemName);
        Assert.IsNotNull(envelope.GetClaim<string>(Claim.Sys));
        envelope.PutClaim(Claim.Uid, Guid.NewGuid());
        Assert.IsNotNull(envelope.GetClaim<Guid>(Claim.Uid));
        Assert.AreNotEqual(default, envelope.GetClaim<Guid>(Claim.Uid));
        try { envelope.PutClaim(Claim.Cap, new List<KeyCapability>() { KeyCapability.Encrypt }); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { envelope.PutClaim(Claim.Key,Commons.IssuerKey.Secret); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { envelope.PutClaim(Claim.Lnk, new ItemLink(Commons.IssuerKey)); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { envelope.PutClaim(Claim.Mim, Commons.Mimetype); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well*/ }
        try { var pri = new Dictionary<string, object>(); pri["tag"] = Commons.Payload; envelope.PutClaim(Claim.Pri, pri); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { envelope.PutClaim(Claim.Pub, Commons.IssuerKey.Public); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
    }

    [TestMethod]
    public void ClaimTest4() 
    {
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        envelope.AddItem(Commons.IssuerKey.PublicCopy());
        envelope.Sign(Commons.IssuerKey);
        try { envelope.RemoveClaim(Claim.Iss); Assert.IsTrue(false, "Exception not thrown."); } catch (InvalidOperationException) { /* all is well */ }
        try { envelope.PutClaim(Claim.Exp, DateTime.UtcNow); } catch (InvalidOperationException) { /* all is well */ }
    }

    [TestMethod]
    public void ClaimTest5() 
    {
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        envelope.AddItem(Commons.IssuerKey.PublicCopy());
        envelope.Sign(Commons.IssuerKey);
        envelope.Strip();
        envelope.RemoveClaim(Claim.Iss);
        envelope.PutClaim(Claim.Iat, DateTime.UtcNow);
    }
    
    [TestMethod]
    public void GetItemTest1() 
    {
        var message = new Message(Guid.NewGuid(), Guid.NewGuid(), Dime.NoExpiration, Commons.Context);
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, Commons.SignKeyContext);
        var envelope = new Envelope();
        envelope.AddItem(message);
        envelope.AddItem(key);
        // Context
        var item1 = envelope.GetItem(Claim.Ctx, Commons.SignKeyContext);
        Assert.IsNotNull(item1);
        Assert.IsTrue(item1.GetType() == typeof(Key));
        Assert.AreEqual(Commons.SignKeyContext, item1.GetClaim<string>(Claim.Ctx));
        var item2 = envelope.GetItem(Claim.Ctx, Commons.Context);
        Assert.IsNotNull(item2);
        Assert.IsTrue(item2.GetType() == typeof(Message));
        Assert.AreEqual(Commons.Context, item2.GetClaim<string>(Claim.Ctx));
        // Unique ID
        var item3 = envelope.GetItem(Claim.Uid, key.GetClaim<Guid>(Claim.Uid));
        Assert.IsNotNull(item3);
        Assert.IsTrue(item3.GetType() == typeof(Key));
        Assert.AreEqual(key.GetClaim<Guid>(Claim.Uid), item3.GetClaim<Guid>(Claim.Uid));
        var item4 = envelope.GetItem(Claim.Uid, message.GetClaim<Guid>(Claim.Uid));
        Assert.IsNotNull(item4);
        Assert.IsTrue(item4.GetType() == typeof(Message));
        Assert.AreEqual(message.GetClaim<Guid>(Claim.Uid), item4.GetClaim<Guid>(Claim.Uid));
    }
    
    [TestMethod]
    public void GetItemTest2() 
    {
        const string exported = "Di:MSG.eyJhdWQiOiJiMWZiMmVhOC1jNThiLTQ0MjktYjRjNC1lODgxMWI4YzIyM2UiLCJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJpYXQiOiIyMDIyLTEwLTIxVDIwOjM5OjQ3LjEwMzE1M1oiLCJpc3MiOiI4NWFiYTMzYS1hYjJmLTQ5NDktOTNmOS0zNDBjNTI3YzdjZDQiLCJ1aWQiOiI4NjAwODNiNS0wZTIzLTQ4N2UtOTE5ZS01NTdjNWEyZTZjMmYifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.MzFhMDYyN2JlZjk1NjNiZC5hZjY3ZDc5NWRiMzRjNTgzYzIxZjA2NjQ5OGVhZGJlYzQzMDQ3MzJjMTBhMzliZTFjNzM5MWE4YmMxYzM1ZDgxMGI0ZjRiNjU4ZTRjMDZlMjdlNmM2OTdiOTU3OWQ0NzZkYjFjMjc1MDRjZDMyYjhmOTE2YWNiYzRmNTk0MDQwZQ:KEY.eyJjYXAiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTEwLTIxVDIwOjM5OjQ3LjE1MjM1NFoiLCJrZXkiOiJTVE4uZWhleU1ZaXFpZkNXcnNqVFdQNlpGYm9OZ0NiZENFbm9hbVlYcHZ1aW1MUkM5WVF1YTdVbnRnZDlKMXNrelFmOGpxUVM1M24yTFNndW83RGc3NlBRc1JyNXJUbVAiLCJwdWIiOiJTVE4uVUNTNlVZemNYWVozNjRXOE1FaVB0dFFuS0s3RzlwY0pRZ0ozMkZZd3RUaDN5N203VSIsInVpZCI6ImU1MTExOGNmLTdkYTktNDRhMi04ZGIxLWQ5YWM3ZTNlN2QxNSJ9";
        var envelope = Envelope.Import(exported);
        // Context
        var item1 = envelope.GetItem(Claim.Ctx, Commons.SignKeyContext);
        Assert.IsNotNull(item1);
        Assert.IsTrue(item1.GetType() == typeof(Key));
        Assert.AreEqual(Commons.SignKeyContext, item1.GetClaim<string>(Claim.Ctx));
        var item2 = envelope.GetItem(Claim.Ctx, Commons.Context);
        Assert.IsNotNull(item2);
        Assert.IsTrue(item2.GetType() == typeof(Message));
        Assert.AreEqual(Commons.Context, item2.GetClaim<string>(Claim.Ctx));
        // Unique ID
        var uid1 = Guid.Parse("e51118cf-7da9-44a2-8db1-d9ac7e3e7d15");
        var item3 = envelope.GetItem(Claim.Uid, uid1);
        Assert.IsTrue(item3 is Key);
        Assert.AreEqual(uid1, item3.GetClaim<Guid>(Claim.Uid));
        var uid2 = Guid.Parse("860083b5-0e23-487e-919e-557c5a2e6c2f");
        var item4 = envelope.GetItem(Claim.Uid, uid2);
        Assert.IsTrue(item4 is Message);
        Assert.AreEqual(uid2, item4.GetClaim<Guid>(Claim.Uid));
    }
    
    [TestMethod]
    public void GetItemTest3() 
    {
        var envelope = new Envelope();
        envelope.AddItem(Key.Generate(KeyCapability.Sign));
        Assert.IsNull(envelope.GetItem(Claim.Ctx, ""));
        Assert.IsNull(envelope.GetItem(Claim.Ctx, "invalid-context"));
        Assert.IsNull(envelope.GetItem(Claim.Uid, Guid.NewGuid()));
        Assert.IsNull(envelope.GetItem(Claim.Uid, default(Guid)));
    }

    [TestMethod]
    public void SetItemsTest1()
    {
        var envelope = new Envelope();
        Assert.AreEqual(0, envelope.Items.Count);
        envelope.SetItems(new List<Item>
            { Commons.IssuerIdentity, Commons.IssuerKey, Commons.AudienceIdentity, Commons.AudienceKey });
        Assert.AreEqual(4, envelope.Items.Count);
        envelope.SetItems(new List<Item>
            { Commons.TrustedIdentity, Commons.IntermediateIdentity });
        Assert.AreEqual(2, envelope.Items.Count);
    }
    
    [TestMethod]
    public void SetItemsTest2()
    {
        var envelope = new Envelope();
        envelope.SetItems(new List<Item>
            { Commons.IssuerIdentity, Commons.IssuerKey, Commons.AudienceIdentity, Commons.AudienceKey });
        envelope.Sign(Commons.IssuerKey);
        try {
            envelope.SetItems(new List<Item> { Commons.TrustedIdentity, Commons.IntermediateIdentity });
        } catch (InvalidOperationException) { return; } // All is well
    }
    
    [TestMethod]
    public void SignTest1()
    {
        var envelope = new Envelope();
        try {
            envelope.Sign(Commons.IssuerKey);
        } catch (InvalidOperationException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }

    [TestMethod]
    public void SignTest2()
    {
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        try {
            envelope.Sign(Commons.IssuerKey);
        } catch (InvalidOperationException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }

    [TestMethod]
    public void SignTest3()
    {
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        envelope.AddItem(Commons.IssuerKey);
        envelope.Sign(Commons.IssuerKey);
    }

    [TestMethod]
    public void ContextTest1()
    {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), context);
        Assert.AreEqual(context, envelope.GetClaim<string>(Claim.Ctx));
    }

    [TestMethod]
    public void ContextTest2()
    {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        var envelope1 = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), context);
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 100);
        message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
        message.Sign(Commons.IssuerKey);
        envelope1.AddItem(message);
        envelope1.Sign(Commons.IssuerKey);
        var exported = envelope1.Export();
        var envelope2 = Envelope.Import(exported);
        Assert.AreEqual(context, envelope2.GetClaim<string>(Claim.Ctx));
    }

    [TestMethod]
    public void ContextTest3()
    {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try
        {
            _ = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), context);
        } catch (ArgumentException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }

    [TestMethod]
    public void ThumbprintTest1()
    {
        var envelope = new Envelope();
        envelope.AddItem(Commons.IssuerKey);
        Assert.IsNotNull(envelope.GenerateThumbprint());
    }

    [TestMethod]
    public void ThumbprintTest2()
    {
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        envelope.AddItem(Commons.IssuerKey);
        envelope.Sign(Commons.IssuerKey);
        Assert.IsNotNull(envelope.GenerateThumbprint());
    }

    [TestMethod]
    public void ThumbprintTest3()
    {
        var envelope1 = new Envelope();
        envelope1.AddItem(Commons.IssuerKey);
        var exported = envelope1.Export();
        var envelope2 = Envelope.Import(exported);
        Assert.AreEqual(envelope1.GenerateThumbprint(), envelope2.GenerateThumbprint());
    }

    [TestMethod]
    public void ThumbprintTest4()
    {
        var envelope1 = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        envelope1.AddItem(Commons.IssuerKey);
        envelope1.Sign(Commons.IssuerKey);
        var exported = envelope1.Export();
        var envelope2 = Envelope.Import(exported);
        Assert.AreEqual(envelope1.GenerateThumbprint(), envelope2.GenerateThumbprint());
    }

    [TestMethod]
    public void ThumbprintTest5()
    {
        var envelope = new Envelope();
        envelope.AddItem(Commons.IssuerKey);
        var exported = envelope.Export();
        Assert.AreEqual(envelope.GenerateThumbprint(), Item.Thumbprint(exported));
    }

    [TestMethod]
    public void ThumbprintTest6()
    {
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        envelope.AddItem(Commons.IssuerKey);
        envelope.Sign(Commons.IssuerKey);
        var exported = envelope.Export();
        Assert.AreEqual(envelope.GenerateThumbprint(), Item.Thumbprint(exported));
    }

    [TestMethod]
    public void IirExportTest1()
    {
        var iir = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
        var envelope = new Envelope();
        envelope.AddItem(iir);
        var exported = envelope.Export();
        Assert.IsNotNull(exported);
        Assert.IsTrue(exported.Length > 0);
        Assert.IsTrue(exported.StartsWith(Envelope.ItemHeader));
        Assert.IsTrue(exported.Split(new[] { ':' }).Length == 2);
    }

    [TestMethod]
    public void IirImportTest1()
    {
        const string exported = "Di:IIR.eyJ1aWQiOiI0ZmIxMzgyNC1lZTUyLTQ1ZjYtYmNiZC1kNTk3MDY1NjUwMzgiLCJpYXQiOiIyMDIxLTA4LTExVDA3OjU0OjIwLjc4Mzk3OVoiLCJwdWIiOiIxaFBLUUdwYldFVzFYR0RQbjRKRlJlYkF3QVlYSEs4N1lzOFhTckg3TFY5ZkdaZkZTaVprUSIsImNhcCI6WyJnZW5lcmljIl19.AR7L9NL4v2b9Kaomy//9hgMebtukkCn/M48KdBnMQ6v0lBgKfytiMRBzJJoxIQWtTy77gAcyM0ixfXrV79Y1iAA";
        var envelope = Envelope.Import(exported);
        Assert.IsTrue(envelope.IsAnonymous);
        Assert.AreEqual(default(Guid), envelope.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(1, envelope.Items.Count);
        Assert.AreEqual(typeof(IdentityIssuingRequest), envelope.Items.ElementAt(0).GetType());
    }

    [TestMethod]
    public void IdentityExportTest1()
    {
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        envelope.AddItem(Commons.IssuerIdentity);
        envelope.Sign(Commons.IssuerKey);
        var exported = envelope.Export();
        Assert.IsNotNull(exported);
        Assert.IsTrue(exported.Length > 0);
        Assert.IsTrue(exported.StartsWith(Envelope.ItemHeader));
        Assert.IsTrue(exported.Split(new[] { ':' }).Length == 3);
    }

    [TestMethod]
    public void IdentityExportTest2()
    {
        var envelope = new Envelope();
        envelope.AddItem(Commons.IssuerIdentity);
        var exported = envelope.Export();
        Assert.IsNotNull(exported);
        Assert.IsTrue(exported.Length > 0);
        Assert.IsTrue(exported.StartsWith(Envelope.ItemHeader));
        Assert.IsTrue(exported.Split(new[] { ':' }).Length == 2);
    }

    [TestMethod]
    public void IdentityImportTest1()
    {
        const string exported = "Di.eyJpYXQiOiIyMDIyLTEwLTI0VDIyOjQxOjQ1LjMyMDI1MVoiLCJpc3MiOiIxMDMwNTcyZi02YjgyLTQzNmQtOWQ1MS03OTAyMGU2MmY4NTMifQ:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMjRUMjI6MzU6NDQuMDg1OTUyWiIsImlhdCI6IjIwMjItMTAtMjRUMjI6MzU6NDQuMDg1OTUyWiIsImlzcyI6IjE3NWM2YTI4LTQ2OTktNGNhMy05MWMwLTk1NTU2OWFjOTE2OSIsInB1YiI6IkRTQy52bk8yNEFuMTI1elJmazg1Rm40eHYvZk0vRVExKzAwaDhCbDVra2oyWklRIiwic3ViIjoiMTAzMDU3MmYtNmI4Mi00MzZkLTlkNTEtNzkwMjBlNjJmODUzIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiJhMzZlNTZkZS04ODNjLTRhNGYtODk2Mi1mZWZiNzVhYTRiMDIifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB5TTFReU1qb3pOVG8wTkM0d09EVTBNVGhhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB5TkZReU1qb3pOVG8wTkM0d09EVTBNVGhhSWl3aWFYTnpJam9pWlRCbE5tTmlZVFl0WW1RMFpDMDBOV1JrTFRneU16UXRNRE5oWm1SbFlXVTVNRFJoSWl3aWNIVmlJam9pUkZORExrZFNhVXhEUW5aVVVHcG1NemRYY21ScFdEWXlRbVJZSzNkWVdGUTFRMWQ1U0d0a1kyOTJPR1JNZGtVaUxDSnpkV0lpT2lJeE56VmpObUV5T0MwME5qazVMVFJqWVRNdE9URmpNQzA1TlRVMU5qbGhZemt4TmpraUxDSnplWE1pT2lKcGJ5NWthVzFsWm05eWJXRjBMbkpsWmlJc0luVnBaQ0k2SWpaall6SXlNbU16TFdVMVpHTXROREl5WVMxaU9XWmpMVE13T0dVNFpEYzJaVGM1WWlKOS5aV1ZqT0RnelltWmlOR05oT0RWa01DNHhZVFJpWkRNMU5UZzFOVEZrTUdVeU1ETmxaamRpWW1aall6RmhabU0wTURJek1tWmpOV0V3Tm1JMlpEWmtPRFF4WVdKaU1HTTJNek5qTXpjM05tSmlNemM0TWpSbE1HRTJNbVV6T1dNellqWTFOVE5qT0RNMk1EZ3daVGcxTXpVNE1EZGpNVEppT0RWaU5UWXhZbVkwTjJJeE9XTXlPVEl3TkdNME1UVXdNdw.NDFlNmM2ODI5Y2VmNjdmZS42YmNlMzg2MmJjNWY5NzM2OGFjMTQxMWVmYmIxYTcxN2JiZGVhOGEyODNjZWYzODJjOTAzNTNjOTU2NTEwMjA0MTlkNWU5MzJkNDM4NDNmMmMyYzUyMDE3ZTIzZjYyZjM5MTBmMmExZmZkMjlkYzZiMjZmMTNkZGFmODFhYTEwMQ:YzFmMjczMDUzZDhmZDQ4YS5kODQxMjFmYTMxOTE1MWYwZDQzODI0OGQ1NTU5ZTA3MzA1NDkxODE1MTFkZGYyMTliYmRkMjY0ZmFhN2Q1NTU4ZWVhZjZiNjI2MGQ1YTA5NDM1NTlkYzM1MGRmNjU1Zjg5MjkxOGE0YzFhNDIyMGM0ZDg5MjZlMjIzNzkwNjEwZA";
        var envelope = Envelope.Import(exported);
        Assert.IsFalse(envelope.IsAnonymous);
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), envelope.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(DateTime.Parse("2022-10-24T22:41:45.320251Z").ToUniversalTime(), envelope.GetClaim<DateTime>(Claim.Iat));
        Assert.IsNull(envelope.GetClaim<string>(Claim.Ctx));
        Assert.AreEqual(1, envelope.Items.Count);
        Assert.AreEqual(typeof(Identity), envelope.Items.ElementAt(0).GetType());
        envelope.Verify(Commons.IssuerKey);
    }

    [TestMethod]
    public void IdentityImportTest2()
    {
        const string exported = "Di:ID.eyJzeXMiOiJkaW1lLWRvdG5ldC1yZWYiLCJ1aWQiOiIyYzZmYTYwMS1mOWIyLTQxNGQtOThhNy00YWY5MDVkY2U1NzIiLCJzdWIiOiI1YzhmODBiNS0wNjA2LTRhZjctOGZlMi03MjcxM2VkZDcwMGYiLCJpc3MiOiJlODQ5YWQ5OS05YWM4LTQ2ZTktYjUyNS1lZWNiMWEwNjE3NDUiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjI1OjA4LjA4NzcwM1oiLCJleHAiOiIyMDIyLTEyLTAyVDIyOjI1OjA4LjA4NzcwM1oiLCJwdWIiOiIyVERYZG9OdU1GaThqd0MzRE43WDJacW1aa0ZmNWE3cWV0elhUV0Fmbmt5aDZncnFZUHE5NE5lbm4iLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbExXUnZkRzVsZEMxeVpXWWlMQ0oxYVdRaU9pSTNNV1k1TkdGa055MDNaakF6TFRRMk5EVXRPVEl3WWkwd1pEaGtPV0V5WVRGa01XSWlMQ0p6ZFdJaU9pSmxPRFE1WVdRNU9TMDVZV000TFRRMlpUa3RZalV5TlMxbFpXTmlNV0V3TmpFM05EVWlMQ0pwYzNNaU9pSTRNVGN4TjJWa09DMDNOMkZsTFRRMk16TXRZVEE1WVMwMllXTTFaRGswWldZeU9HUWlMQ0pwWVhRaU9pSXlNREl4TFRFeUxUQXlWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0psZUhBaU9pSXlNREkyTFRFeUxUQXhWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0p3ZFdJaU9pSXlWRVJZWkc5T2RsWnpSMVpJT0VNNVZWcDFaSEJpUW5aV1Uwc3hSbVZwTlhJMFdWUmFUWGhoUW1GNmIzTnZNbkJNY0ZCWFZFMW1ZMDRpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLjc5SjlldTNxZXJqMW4xdEpSaUJQenNURHNBNWlqWG41REs3ZlVuNEpRcmhzZUJXN0lrYWRBekNFRGtQcktoUG1lMGtzanVhMjhUQitVTGh4bGEybkNB.pdZhvANop6iCyBvAmWqUFnviqTZRlw/mF4fjLj4MdbVRdsJDF8eOUYQJk+HoqAXE4i9NV18uAioVkKR1LM1WDw";
        var envelope = Envelope.Import(exported);
        Assert.IsTrue(envelope.IsAnonymous);
        Assert.AreEqual(default(Guid), envelope.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(1, envelope.Items.Count);
        Assert.AreEqual(typeof(Identity), envelope.Items.ElementAt(0).GetType());
        Assert.IsFalse(Dime.IsIntegrityStateValid(envelope.Verify(Commons.IssuerKey)));
    }

    [TestMethod]
    public void KeyExportTest1()
    {
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        envelope.AddItem(Commons.IssuerKey);
        envelope.Sign(Commons.IssuerKey);
        var exported = envelope.Export();
        Assert.IsNotNull(exported);
        Assert.IsTrue(exported.Length > 0);
        Assert.IsTrue(exported.StartsWith(Envelope.ItemHeader));
        Assert.IsTrue(exported.Split(new[] { ':' }).Length == 3);
    }

    [TestMethod]
    public void KeyImportTest1()
    {
        const string exported = "Di.eyJpYXQiOiIyMDIyLTEwLTI0VDIyOjQyOjQxLjA0MjUxWiIsImlzcyI6IjEwMzA1NzJmLTZiODItNDM2ZC05ZDUxLTc5MDIwZTYyZjg1MyJ9:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjM1OjQ0LjA4NTgzOVoiLCJrZXkiOiJEU0MuNXlFblAxck5LaHZ3MnRoOUs0Qm0rRU1kWlc2QStkT2FlYWN6cGhmNlNMRytjN2JnQ2ZYYm5ORitUemtXZmpHLzk4ejhSRFg3VFNId0dYbVNTUFpraEEiLCJwdWIiOiJEU0Mudm5PMjRBbjEyNXpSZms4NUZuNHh2L2ZNL0VRMSswMGg4Qmw1a2tqMlpJUSIsInVpZCI6IjUxY2FhNGQxLTAzYjEtNGFkYS1hOGVkLTk2MmYzY2Y0NTIzMiJ9:YzFmMjczMDUzZDhmZDQ4YS43MWQ1YmRiZTBlYmRmM2QyZGZlNDEzZjkwNjc4ZTczNjUxZGNmZTQyZjVlMjU3NDQwZGY0NDk3OTQwY2IxMTI0YmIwMzFkNTgyN2NhZjEwZGMyYTYwYmZlNDdjYzg1OGRhZjFlNTlhZWMxNjE3YWUxYzE1NjVkMTA1NTQ3MmIwZg";
        var envelope = Envelope.Import(exported);
        Assert.IsFalse(envelope.IsAnonymous);
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), envelope.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(DateTime.Parse("2022-10-24T22:42:41.04251Z").ToUniversalTime(), envelope.GetClaim<DateTime>(Claim.Iat));
        Assert.IsNull(envelope.GetClaim<string>(Claim.Ctx));
        Assert.AreEqual(1, envelope.Items.Count);
        Assert.AreEqual(typeof(Key), envelope.Items.ElementAt(0).GetType());
        envelope.Verify(Commons.IssuerKey);
    }
    
    [TestMethod]
    public void DataExportTest1() 
    {
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Commons.Context);
        var data = new Data(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub),Dime.ValidFor1Minute);
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), Commons.Mimetype);
        data.Sign(Commons.IssuerKey);
        envelope.AddItem(data);
        envelope.Sign(Commons.IssuerKey);
        var exported = envelope.Export();
        Assert.IsNotNull(exported);
        Assert.IsTrue(exported.Length > 0);
        Assert.IsTrue(exported.StartsWith(Envelope.ItemHeader));
        Assert.AreEqual(3, exported.Split(':').Length);
    }

    [TestMethod]
    public void DataImportTest1() 
    {
        const string exported = "Di.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjQwOjQ4Ljc1NDQ5WiIsImlzcyI6IjEwMzA1NzJmLTZiODItNDM2ZC05ZDUxLTc5MDIwZTYyZjg1MyJ9:DAT.eyJleHAiOiIyMDIyLTEwLTI0VDIyOjQxOjQ4Ljc1NDk3WiIsImlhdCI6IjIwMjItMTAtMjRUMjI6NDA6NDguNzU0OTdaIiwiaXNzIjoiOWQwYzZjMDMtNWU1Zi00NGNiLWIxZWYtYjMwNDAzZTUwNmYwIiwibWltIjoidGV4dC9wbGFpbiIsInVpZCI6IjkxYzFkNmNjLWIyYzctNDU3Zi05ODE2LTY5ZDlmOTNkODFlYyJ9.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.YzFmMjczMDUzZDhmZDQ4YS4yODZkOTBiNmNjNjlhOTdiM2ZiODg1ODcwZDFmOTUzMTZlODRhZjYwM2NiMDNjMWJlNTUyNGY0YzFkY2U4MDY2OTZlMDUyODAxMjQ0MTY0MDUwZmU2ZTdlZTYxMzVjZTgyMjBlYzBjNjRlNzgyMTgwMDM1MzM4ZjA5MmU0MmEwMA:YzFmMjczMDUzZDhmZDQ4YS43ZjQ5MWJhNDUzNDNhNzM2ZGU4ZGJmMThkZTMzYmNkY2YzYTEyNWZjOGU0YjA1ZmY4YzNjOGUxZTRlOGExNjliZjA5MWFiNTVkZjVjNjNjNjRjMmNjZjRjMDM3MTFkMjJkNDI4NzNkNWI2YzZmZjliYTY3ZWRhNTgwZWQyMWUwYg";
        var envelope = Envelope.Import(exported);
        Assert.IsFalse(envelope.IsAnonymous);
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), envelope.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(DateTime.Parse("2022-10-24T22:40:48.75449Z").ToUniversalTime(), envelope.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual(Commons.Context, envelope.GetClaim<string>(Claim.Ctx));
        Assert.AreEqual(1, envelope.Items.Count);
        Assert.IsTrue(envelope.Items[0] is Data);
    }

    [TestMethod]
    public void MessageExportTest1()
    {
        var envelope = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Commons.Context);
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        envelope.AddItem(message);
        envelope.Sign(Commons.IssuerKey);
        var exported = envelope.Export();
        Assert.IsNotNull(exported);
        Assert.IsTrue(exported.Length > 0);
        Assert.IsTrue(exported.StartsWith(Envelope.ItemHeader));
        Assert.IsTrue(exported.Split(new[] { ':' }).Length == 3);
    }

    [TestMethod]
    public void MessageImportTest1()
    {
        const string exported = "Di.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjQzOjM0LjUwODI3OFoiLCJpc3MiOiIxMDMwNTcyZi02YjgyLTQzNmQtOWQ1MS03OTAyMGU2MmY4NTMifQ:MSG.eyJhdWQiOiI5ZDBjNmMwMy01ZTVmLTQ0Y2ItYjFlZi1iMzA0MDNlNTA2ZjAiLCJleHAiOiIyMDIyLTEwLTI0VDIyOjQ0OjM0LjUwODgwNFoiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjQzOjM0LjUwODgwNFoiLCJpc3MiOiIxMDMwNTcyZi02YjgyLTQzNmQtOWQ1MS03OTAyMGU2MmY4NTMiLCJ1aWQiOiJiZGYxZGVjNy1hNGNkLTQ5NTUtYjU4YS04YWM2OWQwYmI5ZWMifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.YzFmMjczMDUzZDhmZDQ4YS43YWRmYWYyMjM1YThhMDRkOTcxZWVhODE3NGE5YTE2YTNkYTM5MDdiMmE3NDI5NjZlMzVlNDgxM2RhY2RkNjEwMmNiNDdlMTNhYzgwZDJjYzFiZWQwOTQzNDQxNzZmNzg4OGZmYWNkYzAyNGRiNTQ3ZDQ1ZmJkNGNlNGQxYjkwNA:YzFmMjczMDUzZDhmZDQ4YS5iMGNkZWI4MWZiNzlmOTU5NWUwYWIwNmNhMDUxN2UwMTYxMWIwM2ZmY2EzY2FkY2JlY2FiNjc4NjhhMjRkYTE0YzRjZTZiNjkxMjM4ZjkwOWI3MDU5NDdmNzUzYTJlMDBlNGU4MDcxY2EyYWVkNTA3NWI0Yjg2NDg0OTRlNzEwNA";
        var envelope = Envelope.Import(exported);
        Assert.IsFalse(envelope.IsAnonymous);
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), envelope.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(DateTime.Parse("2022-10-24T22:43:34.508278Z").ToUniversalTime(), envelope.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual(Commons.Context, envelope.GetClaim<string>(Claim.Ctx));
        Assert.AreEqual(1, envelope.Items.Count);
        Assert.AreEqual(typeof(Message), envelope.Items.ElementAt(0).GetType());
        envelope.Verify(Commons.IssuerKey);
    }

    [TestMethod]
    public void ExportTest1()
    {
        var envelope1 = new Envelope(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        envelope1.AddItem(Commons.IssuerIdentity);
        envelope1.AddItem(Commons.IssuerKey.PublicCopy());
        envelope1.Sign(Commons.IssuerKey);
        var exported = envelope1.Export();

        var envelope2 = Envelope.Import(exported);
        envelope2.Verify(Commons.IssuerKey);
        Assert.AreEqual(2, envelope2.Items.Count);

        var identity = (Identity)envelope2.Items.ElementAt(0);
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), identity.GetClaim<Guid>(Claim.Sub));
        var key = (Key)envelope2.Items.ElementAt(1);
        Assert.AreEqual(Commons.IssuerKey.GetClaim<Guid>(Claim.Uid), key.GetClaim<Guid>(Claim.Uid));
        Assert.IsNull(key.Secret);
    }

}