//
//  TagTest.cs
//  DiME - Data Integrity Message Envelope
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
using DiME;
using DiME.Capability;

namespace DiME_test;

[TestClass]
public class TagTests
{
    
    [TestMethod]
    public void GetItemIdentifierTest1() 
    {
        var tag = new Tag();
        Assert.AreEqual("TAG", tag.Header);
        Assert.AreEqual("TAG", Tag.ItemHeader);
    }
    
    [TestMethod]
    public void ClaimTest1() 
    {
        var tag = new Tag();
        Assert.AreEqual(default, tag.GetClaim<Guid>(Claim.Iss));
        tag.PutClaim(Claim.Iss, Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), tag.GetClaim<Guid>(Claim.Iss));
    }

    [TestMethod]
    public void ClaimTest2() 
    {
        var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), tag.GetClaim<Guid>(Claim.Iss));
        tag.RemoveClaim(Claim.Iss);
        Assert.AreEqual(default, tag.GetClaim<Guid>(Claim.Sub));
    }

    [TestMethod]
    public void ClaimTest3() 
    {
        var tag = new Tag();
        tag.PutClaim(Claim.Amb, new List<string>() { "one", "two" });
        Assert.IsNotNull(tag.GetClaim<List<string>>(Claim.Amb));
        tag.PutClaim(Claim.Aud, Guid.NewGuid());
        Assert.IsNotNull(tag.GetClaim<Guid>(Claim.Aud));
        Assert.AreNotEqual(default, tag.GetClaim<Guid>(Claim.Aud));
        tag.PutClaim(Claim.Ctx, Commons.Context);
        Assert.IsNotNull(tag.GetClaim<string>(Claim.Ctx));
        tag.PutClaim(Claim.Exp, DateTime.UtcNow);
        Assert.IsNotNull(tag.GetClaim<DateTime>(Claim.Exp));
        Assert.AreNotEqual(default, tag.GetClaim<DateTime>(Claim.Exp));
        tag.PutClaim(Claim.Iat, DateTime.UtcNow);
        Assert.IsNotNull(tag.GetClaim<DateTime>(Claim.Iat));
        Assert.AreNotEqual(default, tag.GetClaim<DateTime>(Claim.Iat));
        tag.PutClaim(Claim.Iss, Guid.NewGuid());
        Assert.IsNotNull(tag.GetClaim<Guid>(Claim.Iss));
        Assert.AreNotEqual(default, tag.GetClaim<Guid>(Claim.Iss));
        tag.PutClaim(Claim.Kid, Guid.NewGuid());
        Assert.IsNotNull(tag.GetClaim<Guid>(Claim.Kid));
        Assert.AreNotEqual(default, tag.GetClaim<Guid>(Claim.Kid));
        tag.PutClaim(Claim.Mtd, new List<string>() { "abc", "def" });
        Assert.IsNotNull(tag.GetClaim<List<string>>(Claim.Mtd));
        tag.PutClaim(Claim.Sub, Guid.NewGuid());
        Assert.IsNotNull(tag.GetClaim<Guid>(Claim.Sub));
        Assert.AreNotEqual(default, tag.GetClaim<Guid>(Claim.Sub));
        tag.PutClaim(Claim.Sys, Commons.SystemName);
        Assert.IsNotNull(tag.GetClaim<string>(Claim.Sys));
        tag.PutClaim(Claim.Uid, Guid.NewGuid());
        Assert.IsNotNull(tag.GetClaim<Guid>(Claim.Uid));
        Assert.AreNotEqual(default, tag.GetClaim<Guid>(Claim.Uid));
        try { tag.PutClaim(Claim.Cap, new List<KeyCapability>() { KeyCapability.Encrypt }); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { tag.PutClaim(Claim.Key,Commons.IssuerKey.Secret); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { tag.PutClaim(Claim.Lnk, new ItemLink(Commons.IssuerKey)); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { tag.PutClaim(Claim.Mim, Commons.Mimetype); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well*/ }
        try { var pri = new Dictionary<string, object>(); pri["tag"] = Commons.Payload; tag.PutClaim(Claim.Pri, pri); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { tag.PutClaim(Claim.Pub, Commons.IssuerKey.Public); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
    }

    [TestMethod]
    public void ClaimTest4()
    {
        var items = new List<Item>() {Key.Generate(KeyCapability.Sign), Key.Generate(KeyCapability.Exchange)};
        var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Commons.Context, items);
        tag.Sign(Commons.IssuerKey);
        try { tag.RemoveClaim(Claim.Iss); Assert.IsTrue(false, "Exception not thrown."); } catch (InvalidOperationException) { /* all is well */ }
        try { tag.PutClaim(Claim.Exp, DateTime.UtcNow); } catch (InvalidOperationException) { /* all is well */ }
    }

    [TestMethod]
    public void ClaimTest5() 
    {
        var items = new List<Item>() {Key.Generate(KeyCapability.Sign), Key.Generate(KeyCapability.Exchange)};
        var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Commons.Context, items);
        tag.Sign(Commons.IssuerKey);
        tag.Strip();
        tag.RemoveClaim(Claim.Ctx);
        tag.PutClaim(Claim.Iat, DateTime.UtcNow);
    }
    
    [TestMethod]
    public void TagTest1() 
    {
        var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), tag.GetClaim<Guid>(Claim.Iss));
        Assert.IsNull(tag.GetClaim<string>(Claim.Ctx));
        Assert.IsNull(tag.GetItemLinks());
    }

    [TestMethod]
    public void TagTest2() 
    {
        var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Commons.Context);
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), tag.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(Commons.Context, tag.GetClaim<string>(Claim.Ctx));
        Assert.IsNull(tag.GetItemLinks());
    }

    // TagTest3 not relevant for C#

    [TestMethod]
    public void TagTest4()
    {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
           _ = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), context);
        } catch (ArgumentException) { /* All is well, carry on. */ }
    }

    [TestMethod]
    public void TagTest5() 
    {
        var items = new List<Item>() { Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null) };
        var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Commons.Context, items);
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), tag.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(Commons.Context, tag.GetClaim<string>(Claim.Ctx));
        Assert.IsNotNull(tag.GetItemLinks);
        Assert.AreEqual(2, tag.GetItemLinks()!.Count);
    }

    [TestMethod]
    public void AddItemLinkTest1() 
    {
        var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        tag.AddItemLink(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
        Assert.IsNotNull(tag.GetItemLinks);
        Assert.AreEqual(1, tag.GetItemLinks()!.Count);
        Assert.AreEqual(Key.ItemHeader, tag.GetItemLinks()![0].ItemIdentifier);
    }

    [TestMethod]
    public void AddItemLinkTest2() 
    {
        var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        tag.AddItemLink(Commons.IssuerIdentity);
        Assert.IsNotNull(tag.GetItemLinks);
        Assert.AreEqual(1, tag.GetItemLinks()!.Count);
        Assert.AreEqual(Identity.ItemHeader, tag.GetItemLinks()![0].ItemIdentifier);
    }

    [TestMethod]
    public void AddItemLinkTest3() 
    {
        var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 10);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        tag.AddItemLink(message);
        Assert.IsNotNull(tag.GetItemLinks);
        Assert.AreEqual(1, tag.GetItemLinks()!.Count);
        Assert.AreEqual(Message.ItemHeader, tag.GetItemLinks()![0].ItemIdentifier);
    }

    [TestMethod]
    public void AddItemLinkTest4() 
    {
        try {
            var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
            tag.AddItemLink(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
            tag.Sign(Commons.IssuerKey);
            tag.AddItemLink(Commons.IssuerIdentity);
            Assert.IsTrue(false, "Expected exception not thrown.");
        } catch (InvalidOperationException) {
            /* All is well */
        } 
    }

    [TestMethod]
    public void AddItemLinkTest5() 
    {
        var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        tag.AddItemLink(Commons.TrustedIdentity);
        tag.AddItemLink(Commons.IntermediateIdentity);
        tag.AddItemLink(Commons.IssuerIdentity);
        tag.AddItemLink(Commons.AudienceKey);
        var links = tag.GetItemLinks();
        Assert.IsNotNull(links);
        Assert.AreEqual(4, links.Count);
        var link0 = links[0];
        Assert.AreEqual(Commons.TrustedIdentity.Header, link0.ItemIdentifier);
        Assert.AreEqual(Commons.TrustedIdentity.GetClaim<Guid>(Claim.Uid), link0.UniqueId);
        Assert.AreEqual(Commons.TrustedIdentity.Thumbprint(), link0.Thumbprint);
        var link1 = links[1];
        Assert.AreEqual(Commons.IntermediateIdentity.Header, link1.ItemIdentifier);
        Assert.AreEqual(Commons.IntermediateIdentity.GetClaim<Guid>(Claim.Uid), link1.UniqueId);
        Assert.AreEqual(Commons.IntermediateIdentity.Thumbprint(), link1.Thumbprint);
        var link2 = links[2];
        Assert.AreEqual(Commons.IssuerIdentity.Header, link2.ItemIdentifier);
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Uid), link2.UniqueId);
        Assert.AreEqual(Commons.IssuerIdentity.Thumbprint(), link2.Thumbprint);
        var link3 = links[3];
        Assert.AreEqual(Commons.AudienceKey.Header, link3.ItemIdentifier);
        Assert.AreEqual(Commons.AudienceKey.GetClaim<Guid>(Claim.Uid), link3.UniqueId);
        Assert.AreEqual(Commons.AudienceKey.Thumbprint(), link3.Thumbprint);
    }

    [TestMethod]
    public void ExportTest1() 
    {
        var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 10);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        tag.AddItemLink(message);
        tag.AddItemLink(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
        tag.AddItemLink(Commons.IssuerIdentity);
        tag.Sign(Commons.IssuerKey);
        var encoded = tag.Export();
        Assert.IsNotNull(encoded);
        Assert.IsTrue(encoded.Length > 0);
        Assert.IsTrue(encoded.StartsWith(Commons.FullHeaderFor(Tag.ItemHeader)));
        Assert.AreEqual(3, encoded.Split('.').Length);
    }

    [TestMethod]
    public void ExportTest2() 
    {
        try {
            var tag = new Tag(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
            tag.AddItemLink(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
            tag.Export();
            Assert.IsTrue(false, "Expected exception not thrown.");
        } catch (InvalidOperationException) {
            /* All is well */
        }
    }

    [TestMethod]
    public void ImportTest1() 
    {
        const string exported = "Di:TAG.eyJpc3MiOiJiZTRhZjVmMy1lODM4LTQ3MzItYTBmYy1mZmEyYzMyOGVhMTAiLCJsbmsiOiJNU0cuZTZjZWRlMDEtOTliNC00NGM1LTg2NDEtYzdjZGY5ZGY1MmI2LmU4NTE5N2I2ZTk3Yjg4YjU0MmU2ODJhMmQ5NzgzMjAwOGQyZTczZjg4ZjQ1ZmE2NjJiNmRhOTY4MDM0ZTBiODk6S0VZLjA4YTc0MGYxLTliYzgtNDMwMS1iMzRkLTQyNmYwYWVmMmZmYy5lZjFhNzZiMmY1ZjUyMjRmYTE2NjY5MDQxNWEyODcxYWQ4ZDFhOTY0OTVkMDM1YzExOTc1OWE0ZTZhNmVmMjZiOklELjJhN2Q0MmEzLTZiNDUtNGE0YS1iYjNkLWVjOTRlYzM3OWYxZi5mNTUxNDY2YWE0MDJmYWVkNzBiZmFhYjlmYmJjM2UzNjI0MWRiMzQ5YWNiY2Y3MWM2YmEyOGZiNGY2YzA5MzRjIiwidWlkIjoiNDc5MzE5N2ItZjM3Mi00NzRiLThmNzYtMDViZWMwNmIxNDU4In0.L1apyM3ULPIioUdizKlSyO2O3Z0GzKNzQUKDRpgCvq0pnOZbu+hy/iCX/NkY245/CP/QwJYUeU4MBk9pyPRzDA";
        var tag = Item.Import<Tag>(exported);
        Assert.IsNotNull(tag);
        var itemLinks = tag.GetItemLinks();
        Assert.IsNotNull(itemLinks);
        Assert.AreEqual(3, itemLinks.Count);
        var lnk1 = tag.GetItemLinks()![0];
        Assert.AreEqual(Message.ItemHeader, lnk1.ItemIdentifier);
        Assert.AreEqual("e85197b6e97b88b542e682a2d97832008d2e73f88f45fa662b6da968034e0b89", lnk1.Thumbprint);
        Assert.AreEqual(Guid.Parse("e6cede01-99b4-44c5-8641-c7cdf9df52b6"), lnk1.UniqueId);
        var lnk2 = tag.GetItemLinks()![1];
        Assert.AreEqual(Key.ItemHeader, lnk2.ItemIdentifier);
        Assert.AreEqual("ef1a76b2f5f5224fa166690415a2871ad8d1a96495d035c119759a4e6a6ef26b", lnk2.Thumbprint);
        Assert.AreEqual(Guid.Parse("08a740f1-9bc8-4301-b34d-426f0aef2ffc"), lnk2.UniqueId);
        var lnk3 = tag.GetItemLinks()![2];
        Assert.AreEqual(Identity.ItemHeader, lnk3.ItemIdentifier);
        Assert.AreEqual("f551466aa402faed70bfaab9fbbc3e36241db349acbcf71c6ba28fb4f6c0934c", lnk3.Thumbprint);
        Assert.AreEqual(Guid.Parse("2a7d42a3-6b45-4a4a-bb3d-ec94ec379f1f"), lnk3.UniqueId);
    }

}