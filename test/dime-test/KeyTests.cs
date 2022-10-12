//
//  KeyTests.cs
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

namespace DiME_test;

[TestClass]
public class KeyTests
{
        
    [TestMethod]
    public void GetTagTest1() {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        Assert.AreEqual("KEY", key.Identifier);
    }
        
    [TestMethod]
    public void KeyTest1()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        Assert.IsTrue(key.HasCapability(KeyCapability.Sign));
        Assert.IsFalse(key.HasCapability(KeyCapability.Exchange));
        Assert.IsNotNull(key.UniqueId);
        Assert.IsNotNull(key.Public);
        Assert.IsNotNull(key.Secret);
    }

    [TestMethod]
    public void KeyTest2()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        Assert.IsTrue(key.HasCapability(KeyCapability.Exchange));
        Assert.IsFalse(key.HasCapability(KeyCapability.Sign));
        Assert.IsNotNull(key.UniqueId);
        Assert.IsNotNull(key.Public);
        Assert.IsNotNull(key.Secret);
    }

    [TestMethod]
    public void ExportTest1()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        var encoded = key.Export();
        Assert.IsNotNull(encoded);
        Assert.IsTrue(encoded.StartsWith($"{Envelope.Header}:{Key.ItemIdentifier}"));
        Assert.IsTrue(encoded.Split(".").Length == 2);
    }

    [TestMethod]
    public void ImportTest1()
    {
        const string encoded = "Di:KEY.eyJ1aWQiOiI3ZmE2OGU4OC02ZDVjLTQwMmItOThkOC1mZDg2NjQwY2Y0ZjIiLCJpYXQiOiIyMDIxLTEyLTAxVDIwOjUzOjIzLjM4MzczM1oiLCJrZXkiOiIyVERYZDlXVXR3dVliaTROaFNRRUhmTjg5QmhLVkNTQWVqUFpmRlFRZ1BxaVJadXNUTkdtcll0ZVEiLCJwdWIiOiIyVERYZG9OdXNiNXlWQXB6WTIzYXR1UTNzbUdiOExuZ0o0QVpYRWhpck1mQ0t5OHFkNEZwM1c5OHMifQ";
        var key = Item.Import<Key>(encoded);
        Assert.IsTrue(key.HasCapability(KeyCapability.Sign));
        Assert.AreEqual(new Guid("7fa68e88-6d5c-402b-98d8-fd86640cf4f2"), key.UniqueId);
        Assert.AreEqual(DateTime.Parse("2021-12-01T20:53:23.383733Z").ToUniversalTime(), key.IssuedAt);
        Assert.AreEqual("2TDXd9WUtwuYbi4NhSQEHfN89BhKVCSAejPZfFQQgPqiRZusTNGmrYteQ", key.Secret);
        Assert.AreEqual("2TDXdoNusb5yVApzY23atuQ3smGb8LngJ4AZXEhirMfCKy8qd4Fp3W98s", key.Public);
    }

    [TestMethod]
    public void PublicOnlyTest1()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, 120, Guid.NewGuid(), Commons.Context);
        Assert.IsNotNull(key.Secret);
        var pubOnly = key.PublicCopy();
        Assert.IsNull(pubOnly.Secret);
        Assert.AreEqual(key.Public, pubOnly.Public);
        Assert.AreEqual(key.UniqueId, pubOnly.UniqueId);
        Assert.AreEqual(key.IssuedAt, pubOnly.IssuedAt);
        Assert.AreEqual(key.ExpiresAt, pubOnly.ExpiresAt);
        Assert.AreEqual(key.IssuerId, pubOnly.IssuerId);
        Assert.AreEqual(key.Context, pubOnly.Context);
    }

    [TestMethod]
    public void PublicOnlyTest2()
    {
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100L);
        message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
        message.Sign(Commons.IssuerKey);
        var pubOnly = Commons.IssuerKey.PublicCopy();
        message.Verify(pubOnly);            
    }
        
    [TestMethod]
    public void ContextTest1() {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, context);
        Assert.AreEqual(context, key.Context);
    }

    [TestMethod]
    public void ContextTest2() {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        var key1 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, context);
        var exported = key1.Export();
        var key2 = Item.Import<Key>(exported);
        Assert.AreEqual(context, key2.Context);
    }

    [TestMethod]
    public void ContextTest3() 
    {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, context);
        } catch (ArgumentException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }
        
}