//
//  IdentityTests.cs
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//

using System;
using System.Collections.Generic;
using DiME;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DiME_test;

[TestClass]
public class ItemLinkTest
{
    [TestMethod]
    public void ItemLinkTest1() {
        var key = Key.Generate(new List<KeyUse>() {KeyUse.Sign}, null);
        var link = new ItemLink(key);
        Assert.IsNotNull(link);
        Assert.AreEqual(key.Identifier, link.ItemIdentifier);
        Assert.AreEqual(key.Thumbprint(), link.Thumbprint);
        Assert.AreEqual(key.UniqueId, link.UniqueId);
    }

    // itemLinkTest2 not relevant, as found in Java ref impl.
    
    [TestMethod]
    public void ItemLinkTest3() {
        var key = Key.Generate(new List<KeyUse>() {KeyUse.Sign}, null);
        var link = new ItemLink(Key.ItemIdentifier, key.Thumbprint(), key.UniqueId);
        Assert.IsNotNull(link);
        Assert.AreEqual(Key.ItemIdentifier, link.ItemIdentifier);
        Assert.AreEqual(key.Thumbprint(), link.Thumbprint);
        Assert.AreEqual(key.UniqueId, link.UniqueId);
    }

    [TestMethod]
    public void ItemLinkTest4() {
        var key = Key.Generate(new List<KeyUse>() {KeyUse.Sign}, null);
        try {
            _ = new ItemLink("", key.Thumbprint(), key.UniqueId);
            Assert.IsTrue(false, "Exception not thrown.");
        } catch (ArgumentException) { /* All is well, carry on. */ }
        try {
            _ = new ItemLink(Key.ItemIdentifier, "", key.UniqueId);
            Assert.IsTrue(false, "Exception not thrown.");
        } catch (ArgumentException) { /* All is well, carry on. */ }
    }

    [TestMethod]
    public void ToEncodedTest1() {
        var key = Commons.AudienceKey.PublicCopy();
        var link = new ItemLink(key);
        var encoded = link.ToEncoded();
        Assert.IsNotNull(encoded);
        var compare = $"{key.Identifier}.{key.UniqueId.ToString()}.{key.Thumbprint()}";
        Assert.AreEqual(compare, encoded);
        Assert.AreNotEqual(Commons.AudienceKey.Thumbprint(), link.Thumbprint);
    }

    [TestMethod]
    public void VerifyTest1() {
        var link = new ItemLink(Commons.AudienceKey);
        Assert.IsTrue(link.Verify(Commons.AudienceKey));
        Assert.IsFalse(link.Verify(Commons.IssuerKey));
        Assert.IsFalse(link.Verify(Commons.AudienceKey.PublicCopy()));
    }

    [TestMethod]
    public void VerifyListTest1() {
        var link = new ItemLink(Commons.AudienceKey);
        ItemLink.Verify(new List<Item> { Commons.AudienceKey }, new List<ItemLink> { link });
        try {
            ItemLink.Verify(new List<Item> { Commons.AudienceKey.PublicCopy() }, new List<ItemLink> { link });
            Assert.IsTrue(false, "Exception not thrown.");
        } catch (IntegrityException) { /* all is well */ }
    }

    [TestMethod]
    public void VerifyListTest2() {
        var items = new List<Item> { Commons.AudienceKey, Commons.AudienceIdentity };
        var revItems = new List<Item> { Commons.AudienceIdentity, Commons.AudienceKey };
        var links = new List<ItemLink> { new ItemLink(Commons.AudienceKey), new ItemLink(Commons.AudienceIdentity) };
        ItemLink.Verify(items, links);
        ItemLink.Verify(revItems, links);
        ItemLink.Verify(new List<Item> { Commons.AudienceKey }, links);
        ItemLink.Verify(new List<Item> { Commons.AudienceKey }, links);
        try { ItemLink.Verify(new List<Item>(), links); Assert.IsTrue(false,"Exception not thrown."); } catch (IntegrityException) { /* all is well */ }
        try { ItemLink.Verify(items, new List<ItemLink>()); Assert.IsTrue(false,"Exception not thrown."); } catch (IntegrityException) { /* all is well */ }
    }

    [TestMethod]
    public void ToEncodedTest2() {
        var key = Commons.AudienceKey.PublicCopy();
        var link = new ItemLink(key.Identifier, key.Thumbprint(), key.UniqueId);
        var encoded = link.ToEncoded();
        Assert.IsNotNull(encoded);
        var compare = $"{key.Identifier}.{key.UniqueId.ToString()}.{key.Thumbprint()}";
        Assert.AreEqual(compare, encoded);
        Assert.AreNotEqual(Commons.AudienceKey.Thumbprint(), link.Thumbprint);
    }

    [TestMethod]
    public void ToEncodedListTest1() {
        var links = new List<ItemLink>() { new ItemLink(Commons.AudienceIdentity), new ItemLink(Commons.AudienceKey.PublicCopy()) };
        var encoded = ItemLink.ToEncoded(links);
        Assert.IsNotNull(encoded);
        Assert.IsTrue(encoded.StartsWith(Identity.ItemIdentifier));
        var components = encoded.Split(':');
        Assert.AreEqual(2, components.Length);
    }

    [TestMethod]
    public void ToEncodedListTest2() {
        var links = new List<ItemLink> { new ItemLink(Commons.AudienceIdentity) };
        var encoded = ItemLink.ToEncoded(links);
        Assert.IsNotNull(encoded);
        Assert.IsTrue(encoded.StartsWith(Identity.ItemIdentifier));
        var components = encoded.Split(':');
        Assert.AreEqual(1, components.Length);
    }

    [TestMethod]
    public void ToEncodedListTest3() {
        var encoded = ItemLink.ToEncoded(new List<ItemLink>());
        Assert.IsNull(encoded);
    }

    [TestMethod]
    public void FromEncodedTest1() {
        const string encoded = "KEY.c89b08d7-f472-4703-b5d3-3d23fd39e10d.68cd898db0b2535c912f6aa5f565306991ba74760b2955e7fb8dc91fd45276bc";
        var link = ItemLink.FromEncoded(encoded);
        Assert.IsNotNull(link);
        Assert.AreEqual("KEY", link.ItemIdentifier);
        Assert.AreEqual(Guid.Parse("c89b08d7-f472-4703-b5d3-3d23fd39e10d"), link.UniqueId);
        Assert.AreEqual("68cd898db0b2535c912f6aa5f565306991ba74760b2955e7fb8dc91fd45276bc", link.Thumbprint);
    }

    [TestMethod]
    public void FromEncodedTest2() {
        try
        {
            ItemLink.FromEncoded(Commons.Payload);
            Assert.IsTrue(false, "Exception should have been thrown");
        }
        catch (FormatException)
        {
             /* All is well, carry on. */
        }
    }

    [TestMethod]
    public void FromEncodedListTest1() {
        var lnk1 = new ItemLink(Key.Generate(new List<KeyUse>() { KeyUse.Sign }, null)).ToEncoded();
        var lnk2 = new ItemLink(Key.Generate(new List<KeyUse>() { KeyUse.Exchange }, null)).ToEncoded();
        var lnk3 = new ItemLink(Key.Generate(new List<KeyUse>() { KeyUse.Encrypt }, null)).ToEncoded();
        var links = ItemLink.FromEncodedList($"{lnk1}:{lnk2}:{lnk3}");
        Assert.IsNotNull(links);
        Assert.AreEqual(3, links.Count);
    }

    [TestMethod]
    public void FromEncodedListTest2() {
        try 
        {
            ItemLink.FromEncodedList(Commons.Payload);
            Assert.IsTrue(false, "Exception should have been thrown");
        } catch (FormatException) 
        {
            /* All is well, carry on. */
        }
    }
    
}