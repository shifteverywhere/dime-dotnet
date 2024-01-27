//
//  ItemTests.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using DiME;
using DiME.Capability;
using DiME.KeyRing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DiME_test;

[TestClass]
public class ItemTests
{
    
    [TestMethod]
    public void VerifyTest1() 
    {
        var key = Key.Generate(new List<KeyCapability> { KeyCapability.Sign }, Dime.ValidFor1Minute);
        key.AddItemLink(Commons.IssuerIdentity);
        key.AddItemLink(Commons.AudienceIdentity);
        key.Sign(key);
        Assert.AreEqual(IntegrityState.PartiallyComplete, key.Verify(key));
        Assert.AreEqual(IntegrityState.Intact, key.Verify(key, new List<Item> {Commons.IssuerIdentity}));
        Assert.AreEqual(IntegrityState.Complete, key.Verify(key, new List<Item> {Commons.IssuerIdentity, Commons.AudienceIdentity}));
        Assert.AreEqual(IntegrityState.Intact, key.Verify(key, new List<Item> {Commons.IssuerIdentity, Commons.AudienceIdentity, Commons.IssuerIdentity}));
    }

    [TestMethod]
    public void VerifyTest2() 
    {
        var key = Key.Generate(KeyCapability.Sign);
        key.AddItemLink(Commons.IssuerIdentity);
        key.AddItemLink(Commons.AudienceIdentity);
        key.Sign(key);
        Assert.AreEqual(IntegrityState.Complete, key.Verify(key, new List<Item> {Commons.IssuerIdentity, Commons.AudienceIdentity}));
        Assert.AreEqual(IntegrityState.FailedLinkedItemMismatch, key.Verify(key, new List<Item> {Commons.TrustedIdentity, Commons.IntermediateIdentity}));
        Assert.AreEqual(IntegrityState.FailedLinkedItemMismatch, key.Verify(key, new List<Item> {Commons.TrustedIdentity, Commons.IssuerIdentity}));
        Assert.AreEqual(IntegrityState.Intact, key.Verify(key, new List<Item>() {Commons.IssuerIdentity}));
    }

    [TestMethod]
    public void VerifyTest3() 
    {
        Dime.OverrideTime = null;
        var key = Key.Generate(new List<KeyCapability>() { KeyCapability.Sign }, Dime.ValidFor1Minute);
        key.Sign(key);
        Dime.OverrideTime = DateTime.UtcNow.AddSeconds(Dime.ValidFor1Minute * 2);
        Assert.AreEqual(IntegrityState.FailedUsedAfterExpired, key.Verify(key));
        Dime.OverrideTime = DateTime.UtcNow.AddSeconds(-Dime.ValidFor1Minute);
        Assert.AreEqual(IntegrityState.FailedUsedBeforeIssued, key.Verify(key));
        Dime.OverrideTime = null;
        Assert.AreEqual(IntegrityState.Complete, key.Verify(key));
    }

    [TestMethod]
    public void VerifyTest4() 
    {
        var key = Key.Generate(KeyCapability.Encrypt);
        key.PutClaim(Claim.Iss, Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        key.Sign(Commons.IssuerKey);
        Assert.AreEqual(IntegrityState.Complete, key.Verify(Commons.IssuerIdentity));
        Assert.AreEqual(IntegrityState.FailedIssuerMismatch, key.Verify(Commons.AudienceIdentity));
        Assert.AreEqual(IntegrityState.Complete, key.Verify(Commons.IssuerIdentity.PublicKey));
        Assert.AreEqual(IntegrityState.FailedKeyMismatch, key.Verify(Commons.AudienceIdentity.PublicKey));
    }
    
}