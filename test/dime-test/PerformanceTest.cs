//
//  PerformanceTests.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using DiME;
using DiME.Capability;

namespace DiME_test;

[TestClass]
public class PerformanceTests
{
    private const int PerformanceRounds = 10;

    [TestMethod]
    public void SignaturePerformanceTest()
    {
        Console.WriteLine("-- Signature performance tests --\n");
        Console.WriteLine($"Number of rounds: {PerformanceRounds}\n");

        var totalSw = new Stopwatch();
        var sw = new Stopwatch();
        totalSw.Start();
        
        var key = Key.Generate(KeyCapability.Sign);
        var message = new Message(Guid.NewGuid(),
            Guid.NewGuid(),
            Dime.ValidFor1Hour,
            Commons.Context);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), Commons.Mimetype);
        
        Console.Write("* Running signing tests...");
        sw.Start();
        for(var i = 0; i < PerformanceRounds; i++) {
            message.Sign(key);
            message.Strip();
        }
        sw.Stop();
        Console.WriteLine($" DONE \n\t - Total: {sw.Elapsed}s\n");
        
        message.Sign(key);
        
        sw.Reset();
        Console.Write("* Running verification tests...");
        sw.Start();
        for(var i = 0; i < PerformanceRounds; i++) {
            message.Verify(key);
        }
        sw.Stop();
        Console.WriteLine($" DONE \n\t - Total: {sw.Elapsed}s\n");
        
        totalSw.Stop();
        Console.WriteLine($"\nTOTAL: {totalSw.Elapsed}s\n");
        
    }

    [TestMethod]
    public void IdentityPerformanceTest()
    {
        Console.WriteLine("-- Identity performance tests --\n");
        Console.WriteLine($"Number of rounds: {PerformanceRounds}\n");
            
        var totalSw = new Stopwatch();
        var sw = new Stopwatch();
        totalSw.Start();
            
        Commons.InitializeKeyRing();
        var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Identify };
        var keyList = new List<Key>();
        var iirList = new List<IdentityIssuingRequest>();
        var identityList = new List<Identity>();
        var dimeList = new List<string>();
            
        Console.Write("* Running key generation tests...");
        sw.Start();
        for(var i = 0; i < PerformanceRounds; i++) {
            var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            keyList.Add(key);
        }
        sw.Stop();
        Console.WriteLine($" DONE \n\t - Total: {sw.Elapsed}s\n");
            
        sw.Reset();
        Console.Write("* Running IIR generation tests...");
        sw.Start();
        for(var i = 0; i < PerformanceRounds; i++) {
            var iir = IdentityIssuingRequest.Generate(keyList[i], caps);
            iirList.Add(iir);
        }
        sw.Stop();
        Console.WriteLine($" DONE \n\t - Total: {sw.Elapsed}s\n");
            
        sw.Reset();
        Console.Write("* Running identity issuing tests...");
        sw.Start();
        for(var i = 0; i < PerformanceRounds; i++) {
            var iir = iirList[i];
            var identity = iir.Issue(Guid.NewGuid(), Dime.ValidFor1Year, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
            identityList.Add(identity);
        }
        sw.Stop();
        Console.WriteLine($" DONE \n\t - Total: {sw.Elapsed}s\n");
            
        sw.Reset();
        Console.Write("* Running identity verification from root tests...");
        sw.Start();
        for(var i = 0; i < PerformanceRounds; i++) {
            var identity = identityList[i];
            identity.Verify();
        }
        sw.Stop();
        Console.WriteLine($" DONE \n\t - Total: {sw.Elapsed}s\n");
            
        sw.Reset();
        Console.Write("* Running identity verification from node tests...");
        sw.Start();
        for(var i = 0; i < PerformanceRounds; i++) {
            var identity = identityList[i];
            identity.Verify(Commons.IntermediateIdentity);
        }
        sw.Stop();
        Console.WriteLine($" DONE \n\t - Total: {sw.Elapsed}s\n");
            
        sw.Reset();
        Console.Write("* Running identity exporting tests...");
        sw.Start();
        for(var i = 0; i < PerformanceRounds; i++) {
            var identity = identityList[i];
            var dime = identity.Export();
            dimeList.Add(dime);
        }
        sw.Stop();
        Console.WriteLine($" DONE \n\t - Total: {sw.Elapsed}s\n");
            
        sw.Reset();
        Console.Write("* Running identity importing tests...");
        sw.Start();
        for(var i = 0; i < PerformanceRounds; i++) {
            var dime = dimeList[i];
            Item.Import<Identity>(dime);
        }
        sw.Stop();
        Console.WriteLine($" DONE \n\t - Total: {sw.Elapsed}s\n");
            
        totalSw.Stop();
        Console.WriteLine($"\nTOTAL: {totalSw.Elapsed}s\n");
            
    }
}