//
//  PerformanceTests.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using DiME;

namespace DiME_test
{
    
    [TestClass]
    public class PerformanceTests
    {

        public static int PerformanceRounds = 100;
        
        [TestMethod]
        public void IdentityPerformanceTest()
        {
            Console.WriteLine("-- Identity performance tests --\n");
            Console.WriteLine($"Number of rounds: {PerformanceRounds}\n");
            
            var totalSw = new Stopwatch();
            var sw = new Stopwatch();
            totalSw.Start();
            
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            var caps = new List<Capability> { Capability.Generic, Capability.Identify };
            var keyList = new List<Key>();
            var iirList = new List<IdentityIssuingRequest>();
            var identityList = new List<Identity>();
            var dimeList = new List<string>();
            
            Console.Write("* Running key generation tests...");
            sw.Start();
            for(var i = 0; i < PerformanceRounds; i++) {
                var key = Key.Generate(KeyType.Identity);
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
                var identity = iir.Issue(Guid.NewGuid(), IdentityIssuingRequest._VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
                identityList.Add(identity);
            }
            sw.Stop();
            Console.WriteLine($" DONE \n\t - Total: {sw.Elapsed}s\n");
            
            sw.Reset();
            Console.Write("* Running identity verification from root tests...");
            sw.Start();
            for(var i = 0; i < PerformanceRounds; i++) {
                var identity = identityList[i];
                identity.IsTrusted();
            }
            sw.Stop();
            Console.WriteLine($" DONE \n\t - Total: {sw.Elapsed}s\n");
            
            sw.Reset();
            Console.Write("* Running identity verification from node tests...");
            sw.Start();
            for(var i = 0; i < PerformanceRounds; i++) {
                var identity = identityList[i];
                identity.IsTrusted(Commons.IntermediateIdentity);
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
                var identity = Item.Import<Identity>(dime);
            }
            sw.Stop();
            Console.WriteLine($" DONE \n\t - Total: {sw.Elapsed}s\n");
            
            totalSw.Stop();
            Console.WriteLine($"\nTOTAL: {totalSw.Elapsed}s\n");
            
        }
    }

}