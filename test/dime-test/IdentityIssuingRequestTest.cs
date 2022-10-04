//
//  IdentityIssuingRequestTests.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using DiME;

namespace DiME_test
{
    [TestClass]
    public class IdentityIssuingRequestTests
    {

        [TestMethod]
        public void GetTagTest1()
        {
            var iir = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
            Assert.AreEqual("IIR", iir.Identifier);
        }

        [TestMethod]
        public void GenerateRequestTest1()
        {
            try
            {
                _ = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null));
            }
            catch (ArgumentException)
            {
                return;
            } // All is well

            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void GenerateRequestTest2()
        {
            _ = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
        }

        [TestMethod]
        public void IssueTest1()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var key1 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var caps = new List<IdentityCapability> {IdentityCapability.Generic};
            var iir1 = IdentityIssuingRequest.Generate(key1, caps);
            var components = iir1.Export().Split(new[] {'.'});
            var json = Utility.FromBase64(components[1]);
            var original = System.Text.Encoding.UTF8.GetString(json, 0, json.Length);
            var key2 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var modified = original.Replace(key1.Public, key2.Public);
            var iir2 = Item.Import<IdentityIssuingRequest>(components[0] + "." + Utility.ToBase64(modified) + "." +
                                                           components[2]);
            try
            {
                iir2.Issue(Guid.NewGuid(), 100L, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps,
                    caps);
            }
            catch (IntegrityException)
            {
                return;
            } // All is well 

            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IssueTest2()
        {
            var caps = new List<IdentityCapability> {IdentityCapability.Generic};
            var identity = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null)).Issue(Guid.NewGuid(), 100L,
                Commons.TrustedKey, Commons.TrustedIdentity, true, caps);
            Assert.IsNull(identity.TrustChain);
        }

        [TestMethod]
        public void IssueTest3()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var caps = new List<IdentityCapability> {IdentityCapability.Generic};
            var identity = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null)).Issue(Guid.NewGuid(), 100L,
                Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
            Assert.IsNotNull(identity.TrustChain);
        }

        [TestMethod]
        public void IssueTest4()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var caps = new List<IdentityCapability> {IdentityCapability.Generic};
            var identity = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null)).Issue(Guid.NewGuid(), 100L,
                Commons.IntermediateKey, Commons.IntermediateIdentity, false, caps);
            Assert.IsNull(identity.TrustChain);
        }

        [TestMethod]
        public void VerifyTest1()
        {
            var iir = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
            iir.Verify();
        }

        [TestMethod]
        public void ThumbprintTest1()
        {
            var iir = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
            var thumbprint = iir.Thumbprint();
            Assert.IsNotNull(thumbprint);
            Assert.IsTrue(thumbprint.Length > 0, "Thumbprint should not be empty string");
            Assert.IsTrue(thumbprint == iir.Thumbprint(), "Different thumbprints produced from same claim");
        }

        [TestMethod]
        public void ThumbprintTest2()
        {
            var iir1 = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
            var iir2 = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
            Assert.IsFalse(iir1.Thumbprint() == iir2.Thumbprint(),
                "Thumbprints of different iirs should not be the same");
        }

        [TestMethod]
        public void ExportTest1()
        {
            var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var iir = IdentityIssuingRequest.Generate(key);
            var exported = iir.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith($"{Envelope.Header}:{IdentityIssuingRequest.ItemIdentifier}"));
            Assert.IsTrue(exported.Split(new[] {'.'}).Length == 3);
        }

        [TestMethod]
        public void ImportTest1()
        {
            const string exported =
                "Di:IIR.eyJ1aWQiOiJkNWRkNzEyZC1hM2U3LTQ3YjAtYjRmNi0yMjU2NzJlYzZkMjMiLCJpYXQiOiIyMDIxLTEyLTAxVDIxOjA4OjQ0LjQxMzMyNloiLCJwdWIiOiIyVERYZG9Odk0xVmhNWjhpRzVZNFVlZkVBQzVFQWZiR1NacGt6OUVoWkVGNEw1a1p5RzhuVDRTSkoiLCJjYXAiOlsiZ2VuZXJpYyJdfQ.eduHuVrUY/Q9xpZVApuPjBnbG4Oo29PeTPSQIRW6xJVRYZiH0h5jEL1MgZrIFxQRPyiBQlK6BMVTc6e7OwFVDw";
            var iir = Item.Import<IdentityIssuingRequest>(exported);
            Assert.IsNotNull(iir);
            Assert.AreEqual(new Guid("d5dd712d-a3e7-47b0-b4f6-225672ec6d23"), iir.UniqueId);
            Assert.AreEqual(DateTime.Parse("2021-12-01T21:08:44.413326Z").ToUniversalTime(), iir.IssuedAt);
            Assert.IsTrue(iir.WantsCapability(IdentityCapability.Generic));
            Assert.AreEqual("2TDXdoNvM1VhMZ8iG5Y4UefEAC5EAfbGSZpkz9EhZEF4L5kZyG8nT4SJJ", iir.PublicKey.Public);
            iir.Verify();
        }

        [TestMethod]
        public void CapabilityTest1()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var requestedCapabilities = new List<IdentityCapability> {IdentityCapability.Generic, IdentityCapability.Identify};
            var iir = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), requestedCapabilities);
            try
            {
                _ = iir.Issue(Guid.NewGuid(), Dime.ValidFor1Year, Commons.IntermediateKey,
                    Commons.IntermediateIdentity, true, null);
            }
            catch (ArgumentException)
            {
                return;
            } // All is well

            Assert.IsTrue(false, "Should not happen.");
        }


        [TestMethod]
        public void CapabilityTest2()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var requestedCapabilities = new List<IdentityCapability>
                {IdentityCapability.Generic, IdentityCapability.Identify, IdentityCapability.Issue};
            var allowedCapabilities = new List<IdentityCapability> {IdentityCapability.Generic, IdentityCapability.Identify};
            var iir = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), requestedCapabilities);
            try
            {
                _ = iir.Issue(Guid.NewGuid(), Dime.ValidFor1Year, Commons.IntermediateKey,
                    Commons.IntermediateIdentity, true, allowedCapabilities);
            }
            catch (IdentityCapabilityException)
            {
                return;
            } // All is well

            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void CapabilityTest3()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var requestedCapabilities = new List<IdentityCapability> {IdentityCapability.Generic};
            var allowedCapabilities = new List<IdentityCapability> {IdentityCapability.Generic, IdentityCapability.Identify};
            var requiredCapabilities = new List<IdentityCapability> {IdentityCapability.Identify};
            var iir = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), requestedCapabilities);
            try
            {
                _ = iir.Issue(Guid.NewGuid(), Dime.ValidFor1Year, Commons.IntermediateKey,
                    Commons.IntermediateIdentity, true, allowedCapabilities, requiredCapabilities);
            }
            catch (IdentityCapabilityException)
            {
                return;
            } // All is well

            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void CapabilityTest4()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var requestedCapabilities = new List<IdentityCapability> {IdentityCapability.Generic, IdentityCapability.Identify};
            var allowedCapabilities = new List<IdentityCapability> {IdentityCapability.Generic, IdentityCapability.Identify};
            var requiredCapabilities = new List<IdentityCapability> {IdentityCapability.Identify};
            var iir = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), requestedCapabilities);
            var identity = iir.Issue(Guid.NewGuid(), Dime.ValidFor1Year, Commons.IntermediateKey,
                Commons.IntermediateIdentity, true, allowedCapabilities, requiredCapabilities);
            Assert.IsTrue(identity.HasCapability(requestedCapabilities[0]));
            Assert.IsTrue(identity.HasCapability(requestedCapabilities[1]));
        }

        [TestMethod]
        public void CapabilityTest5()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var allowedCapabilities = new List<IdentityCapability> {IdentityCapability.Generic, IdentityCapability.Identify};
            var requestedCapabilities = new List<IdentityCapability> {IdentityCapability.Issue};
            try
            {
                IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), requestedCapabilities).Issue(
                    Guid.NewGuid(), 100L, Commons.TrustedKey, Commons.TrustedIdentity, true, allowedCapabilities);
            }
            catch (IdentityCapabilityException)
            {
                return;
            } // All is well

            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void CapabilityTest6()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var caps = new List<IdentityCapability> {IdentityCapability.Issue};
            try
            {
                IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), caps)
                    .Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, null, true, caps);
            }
            catch (ArgumentNullException)
            {
                return;
            } // All is well

            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void PrinciplesTest1()
        {
            var principles = new Dictionary<string, object>
            {
                ["tag"] = "Racecar is racecar backwards.",
                ["nbr"] = new List<string> {"one", "two", "three"}
            };
            var iir = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null),
                new List<IdentityCapability> {IdentityCapability.Generic}, principles);
            var pri = iir.Principles;
            Assert.AreEqual("Racecar is racecar backwards.", pri["tag"]);
            var nbr = (List<string>) pri["nbr"];
            Assert.AreEqual(3, nbr.Count);
            Assert.AreEqual("two", nbr[1]);
        }

        [TestMethod]
        public void PrinciplesTest2()
        {
            var principles = new Dictionary<string, dynamic>
            {
                ["tag"] = "Racecar is racecar backwards.",
                ["nbr"] = new[] {"one", "two", "three"}
            };
            var iir1 = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null),
                new List<IdentityCapability> {IdentityCapability.Generic}, principles);
            var iir2 = Item.Import<IdentityIssuingRequest>(iir1.Export());
            Assert.AreEqual("Racecar is racecar backwards.", iir2.Principles["tag"]);
            var nbr = (List<string>) iir2.Principles["nbr"];
            Assert.AreEqual(3, nbr.Count);
            Assert.AreEqual("three", nbr[2]);
        }

        [TestMethod]
        public void SystemNameTest1()
        {
            var caps = new List<IdentityCapability> {IdentityCapability.Generic};
            var identity = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null)).Issue(Guid.NewGuid(), 100L,
                Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
            Assert.AreEqual(Commons.IntermediateIdentity.SystemName, identity.SystemName);
        }

        [TestMethod]
        public void SystemNameTest2()
        {
            const string system = "racecar:is:racecar:backwards";
            var caps = new List<IdentityCapability> {IdentityCapability.Generic};
            var identity = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null)).Issue(Guid.NewGuid(), 100L,
                Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps, null, system);
            Assert.AreNotEqual(Commons.IntermediateIdentity.SystemName, identity.SystemName);
            Assert.AreEqual(system, identity.SystemName);
        }

        [TestMethod]
        public void AlienIdentityIssuingRequestTest1()
        {
            var caps = new List<IdentityCapability> {IdentityCapability.Generic};
            const string exported = "Di:IIR.eyJjYXAiOlsiZ2VuZXJpYyJdLCJpYXQiOiIyMDIyLTA3LTAxVDA5OjI1OjAwLjIyNTcwM1oiLCJwdWIiOiIyVERYZG9OdnVjd1dmdjNwUE1EWnV3UmFnTVpaQURia0dYTGRIS1ZSOENyZGFBRVFnVmlrZHRUQlYiLCJ1aWQiOiIyZGYyOTExNS05YjFmLTQ0NTYtOGQzYS1jMzJmZjcwZDVmOTcifQ.3Dfa4O6oPzyZH62q0p46sNA6syL5C317grIdSpWZhny52HVZzN5uEnbiSGetHUCe8BcZsxT09NLZ40wVcrl6Bw";
            var iir = Item.Import<IdentityIssuingRequest>(exported);
            Assert.IsNotNull(iir);
            iir.Verify();
            var identity = iir.Issue(Guid.NewGuid(), Dime.ValidFor1Year,
                Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
            Assert.IsNotNull(identity);
        }

    }
    
}