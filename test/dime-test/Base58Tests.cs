//
//  Base58Tests.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class Base58Tests
    {

        [TestMethod]
        public void EncodeTest1() 
        {
            const string reference = "1424C2F4bC9JidNjjTUZCbUxv6Sa1Mt62x";
            var bytes = new byte[] { 0x21, 0x1b, 0x74, 0xca, 0x46, 0x86, 0xf8, 0x1e, 0xfd, 0xa5, 0x64, 0x17, 0x67, 0xfc, 0x84, 0xef, 0x16, 0xda, 0xfe, 0x0b };
            var base58 = Base58.Encode(bytes, new byte[] { 0x00 });
            Assert.AreEqual(reference, base58);
        }

        [TestMethod]
        public void EncodeTest2() 
        {
            const string str = "Racecar is racecar backwards.";
            var base58 = Base58.Encode(Encoding.UTF8.GetBytes(str), new byte[] { 0x00 });
            Assert.AreEqual("1RUP8qykPEgwU7tFVRBorfw2BdwmQX9q9VR5oELDCQndpL", base58);
        }

        [TestMethod]
        public void DecodeTest1() 
        {                   
            const string base58 = "1RUP8qykPEgwU7tFVRBorfw2BdwmQX9q9VR5oELDCQndpL";
            var bytes = Base58.Decode(base58);
            Assert.IsTrue(bytes[0] == 0x00);
            var decoded = System.Text.Encoding.UTF8.GetString(Utility.SubArray(bytes, 1));
            Assert.AreEqual("Racecar is racecar backwards.", decoded);
        }

    }

}