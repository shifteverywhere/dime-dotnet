//
//  Base58Tests.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class Base58Tests
    {
        [TestMethod]
        public void EncodeTest1() {
            byte[] bytes = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            string b58 = Base58.Encode(bytes);
            int i = 0;
        }

    }

}