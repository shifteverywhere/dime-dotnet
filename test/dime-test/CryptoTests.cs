//
//  Crypto.cs
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
    public class CryptoTests
    {

        [TestMethod]
        public void EncryptTest1() {

            
            string nonce = "82yTd7yxWtmaHaoY";
            string cipherText = "C7L9psdBgQ62otVMXsnjVwS3UNOva+ekuY6gg3aSg0znQ4rGQ/qjQbaFXd/f";
            string secret = "AAHgAC2Lo+h554Sn6XEbLFCDlXxCis4CzfhZiY862eYAA1Se";

            Crypto.Decrypt()



        }


        [TestMethod]
        public void GenerateHashTest1() {
            string expected = "b9f050dd8bfbf027ea9fc729e9e764fda64c2bca20030a5d25264c35c486d892";
            byte[] data = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            byte[] hash = Crypto.GenerateHash(Profile.Uno, data);
            Assert.IsNotNull(hash);
            String hex = Utility.ToHex(hash);
            Assert.AreEqual(expected, hex);
        }

    }

}