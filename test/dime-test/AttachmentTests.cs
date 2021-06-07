//
//  AttachmentTests.cs
//  DiME - Digital Identity Message Envelope
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
    public class AttachmentTests
    {

        [TestMethod]
        public void AddItemTest1()
        {
            byte[] text = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            Attachment attachment = new Attachment();
            attachment.AddItem(text);
            byte[] itemBytes = attachment.Items[0];
            string item = System.Text.Encoding.UTF8.GetString(itemBytes, 0, itemBytes.Length);
            Assert.IsTrue(attachment.Items.Count == 1);
            Assert.AreEqual("Racecar is racecar backwards.", item);
        }

        [TestMethod]
        public void ExportTest1()
        {
            byte[] text = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            Attachment attachment = new Attachment();
            attachment.AddItem(text);
            try {
                string encoded = attachment.Export();
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void ExportTest2()
        {
            byte[] text = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            Attachment attachment = new Attachment();
            attachment.AddItem(text);
            attachment.Seal(Commons.SenderKeypair.Key);
            string encoded = attachment.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith("a" + (int)attachment.Profile));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 3);
        }

        [TestMethod]
        public void SealTest1()
        {
            Attachment attachment = new Attachment();
            try {
                attachment.Seal(Commons.SenderKeypair.Key);
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void ImportTest1()
        {
            string encoded = "a1.VW1GalpXTmhjaUJwY3lCeVlXTmxZMkZ5SUdKaFkydDNZWEprY3k0.7VG3eJsZTNRu/SHsaX1ix6YFO2iMOJzrwpssOB/DcJaNrldibHBXy71AIU9CcWNG2l39vvmiEipA1lWGrD1rDQ";
            Attachment attachment = Dime.Import<Attachment>(encoded);
            byte[] itemBytes = attachment.Items[0];
            string item = System.Text.Encoding.UTF8.GetString(itemBytes, 0, itemBytes.Length);
            Assert.IsTrue(attachment.Items.Count == 1);
            Assert.AreEqual("Racecar is racecar backwards.", item);
        }     

        [TestMethod]
        public void VerifyTest1()
        {
            Attachment attachment = new Attachment();
            try {
                attachment.Verify();
             } catch (NotImplementedException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void VerifyTest2()
        {
            byte[] text = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            Attachment attachment = new Attachment();
            attachment.AddItem(text);
            try {
                attachment.Verify(Commons.SenderKeypair.PublicKey);
             } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void VerifyTest3()
        {
            byte[] text = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            Attachment attachment = new Attachment();
            attachment.AddItem(text);
            attachment.Seal(Commons.SenderKeypair.Key);
            try {
                attachment.Verify(Commons.ReceiverKeypair.PublicKey);
             } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void VerifyTest4()
        {
            byte[] text = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            Attachment attachment = new Attachment();
            attachment.AddItem(text);
            attachment.Seal(Commons.SenderKeypair.Key);
            attachment.Verify(Commons.SenderKeypair.PublicKey);
        }

    }

}