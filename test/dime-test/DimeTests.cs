//
//  DimeTest.cs
//  DiME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Text;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class DimeTests
    {

        [TestMethod]
        public void VerifyTokenTest1()
        {
            Message message1 = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, 120);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message1.Seal(Commons.SenderKeypair.Key);
            message1.SetVerifiedToken(Commons.IntermediateIdentity, Commons.IntermediateKeypair.Key);
            string encoded = message1.Export();
            Assert.IsTrue(encoded.Split(new char[] { ':' }).Length == 4);
            Message message2 = Dime.Import<Message>(encoded);
            Assert.IsTrue(message2.HasVerifyToken);
            message2.ValidateVerifiedToken(Commons.IntermediateIdentity);
        }

        [TestMethod]
        public void VerifyTokenTest2()
        {
            Message message1 = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, 120);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message1.Seal(Commons.SenderKeypair.Key);
            string encoded1 = message1.Export();
            Message message2 = Dime.Import<Message>(encoded1);
            Assert.IsFalse(message2.HasVerifyToken);
            message2.SetVerifiedToken(Commons.IntermediateIdentity, Commons.IntermediateKeypair.Key);
            string encoded2 = message2.Export();
            Message message3 = Dime.Import<Message>(encoded2);
            Assert.IsTrue(message3.HasVerifyToken);
            message3.ValidateVerifiedToken(Commons.IntermediateIdentity);
        }

        [TestMethod]
        public void VerifyTokenTest3()
        {
            Message message1 = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, 120);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message1.Seal(Commons.SenderKeypair.Key);
            message1.SetVerifiedToken(Commons.IntermediateIdentity, Commons.IntermediateKeypair.Key);
            string encoded = message1.Export();
            Message message2 = Dime.Import<Message>(encoded);
            Assert.IsTrue(message2.HasVerifyToken);
            try {
                message2.ValidateVerifiedToken(Commons.TrustedIdentity);
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");            
        }

    }

}