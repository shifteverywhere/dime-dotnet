//
//  EnvelopeTests.cs
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
    public class EnvelopeTests
    {
        [TestMethod]
        public void EnvelopeTest1()
        {
            ProfileVersion profile = ProfileVersion.One;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10, profile);
            Assert.AreEqual(ProfileVersion.One, envelope.Profile);
            Assert.IsNotNull(envelope.Id);
            Assert.AreEqual(Commons.SenderIdentity.SubjectId, envelope.IssuerId);
            Assert.AreEqual(Commons.ReceiverIdentity.SubjectId, envelope.SubjectId);
            Assert.IsTrue(envelope.IssuedAt >= now && envelope.IssuedAt <= (now + 1));
            Assert.IsTrue(envelope.ExpiresAt >= (now + 10) && envelope.ExpiresAt <= (now + 11));         
        }

        [TestMethod]
        public void ExportTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            envelope.AddMessage(GetMessage("Racecar is racecar backwards."));
            envelope.Seal(Commons.SenderKeypair.Key);
            string encoded = envelope.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith(Dime.DIME_HEADER));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 6);          
        }

        [TestMethod]
        public void ExportTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            try {
                envelope.Export();
            } catch(IntegrityException) { } // All is well
        }

        [TestMethod]
        public void ExportTest3()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            envelope.AddMessage(GetMessage("Racecar is racecar backwards."));
            envelope.Seal(Commons.SenderKeypair.Key);
            envelope.Export();
            try {
                envelope.ExpiresAt = envelope.ExpiresAt + 100;
                envelope.Export();
            } catch(IntegrityException) { } // All is well
        }

        [TestMethod]
        public void SealTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            try {
                envelope.Seal(Commons.SenderKeypair.Key);
            } catch(DataFormatException) { return; } // All is well
        }

        [TestMethod]
        public void SealTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = GetMessage("Racecar is racecar backwards.");
            Message response = GetResponse("It is!", message);
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 120);
            envelope.AddMessage(message);
            envelope.AddMessage(response);
            envelope.Seal(Commons.SenderKeypair.Key);
        } 

        [TestMethod]
        public void ImportTest1()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            string encoded = "DI1.aW8uZGltZWZvcm1hdC5lbnY.REkxLmFXOHVaR2x0WldadmNtMWhkQzVwWkEuZXlKemRXSWlPaUkwTVRRMFpUa3dNaTB3WXpGa0xUUTRORGd0T1RCbVl5MWxaREJrT1RNek9HSTJNek1pTENKcGMzTWlPaUk1WVdVNE5EVm1aaTA0TnpRM0xUUXlZV0l0WW1SaFlpMWxZbU14TldNNE9HRTNOMlFpTENKcFlYUWlPakUyTWpNeE9ERXhNemNzSW1WNGNDSTZNVFkxTkRjeE56RXpOeXdpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFUbHpZVlZEUW5OY2RUQXdNa0pOTkhOU2FqVnVhVVoxUmxaWEwzTTFZazVGVUd4eVZsTTNTMGxNVm1aelVGSnFieUlzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVdSbGJuUnBabmtpWFgwLlJFa3hMbUZYT0hWYVIyeDBXbGRhZG1OdE1XaGtRelZ3V2tFdVpYbEtlbVJYU1dsUGFVazFXVmRWTkU1RVZtMWFhVEEwVG5wUk0weFVVWGxaVjBsMFdXMVNhRmxwTVd4WmJVMTRUbGROTkU5SFJUTk9NbEZwVEVOS2NHTXpUV2xQYVVrelRsUkJNRTVxUVROTmFUQXhUV3BaTkV4VVVURmFWR2QwV1cxV2FFNVRNREphUkZGNFQxZEZOVTV0U1hsT2FrVnBURU5LY0ZsWVVXbFBha1V5VFdwTmVFOUVRVFJOVkdOelNXMVdOR05EU1RaTlZHTTBUVVJuTWsxRVozaE9lWGRwWVZkME5VbHFiMmxVVlU1MlpEQktVbGRWVWt4TmJGb3pVVmhzUmxGWGRIUmFiRlpYVW01bk1scFVRbHBpYTJ4d1QxWldZV0l4VVhsVlZrcEZUa2RhUkZGNlNUQldWMHBTV2toc01XSklUalJpV0dSalpGUkJkMDFyU2t0V1UwbHpTVzFPYUdORFNUWlhlVXB1V2xjMWJHTnRiR3BKYVhkcFlWaE9lbVJYVldsWVdEQXVkeXRMTUV3Mk1FSnVaM1ZDWW14Nk0zWmtjV2RKSzJkbk1HOURXWEYxZUhGVk5qQlFUVFZrUzFSVFIxTmpiMUJpYkRVM01sRnpTM0p0VlRGdmQwWnFWMHQzTjNSUVZUVndjR1ZSWlNzd2IyRnlVMHBLUkdjLk1KdS85c0tYK3VGNWtnRFNiSEh3ck50Rk9LSjk2dXBoNDdCRmRMWC9SVEthU3BBUU5WRlFjMTAzdkhwWTRLaVVQcURSd0w3eCtwUGRxTzlLcDl6ZEJR.REkxLmFXOHVaR2x0WldadmNtMWhkQzV0YzJjLlJFa3hMbUZYT0hWYVIyeDBXbGRhZG1OdE1XaGtRelZ3V2tFdVpYbEtlbVJYU1dsUGFVa3dUVlJSTUZwVWEzZE5hVEIzV1hwR2EweFVVVFJPUkdkMFQxUkNiVmw1TVd4YVJFSnJUMVJOZWs5SFNUSk5lazFwVEVOS2NHTXpUV2xQYVVrMVdWZFZORTVFVm0xYWFUQTBUbnBSTTB4VVVYbFpWMGwwV1cxU2FGbHBNV3haYlUxNFRsZE5ORTlIUlROT01sRnBURU5LY0ZsWVVXbFBha1V5VFdwTmVFOUVSWGhOZW1OelNXMVdOR05EU1RaTlZGa3hUa1JqZUU1NlJYcE9lWGRwWVZkME5VbHFiMmxVVlU1MlpEQktVbGRWVWt4TmJGb3pVVmhzUmxGVWJIcFpWbFpFVVc1T1kyUlVRWGROYTBwT1RraE9VMkZxVm5WaFZWb3hVbXhhV0V3elRURlphelZHVlVkNGVWWnNUVE5UTUd4TlZtMWFlbFZHU25GaWVVbHpTVzFPYUdORFNUWlhlVXB1V2xjMWJHTnRiR3BKYVhkcFlWZFNiR0p1VW5CYWJtdHBXRmd3TGxKRmEzaE1iVVpZVDBoV1lWSXllREJYYkdSaFpHMU9kRTFYYUd0UmVsWjNWMnRGZFZwWWJFdGxiVkpZVTFkc1VHRlZhekZYVm1SV1RrVTFSVlp0TVdGaFZFRXdWRzV3VWswd2VGVlZXR3hhVmpCc01GZFhNVk5oUm14d1RWZDRXbUpWTVRSVWJHUk9Ua1U1U0ZKVVRrOU5iRVp3VkVWT1MyTkhUWHBVVjJ4UVlWVnJlbFJzVWtKTlJUVnhVVlJPVG1GVVFYaFVWM0JhVGtWNFZWVlVSbUZXUjJRd1YxY3hWMkZGTlZSTlJFcGhVa1pHTkZReFpFWk9WVFYwVTFoc1QyRnJWbkJVUlU1TFkwWnNXVlZYYkZCaGExVjVWRmR3VG1WRk9VVlJWRkpPVmtkT2VsTlhNVmRPUjA1RVUxUmFUbFpIVFRCVVZWSnVUV3N4UlZvemFFOWxXR1J3V1Zaa01FNVZiSEZpTW14VlZsVTFNbHBFUWt0VmJHUldWV3Q0VG1KR2IzcFZWbWh6VW14R1dHUklVbUZpUmxwWVZXMDFiazFzY0ZWUmJIQnBZVEo0ZDFReFdsZFpWMGw0VlZoc1ZsWnJjRVpVYTJSaFVrWkdObE5VUWxkV01IQlRWMnRvYzAxWFNrbFVhbEpwVjBkU2FscEdVa0prTURGeVUydDBWMVV3YkhwVFZ6RlBZVWRPUkZOVVdsaGxWWEIxVjJ4ak1XSkhUblJpUjNCS1lWaGtjRmxXYUU5bGJWSllWbGRzV1ZkRVFYVmtlWFJNVFVWM01rMUZTblZhTTFaRFdXMTROazB6V210alYyUktTekprYmsxSE9VUlhXRVl4WlVoR1ZrNXFRbEZVVkZaclV6RlNWRkl4VG1waU1VSnBZa1JWTTAxc1JucFRNMHAwVmxSR2RtUXdXbkZXTUhRelRqTlNVVlpVVm5kalIxWlNXbE56ZDJJeVJubFZNSEJMVWtkakxrMUtkUzg1YzB0WUszVkdOV3RuUkZOaVNFaDNjazUwUms5TFNqazJkWEJvTkRkQ1JtUk1XQzlTVkV0aFUzQkJVVTVXUmxGak1UQXpka2h3V1RSTGFWVlFjVVJTZDB3M2VDdHdVR1J4VHpsTGNEbDZaRUpSLmV5SjFhV1FpT2lKbFpEVmtabVpqTVMwNFpEY3pMVFJrTkRFdFlqSTJPUzAxTkRKaFkyTmxaV0UyTmpZaUxDSnpkV0lpT2lJMU4yWXhPREV6WWkweFpUTmtMVFEyT0dRdE9UQTBNaTB6TnpnNVpUVXpORGRsTjJNaUxDSnBjM01pT2lJME1UUTBaVGt3TWkwd1l6RmtMVFE0TkRndE9UQm1ZeTFsWkRCa09UTXpPR0kyTXpNaUxDSnBZWFFpT2pFMk1qTXhPRFF5TXpZc0ltVjRjQ0k2TVRZeU16RTRORE0xTm4wLlVtRmpaV05oY2lCcGN5QnlZV05sWTJGeUlHSmhZMnQzWVhKa2N5NC5xcEJKdWFmRFIrY2lVUVZsMUxaZWUzOWh6RjgrRm80VEk1TkVTa2JEZVJMN3VNYkpHc2FwR3RESDg4cmlHWTNTTjAwTUltbHBNcVg3NzM0bHl0eFVCUQ.eyJ1aWQiOiJhOTUyNDIxMC0wMGY4LTQyY2QtYjNhOC02ZmIzNTc1MWU1Y2QiLCJzdWIiOiI1N2YxODEzYi0xZTNkLTQ2OGQtOTA0Mi0zNzg5ZTUzNDdlN2MiLCJpc3MiOiI0MTQ0ZTkwMi0wYzFkLTQ4NDgtOTBmYy1lZDBkOTMzOGI2MzMiLCJpYXQiOjE2MjMxODQyMzYsImV4cCI6MTYyMzE4NDI0Nn0.dC4yWTMcfzAxA7Zsc/IQEuMush+tYrqvvN/iWNE/wazo4ktX3K39Bq4mVsdcRMsiuwEUrIuxmiGiE63JjkikBQ";
            Envelope envelope = Dime.Import<Envelope>(encoded);
            Assert.AreEqual(new Guid("a9524210-00f8-42cd-b3a8-6fb35751e5cd"), envelope.Id);
            Assert.AreEqual(new Guid("57f1813b-1e3d-468d-9042-3789e5347e7c"), envelope.SubjectId);
            Assert.AreEqual(new Guid("4144e902-0c1d-4848-90fc-ed0d9338b633"), envelope.IssuerId);
            Assert.AreEqual(1623184236, envelope.IssuedAt);
            Assert.AreEqual(1623184246, envelope.ExpiresAt);
            Assert.IsNotNull(envelope.Identity);
            Assert.IsNotNull(envelope.Messages);
        }

        [TestMethod]
        public void ImportTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            string encoded = "DI1.aW8uZGltZWZvcm1hdC5tc2c.REkxLmFXOHVaR2x0WldadmNtMWhkQzVwWkEuZXlKemRXSWlPaUkwTVRRMFpUa3dNaTB3WXpGa0xUUTRORGd0T1RCbVl5MWxaREJrT1RNek9HSTJNek1pTENKcGMzTWlPaUk1WVdVNE5EVm1aaTA0TnpRM0xUUXlZV0l0WW1SaFlpMWxZbU14TldNNE9HRTNOMlFpTENKcFlYUWlPakUyTWpNeE9ERXhNemNzSW1WNGNDSTZNVFkxTkRjeE56RXpOeXdpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFUbHpZVlZEUW5OY2RUQXdNa0pOTkhOU2FqVnVhVVoxUmxaWEwzTTFZazVGVUd4eVZsTTNTMGxNVm1aelVGSnFieUlzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVdSbGJuUnBabmtpWFgwLlJFa3hMbUZYT0hWYVIyeDBXbGRhZG1OdE1XaGtRelZ3V2tFdVpYbEtlbVJYU1dsUGFVazFXVmRWTkU1RVZtMWFhVEEwVG5wUk0weFVVWGxaVjBsMFdXMVNhRmxwTVd4WmJVMTRUbGROTkU5SFJUTk9NbEZwVEVOS2NHTXpUV2xQYVVrelRsUkJNRTVxUVROTmFUQXhUV3BaTkV4VVVURmFWR2QwV1cxV2FFNVRNREphUkZGNFQxZEZOVTV0U1hsT2FrVnBURU5LY0ZsWVVXbFBha1V5VFdwTmVFOUVRVFJOVkdOelNXMVdOR05EU1RaTlZHTTBUVVJuTWsxRVozaE9lWGRwWVZkME5VbHFiMmxVVlU1MlpEQktVbGRWVWt4TmJGb3pVVmhzUmxGWGRIUmFiRlpYVW01bk1scFVRbHBpYTJ4d1QxWldZV0l4VVhsVlZrcEZUa2RhUkZGNlNUQldWMHBTV2toc01XSklUalJpV0dSalpGUkJkMDFyU2t0V1UwbHpTVzFPYUdORFNUWlhlVXB1V2xjMWJHTnRiR3BKYVhkcFlWaE9lbVJYVldsWVdEQXVkeXRMTUV3Mk1FSnVaM1ZDWW14Nk0zWmtjV2RKSzJkbk1HOURXWEYxZUhGVk5qQlFUVFZrUzFSVFIxTmpiMUJpYkRVM01sRnpTM0p0VlRGdmQwWnFWMHQzTjNSUVZUVndjR1ZSWlNzd2IyRnlVMHBLUkdjLk1KdS85c0tYK3VGNWtnRFNiSEh3ck50Rk9LSjk2dXBoNDdCRmRMWC9SVEthU3BBUU5WRlFjMTAzdkhwWTRLaVVQcURSd0w3eCtwUGRxTzlLcDl6ZEJR.eyJ1aWQiOiJjNGY3ZDJhNC0xNTQ5LTQ0ZGYtOGVhMS01MDVhMmQ5OThhYmYiLCJzdWIiOiIyNjBmZWM3Zi1jODgzLTQ4ZjMtODFmMS1lYTkyZTZiNTM1YmYiLCJpc3MiOiI0MTQ0ZTkwMi0wYzFkLTQ4NDgtOTBmYy1lZDBkOTMzOGI2MzMiLCJpYXQiOjE2MjMxODMxOTIsImV4cCI6MTYyMzE4MzIwMn0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.MgxHn8hjzvK5Mggn3FEc/6iS71CbAf5xLWWHpQhSAkcMrUpGhYAqMt7lO8QXqR4xEPHm7nBUaU+o2vA1NImWCQ";
            try {
                Dime.Import<Envelope>(encoded);
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSealedTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            envelope.AddMessage(GetMessage("Racecar is racecar backwards."));
            Assert.IsFalse(envelope.IsSealed);
            envelope.Seal(Commons.SenderKeypair.Key);
            Assert.IsTrue(envelope.IsSealed);
        }

        [TestMethod]
        public void IdTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            envelope.AddMessage(GetMessage("Racecar is racecar backwards."));
            envelope.Seal(Commons.SenderKeypair.Key);
            Guid uid1 = envelope.Id;
            envelope.ExpiresAt = envelope.ExpiresAt + 100;
            Assert.AreNotEqual(uid1, envelope.Id);
        }

        [TestMethod]
        public void AddMessageTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Envelope envelope1 = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 100);
            envelope1.AddMessage(GetMessage("Racecar is racecar backwards."));
            envelope1.Seal(Commons.SenderKeypair.Key);
            string encoded = envelope1.Export();

            Envelope envelope2 = Dime.Import<Envelope>(encoded);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(envelope2.Messages[0].GetPayload()));
        }  

        [TestMethod]
        public void VerifyTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 100);
            envelope.AddMessage(GetMessage("Racecar is racecar backwards."));
            try {
                envelope.Verify(false);
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen");
        }

        [TestMethod]
        public void ThumbprintTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Envelope envelope1 = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 120);
            envelope1.AddMessage(GetMessage("Racecar is racecar backwards."));
            envelope1.Seal(Commons.SenderKeypair.Key);
            string thumbprint1 = envelope1.Thumbprint();
            string encoded = envelope1.Export();
            Envelope envelope2 = Dime.Import<Envelope>(encoded);
            string thumbprint2 = envelope2.Thumbprint();
            Assert.AreEqual(thumbprint1, thumbprint2);
        }

        [TestMethod]
        public void ThumbprintTest2()
        {   
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = GetMessage("Racecar is racecar backwards.");
            Envelope envelope1 = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 120);
            envelope1.AddMessage(message);
            envelope1.Seal(Commons.SenderKeypair.Key);
            Envelope envelope2 = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 120);
            envelope2.AddMessage(message);
            envelope2.Seal(Commons.SenderKeypair.Key);
            Assert.AreNotEqual(envelope1.Thumbprint(), envelope2.Thumbprint());
        }

        [TestMethod]
        public void ThumbprintTest3()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 120);
            try {
                envelope.Thumbprint();
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        #region -- PRIVATE --
        private Message GetMessage(string payload)
        {
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity, 120);
            message.SetPayload(Encoding.UTF8.GetBytes(payload));
            message.Seal(Commons.SenderKeypair.Key);
            return message;
        }

        private Message GetResponse(string payload, Message linkedMessage = null)
        {
            Message message = new Message(Commons.SenderIdentity.SubjectId, Commons.ReceiverIdentity, 120);
            message.SetPayload(Encoding.UTF8.GetBytes(payload));
            if (linkedMessage != null)
            {
                message.LinkMessage(linkedMessage);
            }
            message.Seal(Commons.ReceiverKeypair.Key);
            return message;
        }
        #endregion

    }

}
