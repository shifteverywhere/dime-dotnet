using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class MessageTests
    {
        [TestMethod]
        public void MessageTest1()
        {
            int profile = 1;
            Guid subjectId = Guid.NewGuid();
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.IdentityKey, profile);
            Identity issuer = this.GetIdentity(keypair);
            byte[] payload = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Message message = new Message(subjectId, issuer, payload, 10);
            Assert.IsTrue(1 == message.profile);
            Assert.AreEqual(subjectId, message.subjectId);
            Assert.AreEqual(issuer.identityKey, message.identity.identityKey);
            Assert.AreEqual(payload, message.payload);
            Assert.IsTrue(message.issuedAt >= now && message.issuedAt <= (now + 1));
            Assert.IsTrue(message.expiresAt >= (now + 10) && message.expiresAt <= (now + 10));
        }

        /* PRIVATE */
        private void SetTrustedIdentity()
        {
            Identity.trustedIdentity = Identity.IssueIdentity(IdentityIssuingRequest.GenerateRequest(this.trustedKeypair), Guid.NewGuid(), this.trustedKeypair);
        }
        private Identity GetIdentity(Keypair keypair)
        {
            return Identity.IssueIdentity(IdentityIssuingRequest.GenerateRequest(keypair), Guid.NewGuid(), this.trustedKeypair);
        }
        private Keypair trustedKeypair { get { return Keypair.GenerateKeypair(KeypairType.IdentityKey); }}

    }

}