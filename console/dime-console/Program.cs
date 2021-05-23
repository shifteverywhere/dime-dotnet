using System;
using System.Text;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMEConsole
{
    class Program
    {
        public Identity trustedIdentity;
        public Keypair trustedKeypair;
        public Identity serviceProviderIdentity;
        public Keypair serviceProviderKeypair;
        public Identity mobileIdentity;
        public Keypair mobileKeypair;

        public Program()
        {
            this.trustedKeypair = Keypair.GenerateKeypair(KeypairType.IdentityKey);
            this.trustedIdentity = GenerateIdentity(this.trustedKeypair);
            this.serviceProviderKeypair = Keypair.GenerateKeypair(KeypairType.IdentityKey);
            this.serviceProviderIdentity = GenerateIdentity(this.serviceProviderKeypair);
            this.mobileKeypair = Keypair.GenerateKeypair(KeypairType.IdentityKey);
            this.mobileIdentity = GenerateIdentity(this.mobileKeypair);
            Identity.trustedIdentity = this.trustedIdentity;
        }

        public Identity GenerateIdentity(Keypair keypair)
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.GenerateRequest(keypair);
            return Identity.IssueIdentity(iir, Guid.NewGuid(), this.trustedKeypair, this.trustedIdentity);
        }

        public Message GenerateMessage(Guid subjectId, Identity issuerIdentity, string payload)
        {
            long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120;
            return new Message(subjectId, issuerIdentity, Encoding.UTF8.GetBytes(payload), expiresAt);
        }

        static void Main(string[] args)
        {
            Program prg = new Program();
            // At service provider
            Message serviceProviderMessage = prg.GenerateMessage(prg.mobileIdentity.subjectId, prg.serviceProviderIdentity, "Racecar is racecar backwards.");
            string serviceProviderMessageEncoded = serviceProviderMessage.Export(prg.serviceProviderKeypair.privateKey);
            // Send 'serviceProviderMessageEncoded' to back-end
            Message serviceProviderMessageAtBackEnd = Message.Import(serviceProviderMessageEncoded);
            Envelope backEndEnvelope = new Envelope(prg.trustedIdentity, prg.mobileIdentity.subjectId, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), serviceProviderMessage.expiresAt);
            backEndEnvelope.AddMessage(serviceProviderMessage);
            string backEndEnvelopeEncoded = backEndEnvelope.Export(prg.trustedKeypair.privateKey);
            // Send 'backEndEnvelopeEncoded' to mobile
            Envelope backEndEnvelopeAtMobile = Envelope.Import(backEndEnvelopeEncoded);
            string messagePayload = System.Text.Encoding.UTF8.GetString(backEndEnvelopeAtMobile.messages[0].GetPayload(), 0, backEndEnvelopeAtMobile.messages[0].GetPayload().Length);
            Console.WriteLine("Message from service provider: " + messagePayload);
            Message mobileResponseMessage = prg.GenerateMessage(prg.mobileIdentity.subjectId, prg.serviceProviderIdentity, "Yes, it is!");
            mobileResponseMessage.LinkMessage(backEndEnvelopeAtMobile.messages[0]); // link the mobile response to the received service provider message       
            Envelope mobileEnvelope = new Envelope(prg.mobileIdentity, prg.serviceProviderIdentity.issuerId, mobileResponseMessage.issuedAt, backEndEnvelopeAtMobile.expiresAt);
            mobileEnvelope.AddMessage(backEndEnvelopeAtMobile.messages[0]);
            mobileEnvelope.AddMessage(mobileResponseMessage);
            string mobileEnvelopeEncoded = mobileEnvelope.Export(prg.mobileKeypair.privateKey);
            // Send 'mobileEnvelopeEncoded' to back-end
            Envelope mobleEnvelopeAtBackEnd = Envelope.Import(mobileEnvelopeEncoded);
            Envelope finalBackEndEnvelope = new Envelope(prg.trustedIdentity, mobileEnvelope.subjectId, DateTimeOffset.UtcNow.ToUnixTimeSeconds(), mobileEnvelope.expiresAt);
            finalBackEndEnvelope.AddMessage(mobleEnvelopeAtBackEnd.messages[0]);
            finalBackEndEnvelope.AddMessage(mobleEnvelopeAtBackEnd.messages[1]);
            string finalBackEndEnvelopeEncoded = finalBackEndEnvelope.Export(prg.trustedKeypair.privateKey);
            // Send 'finalBackEndEnvelopeEncoded' to service provider
            Envelope finalBackEndEnvelopeAtServiceProvider = Envelope.Import(finalBackEndEnvelopeEncoded);
            string responcePayload = System.Text.Encoding.UTF8.GetString(finalBackEndEnvelopeAtServiceProvider.messages[1].GetPayload(), 0, finalBackEndEnvelopeAtServiceProvider.messages[1].GetPayload().Length);
            Console.WriteLine("Responce from mobile: " + responcePayload);
        }
    }
}
