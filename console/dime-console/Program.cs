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
            this.trustedKeypair = Keypair.GenerateKeypair(KeypairType.Identity);
            this.trustedIdentity = GenerateIdentity(this.trustedKeypair);
            this.serviceProviderKeypair = Keypair.GenerateKeypair(KeypairType.Identity);
            this.serviceProviderIdentity = GenerateIdentity(this.serviceProviderKeypair);
            this.mobileKeypair = Keypair.GenerateKeypair(KeypairType.Identity);
            this.mobileIdentity = GenerateIdentity(this.mobileKeypair);
            Identity.TrustedIdentity = this.trustedIdentity;
        }

        public Identity GenerateIdentity(Keypair keypair)
        {
            Identity.Capability[] caps = new Identity.Capability[2] {Identity.Capability.Authorize, Identity.Capability.Authorize};
            IdentityIssuingRequest iir = IdentityIssuingRequest.GenerateRequest(keypair, caps);            
            return Identity.IssueIdentity(iir, Guid.NewGuid(), caps, this.trustedKeypair, this.trustedIdentity);
        }

        public Message GenerateMessage(Guid subjectId, Identity issuerIdentity, string payload)
        {
            long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120;
            Message msg = new Message(subjectId, issuerIdentity, expiresAt);
            msg.AddPayload(Encoding.UTF8.GetBytes(payload));
            return msg;
        }

        static void Main(string[] args)
        {
            Program prg = new Program();
            // At service provider
            Message serviceProviderMessage = prg.GenerateMessage(prg.mobileIdentity.SubjectId, prg.serviceProviderIdentity, "Racecar is racecar backwards.");
            string serviceProviderMessageEncoded = serviceProviderMessage.Export(prg.serviceProviderKeypair.PrivateKey);
            // Send 'serviceProviderMessageEncoded' to back-end
            Message serviceProviderMessageAtBackEnd = Message.Import(serviceProviderMessageEncoded);
            Envelope backEndEnvelope = new Envelope(prg.trustedIdentity, prg.mobileIdentity.SubjectId, 120);
            backEndEnvelope.AddMessage(serviceProviderMessage);
            backEndEnvelope.Seal(prg.trustedKeypair.PrivateKey);
            string backEndEnvelopeEncoded = backEndEnvelope.Export();
            // Send 'backEndEnvelopeEncoded' to mobile
            Envelope backEndEnvelopeAtMobile = Envelope.Import(backEndEnvelopeEncoded);
            string messagePayload = System.Text.Encoding.UTF8.GetString(backEndEnvelopeAtMobile.Messages[0].GetPayload(), 0, backEndEnvelopeAtMobile.Messages[0].GetPayload().Length);
            Console.WriteLine("Message from service provider: " + messagePayload);
            Message mobileResponseMessage = prg.GenerateMessage(prg.mobileIdentity.SubjectId, prg.serviceProviderIdentity, "Yes, it is!");
            mobileResponseMessage.LinkMessage(backEndEnvelopeAtMobile.Messages[0]); // link the mobile response to the received service provider message       
            Envelope mobileEnvelope = new Envelope(prg.mobileIdentity, prg.serviceProviderIdentity.IssuerId, 120);
            mobileEnvelope.AddMessage(backEndEnvelopeAtMobile.Messages[0]);
            mobileEnvelope.AddMessage(mobileResponseMessage);
            mobileEnvelope.Seal(prg.mobileKeypair.PrivateKey);
            string mobileEnvelopeEncoded = mobileEnvelope.Export();
            // Send 'mobileEnvelopeEncoded' to back-end
            Envelope mobleEnvelopeAtBackEnd = Envelope.Import(mobileEnvelopeEncoded);
            Envelope finalBackEndEnvelope = new Envelope(prg.trustedIdentity, mobileEnvelope.SubjectId, 120);
            finalBackEndEnvelope.AddMessage(mobleEnvelopeAtBackEnd.Messages[0]);
            finalBackEndEnvelope.AddMessage(mobleEnvelopeAtBackEnd.Messages[1]);
            finalBackEndEnvelope.Seal(prg.trustedKeypair.PrivateKey);
            string finalBackEndEnvelopeEncoded = finalBackEndEnvelope.Export();
            // Send 'finalBackEndEnvelopeEncoded' to service provider
            Envelope finalBackEndEnvelopeAtServiceProvider = Envelope.Import(finalBackEndEnvelopeEncoded);
            string responcePayload = System.Text.Encoding.UTF8.GetString(finalBackEndEnvelopeAtServiceProvider.Messages[1].GetPayload(), 0, finalBackEndEnvelopeAtServiceProvider.Messages[1].GetPayload().Length);
            Console.WriteLine("Responce from mobile: " + responcePayload);
        }
    }
}
