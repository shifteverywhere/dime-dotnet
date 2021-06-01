//
//  Program.cs
//  DiME - Digital Identity Message Envelope
//  Compact messaging format for assertion and use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Collections.Generic;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMEConsole
{
    class Program
    {
        public Identity trustedIdentity;
        public KeyBox trustedKeypair;
        public Identity serviceProviderIdentity;
        public KeyBox serviceProviderKeypair;
        public Identity mobileIdentity;
        public KeyBox mobileKeypair;

        public Program()
        {
            this.trustedKeypair = KeyBox.GenerateKey(KeyType.Identity);
            this.trustedIdentity = GenerateIdentity(this.trustedKeypair);
            this.serviceProviderKeypair = KeyBox.GenerateKey(KeyType.Identity);
            this.serviceProviderIdentity = GenerateIdentity(this.serviceProviderKeypair);
            this.mobileKeypair = KeyBox.GenerateKey(KeyType.Identity);
            this.mobileIdentity = GenerateIdentity(this.mobileKeypair);
            Dime.SetTrustedIdentity(this.trustedIdentity);
        }

        public Identity GenerateIdentity(KeyBox keypair)
        {
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(keypair, caps);    
            return iir.IssueIdentity(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, caps, this.trustedKeypair, this.trustedIdentity);
        }

        public Message GenerateMessage(Guid subjectId, Identity issuerIdentity, string payload)
        {
            long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120;
            Message msg = new Message(subjectId, issuerIdentity, expiresAt);
            msg.SetPayload(Encoding.UTF8.GetBytes(payload));
            return msg;
        }

        static void Main(string[] args)
        {
            Program prg = new Program();
            
            /** At service provider side **/
            Message serviceProviderMessage = prg.GenerateMessage(prg.mobileIdentity.SubjectId, prg.serviceProviderIdentity, "Racecar is racecar backwards.");
            serviceProviderMessage.Seal(prg.serviceProviderKeypair.Key);
            string serviceProviderMessageEncoded = serviceProviderMessage.Export();
            // ==> Send 'serviceProviderMessageEncoded' to back-end

            /** At back-end side **/
            Message serviceProviderMessageAtBackEnd = Dime.Import<Message>(serviceProviderMessageEncoded);
            serviceProviderMessageAtBackEnd.Verify();
            Envelope backEndEnvelope = new Envelope(prg.trustedIdentity, prg.mobileIdentity.SubjectId, 120);
            backEndEnvelope.AddMessage(serviceProviderMessage);
            backEndEnvelope.Seal(prg.trustedKeypair.Key);
            string backEndEnvelopeEncoded = backEndEnvelope.Export();
            // ==> Send 'backEndEnvelopeEncoded' to mobile

            /** At mobile side **/
            Envelope backEndEnvelopeAtMobile = Dime.Import<Envelope>(backEndEnvelopeEncoded);
            backEndEnvelopeAtMobile.Verify();
            string messagePayload = System.Text.Encoding.UTF8.GetString(backEndEnvelopeAtMobile.Messages[0].GetPayload(), 0, backEndEnvelopeAtMobile.Messages[0].GetPayload().Length);
            Console.WriteLine("Message from service provider: " + messagePayload);
            Message mobileResponseMessage = prg.GenerateMessage(prg.mobileIdentity.SubjectId, prg.serviceProviderIdentity, "Yes, it is!");
            mobileResponseMessage.LinkMessage(backEndEnvelopeAtMobile.Messages[0]); // link the mobile response to the received service provider message       
            Envelope mobileEnvelope = new Envelope(prg.mobileIdentity, prg.serviceProviderIdentity.IssuerId, 120);
            mobileEnvelope.AddMessage(backEndEnvelopeAtMobile.Messages[0]);
            mobileEnvelope.AddMessage(mobileResponseMessage);
            mobileEnvelope.Seal(prg.mobileKeypair.Key);
            string mobileEnvelopeEncoded = mobileEnvelope.Export();
            // ==> Send 'mobileEnvelopeEncoded' to back-end

            /** At back-end side **/
            Envelope mobleEnvelopeAtBackEnd = Dime.Import<Envelope>(mobileEnvelopeEncoded);
            mobleEnvelopeAtBackEnd.Verify();
            Envelope finalBackEndEnvelope = new Envelope(prg.trustedIdentity, mobileEnvelope.SubjectId, 120);
            finalBackEndEnvelope.AddMessage(mobleEnvelopeAtBackEnd.Messages[0]);
            finalBackEndEnvelope.AddMessage(mobleEnvelopeAtBackEnd.Messages[1]);
            finalBackEndEnvelope.Seal(prg.trustedKeypair.Key);
            string finalBackEndEnvelopeEncoded = finalBackEndEnvelope.Export();
            // ==> Send 'finalBackEndEnvelopeEncoded' to service provider

            /** At service provider side **/
            Envelope finalBackEndEnvelopeAtServiceProvider = Dime.Import<Envelope>(finalBackEndEnvelopeEncoded);
            finalBackEndEnvelopeAtServiceProvider.Verify();
            string responcePayload = System.Text.Encoding.UTF8.GetString(finalBackEndEnvelopeAtServiceProvider.Messages[1].GetPayload(), 0, finalBackEndEnvelopeAtServiceProvider.Messages[1].GetPayload().Length);
            Console.WriteLine("Responce from mobile: " + responcePayload);
        }
    }
}
