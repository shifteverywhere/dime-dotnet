//
//  Program.cs
//  DiME - Digital Identity Message Envelope
//  Compact messaging format for assertion and use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//

using System;
using System.Diagnostics;
using System.Threading;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using ShiftEverywhere.DiME;
using System.Runtime.CompilerServices;

namespace ShiftEverywhere.DiMEConsole
{
    class Program
    {
        public Identity trustedIdentity;
        public Key trustedKeypair;
        public Identity serviceProviderIdentity;
        public Key serviceProviderKeypair;
        public Identity mobileIdentity;
        public Key mobileKeypair;

        public Program()
        {
            this.trustedKeypair = Key.Generate(KeyType.Identity);
            this.trustedIdentity = GenerateIdentity(this.trustedKeypair, new List<Capability> { Capability.Issue, Capability.Generic, Capability.Identify });
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Trusted Key Pair");
            Console.WriteLine("private key : " + this.trustedKeypair.Secret.ToString());
            Console.WriteLine("public key : " + this.trustedKeypair.Public.ToString());
            Console.WriteLine("Thumbprint : " + this.trustedIdentity.Thumbprint().ToString());
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            this.serviceProviderKeypair = Key.Generate(KeyType.Identity);
            this.serviceProviderIdentity = GenerateIdentity(this.serviceProviderKeypair, new List<Capability> { Capability.Generic, Capability.Identify });
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Service Provider Key Pair");
            Console.WriteLine("private key : " + this.serviceProviderKeypair.Secret.ToString());
            Console.WriteLine("public key : " + this.serviceProviderKeypair.Public.ToString());
            Console.WriteLine("Thumbprint : " + this.serviceProviderIdentity.Thumbprint().ToString());
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            this.mobileKeypair = Key.Generate(KeyType.Identity);
            this.mobileIdentity = GenerateIdentity(this.mobileKeypair, new List<Capability> {  Capability.Generic, Capability.Identify });
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Mobile Key Pair");
            Console.WriteLine("private key : " + this.mobileKeypair.Secret.ToString());
            Console.WriteLine("public key : " + this.mobileKeypair.Public.ToString());
            Console.WriteLine("Thumbprint : " + this.mobileIdentity.Thumbprint().ToString());
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            Identity.SetTrustedIdentity(this.trustedIdentity);
        }

        public Identity GenerateIdentity(Key keypair, List<Capability> capabilities)
        {
            List<Capability> caps = capabilities;
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(keypair, caps);    
            return iir.Issue(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, this.trustedKeypair, this.trustedIdentity, caps, null);
        }

        public Message GenerateMessage(Identity audience, Identity issuer, string payload)
        {
            long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120;
            Message msg = new Message(audience.SubjectId, issuer.SubjectId, expiresAt);
            msg.SetPayload(Encoding.UTF8.GetBytes(payload));
            return msg;
        }

        public static void NewSendMessage(Program prg)
        {
            /** At service provider side **/
            Message sp_message = prg.GenerateMessage(prg.mobileIdentity, prg.serviceProviderIdentity, "Racecar is racecar backwards.");
            sp_message.Sign(prg.serviceProviderKeypair);
            string sp_message_encoded = sp_message.Export();
            // ==> Send 'sp_envelope_encoded' to back-end

            /** At back-end side **/
            Message sp_message_at_backend = Item.Import<Message>(sp_message_encoded);
            // sp_message_at_backend.IssuerId == prg.serviceProviderIdentity.SubjectId -> look up and fetch service provider identity
            sp_message_at_backend.Verify(prg.serviceProviderIdentity.PublicKey);
            Envelope be_envelope = new Envelope();
            be_envelope.AddItem(sp_message_at_backend);
            be_envelope.Sign(prg.trustedKeypair);
            string be_envelope_encoded = be_envelope.Export();
            // ==> Send 'be_envelope_encoded' to mobile

            /** At mobile side **/
            Envelope be_envelope_at_mob = Envelope.Import(be_envelope_encoded);
            be_envelope_at_mob.Verify(prg.trustedIdentity.PublicKey);
            Message sp_message_at_mob = (Message)be_envelope_at_mob.Items.ElementAt(0);
            // sp_message_at_mob.IssuerId == prg.serviceProviderIdentity.SubjectId -> look up and fetch service provider identity
            sp_message_at_mob.Verify(prg.serviceProviderIdentity.PublicKey);
            Message mob_response = prg.GenerateMessage(prg.mobileIdentity, prg.serviceProviderIdentity, "Luke, who's your father?");
            mob_response.LinkItem(sp_message_at_mob);
            mob_response.Sign(prg.mobileKeypair);
            Envelope mob_envelope = new Envelope();
            mob_envelope.AddItem(sp_message_at_mob);
            mob_envelope.AddItem(mob_response);
            string mob_envelope_encoded = mob_envelope.Export(); // yes, the envelope was not signed
            // ==> Send 'mob_envelope_encoded' to back-end

            /** At back-end side **/
            Envelope mob_envelope_at_be = Envelope.Import(mob_envelope_encoded);
            Message sp_message_at_be_2 = (Message)mob_envelope_at_be.Items.ElementAt(0);
            // sp_message_at_be_2.IssuerId == prg.serviceProviderIdentity.SubjectId -> look up and fetch service provider identity
            sp_message_at_be_2.Verify(prg.serviceProviderIdentity.PublicKey);
            Message mob_response_at_be = (Message)mob_envelope_at_be.Items.ElementAt(1);
            // mob_response_at_be.IssuerId == prg.mobileIdentity.SubjectId -> look up and fetch mobile client identity
            mob_response_at_be.Verify(prg.mobileIdentity.PublicKey, sp_message_at_be_2);
            Envelope be_envelope_2 = new Envelope();
            //be_envelope_2.AddItem(sp_message_at_be_2); // this may be optional
            be_envelope_2.AddItem(mob_response_at_be);
            be_envelope_2.Sign(prg.trustedKeypair);
            string be_envelope_2_encoded = be_envelope_2.Export();
            // ==> Send 'be_envelope_2_encoded' to service provider

            /** At service provider side **/
            Envelope be_envelope_2_at_sp = Envelope.Import(be_envelope_2_encoded);
            be_envelope_2_at_sp.Verify(prg.trustedIdentity.PublicKey);
            Message mob_response_at_sp = (Message)mob_envelope_at_be.Items.ElementAt(0);
            // mob_response_at_sp.IssuerId == prg.mobileIdentity.SubjectId -> look up and fetch mobile client identity
            mob_response_at_sp.Verify(prg.mobileIdentity.PublicKey, sp_message_at_be_2);

        }


        public static void SendMessage(Program prg)
        {
            /** At service provider side **/
            Message serviceProviderMessage = prg.GenerateMessage(prg.mobileIdentity, prg.serviceProviderIdentity, "Racecar is racecar backwards.");
            serviceProviderMessage.Sign(prg.serviceProviderKeypair);
            string serviceProviderMessageEncoded = serviceProviderMessage.Export();
            // ==> Send 'serviceProviderMessageEncoded' to back-end
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Service Provider Message -> /api/send");
            Console.WriteLine(serviceProviderMessageEncoded.ToString());
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            /** At back-end side **/
            Message serviceProviderMessageAtBackEnd = Item.Import<Message>(serviceProviderMessageEncoded);
            serviceProviderMessageAtBackEnd.Verify(prg.serviceProviderKeypair.PublicCopy());
            //serviceProviderMessageAtBackEnd.SetVerifiedToken(prg.trustedIdentity, prg.trustedKeypair.Key);
            string backEndMessageEncoded = serviceProviderMessageAtBackEnd.Export();
            // ==> Send 'backEndEnvelopeEncoded' to mobile
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Back End Envelope -> moblie");
            Console.WriteLine(backEndMessageEncoded.ToString());
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            /** At mobile side **/
            Message serviceProviderMessageAtMobile = Item.Import<Message>(serviceProviderMessageEncoded);
            serviceProviderMessageAtMobile.Verify(prg.serviceProviderKeypair.PublicCopy());
            //serviceProviderMessageAtMobile.ValidateVerifiedToken(prg.trustedIdentity);
            string messagePayload = System.Text.Encoding.UTF8.GetString(serviceProviderMessageAtMobile.GetPayload(), 0, serviceProviderMessageAtMobile.GetPayload().Length);
            Console.WriteLine("Message from service provider: " + messagePayload);
            Message mobileResponseMessage = prg.GenerateMessage(prg.mobileIdentity, prg.serviceProviderIdentity, "Luke, who's your father?");
            mobileResponseMessage.LinkItem(serviceProviderMessageAtMobile); // link the mobile response to the received service provider message
            mobileResponseMessage.Sign(prg.mobileKeypair);
            string mobileMessageEncoded = mobileResponseMessage.Export();
            // ==> Send 'mobileEnvelopeEncoded' to back-end
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Mobile Response -> Back End");
            Console.WriteLine(mobileMessageEncoded);
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            /** At back-end side **/
            Message mobileMessageAtBackEnd = Item.Import<Message>(mobileMessageEncoded);
            mobileMessageAtBackEnd.Verify(prg.mobileKeypair.PublicCopy());
            //mobileMessageAtBackEnd.SetVerifiedToken(prg.trustedIdentity, prg.trustedKeypair.Key);
            string finalBackEndMessageEncoded = mobileMessageAtBackEnd.Export();
            // ==> Send 'finalBackEndEnvelopeEncoded' to service provider
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Backend Envelope -> Service Provider Back End");
            Console.WriteLine(finalBackEndMessageEncoded);
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            /** At service provider side **/
            Message mobileResponseMessageAtServiceProvider = Item.Import<Message>(finalBackEndMessageEncoded);
            mobileResponseMessageAtServiceProvider.Verify(prg.mobileKeypair.PublicCopy()); 
            //mobileResponseMessageAtServiceProvider.ValidateVerifiedToken(prg.trustedIdentity);
            string responcePayload = System.Text.Encoding.UTF8.GetString(mobileResponseMessageAtServiceProvider.GetPayload(), 0, mobileResponseMessageAtServiceProvider.GetPayload().Length);
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Response From Mobile");
            Console.WriteLine(responcePayload);
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

        }

        public static void SpeedTestMessage(Program prg, int itterations)
        {
            var stopwatch = Stopwatch.StartNew();
            stopwatch.Start();
            
            for (int i = 0; i < itterations; i++)
            {
                Message serviceProviderMessage = prg.GenerateMessage(prg.mobileIdentity, prg.serviceProviderIdentity, "Racecar is racecar backwards.");
                serviceProviderMessage.Sign(prg.serviceProviderKeypair);
                string serviceProviderMessageEncoded = serviceProviderMessage.Export();
                
            }

            stopwatch.Stop();
            Console.WriteLine("elapsed : " + stopwatch.ElapsedMilliseconds + " miliseconds");
            double d = (Convert.ToDouble(stopwatch.ElapsedMilliseconds) / itterations);
            Console.WriteLine("per itteration : " + d + " miliseconds");

        }

        /// <summary>
        /// Main method of console application
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            Console.Title = "DIME Console App";
            Program prg = new();

            string command;
            bool quitNow = false;
            while (!quitNow)
            {
                string[] inputs = Console.ReadLine().Split(new char[] { '-' });
                command = inputs[0].ToString().Trim();

                switch (command)
                {
                    case "/help":
                        Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++");
                        Console.WriteLine("sendmessage : will send a new message and output the data at each stage");
                        Console.WriteLine("speedtest -n : will allow n itterations of generated messages to send");
                        Console.WriteLine("quit : quits out of the command line interface");
                        Console.WriteLine();
                        break;

                    case "sendmessage":
                        SendMessage(prg);
                        break;

                    case "speedtest":
                        SpeedTestMessage(prg, int.Parse(inputs[1]));
                        break;

                    case "quit":
                        quitNow = true;
                        break;

                    default:
                        Console.WriteLine("Unknown Command " + command);
                        break;
                }
            }
        }
    }
}