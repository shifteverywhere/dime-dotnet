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
using ShiftEverywhere.DiME;
using System.Runtime.CompilerServices;

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
            this.trustedKeypair = KeyBox.Generate(KeyType.Identity);
            this.trustedIdentity = GenerateIdentity(this.trustedKeypair, new List<Capability> { Capability.Issue, Capability.Generic, Capability.Identify });
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Trusted Key Pair");
            Console.WriteLine("private key : " + this.trustedKeypair.Key.ToString());
            Console.WriteLine("public key : " + this.trustedKeypair.PublicKey.ToString());
            Console.WriteLine("Thumbprint : " + this.trustedIdentity.Thumbprint().ToString());
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            this.serviceProviderKeypair = KeyBox.Generate(KeyType.Identity);
            this.serviceProviderIdentity = GenerateIdentity(this.serviceProviderKeypair, new List<Capability> { Capability.Generic, Capability.Identify });
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Service Provider Key Pair");
            Console.WriteLine("private key : " + this.serviceProviderKeypair.Key.ToString());
            Console.WriteLine("public key : " + this.serviceProviderKeypair.PublicKey.ToString());
            Console.WriteLine("Thumbprint : " + this.serviceProviderIdentity.Thumbprint().ToString());
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            this.mobileKeypair = KeyBox.Generate(KeyType.Identity);
            this.mobileIdentity = GenerateIdentity(this.mobileKeypair, new List<Capability> {  Capability.Generic, Capability.Identify });
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Mobile Key Pair");
            Console.WriteLine("private key : " + this.mobileKeypair.Key.ToString());
            Console.WriteLine("public key : " + this.mobileKeypair.PublicKey.ToString());
            Console.WriteLine("Thumbprint : " + this.mobileIdentity.Thumbprint().ToString());
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            Dime.SetTrustedIdentity(this.trustedIdentity);
        }

        public Identity GenerateIdentity(KeyBox keypair, List<Capability> capabilities)
        {
            List<Capability> caps = capabilities;
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

        public static void SendMessage(Program prg)
        {
            /** At service provider side **/
            Message serviceProviderMessage = prg.GenerateMessage(prg.mobileIdentity.SubjectId, prg.serviceProviderIdentity, "Racecar is racecar backwards.");
            serviceProviderMessage.Seal(prg.serviceProviderKeypair.Key);
            string serviceProviderMessageEncoded = serviceProviderMessage.Export();
            // ==> Send 'serviceProviderMessageEncoded' to back-end
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Service Provider Message -> /api/send");
            Console.WriteLine(serviceProviderMessageEncoded.ToString());
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            /** At back-end side **/
            Message serviceProviderMessageAtBackEnd = Dime.Import<Message>(serviceProviderMessageEncoded);
            serviceProviderMessageAtBackEnd.Verify();
            Envelope backEndEnvelope = new Envelope(prg.trustedIdentity, prg.mobileIdentity.SubjectId, 120);
            backEndEnvelope.AddMessage(serviceProviderMessage);
            backEndEnvelope.Seal(prg.trustedKeypair.Key);
            string backEndEnvelopeEncoded = backEndEnvelope.Export();
            // ==> Send 'backEndEnvelopeEncoded' to mobile
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Back End Envelope -> moblie");
            Console.WriteLine(backEndEnvelopeEncoded.ToString());
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            /** At mobile side **/
            Envelope backEndEnvelopeAtMobile = Dime.Import<Envelope>(backEndEnvelopeEncoded);
            //backEndEnvelopeAtMobile.Verify(); //ToDo: exception is thrown because it is self-signed
            string messagePayload = System.Text.Encoding.UTF8.GetString(backEndEnvelopeAtMobile.Messages[0].GetPayload(), 0, backEndEnvelopeAtMobile.Messages[0].GetPayload().Length);
            Console.WriteLine("Message from service provider: " + messagePayload);
            Message mobileResponseMessage = prg.GenerateMessage(prg.mobileIdentity.SubjectId, prg.serviceProviderIdentity, "Luke, who's your father?");
            mobileResponseMessage.LinkMessage(backEndEnvelopeAtMobile.Messages[0]); // link the mobile response to the received service provider message
            mobileResponseMessage.Seal(prg.mobileKeypair.Key);
            Envelope mobileEnvelope = new Envelope(prg.mobileIdentity, prg.serviceProviderIdentity.IssuerId, 120);
            mobileEnvelope.AddMessage(backEndEnvelopeAtMobile.Messages[0]);
            mobileEnvelope.AddMessage(mobileResponseMessage);
            mobileEnvelope.Seal(prg.mobileKeypair.Key);
            string mobileEnvelopeEncoded = mobileEnvelope.Export();
            // ==> Send 'mobileEnvelopeEncoded' to back-end
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Mobile Envelope -> Back End");
            Console.WriteLine(mobileEnvelopeEncoded);
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            /** At back-end side **/
            Envelope mobleEnvelopeAtBackEnd = Dime.Import<Envelope>(mobileEnvelopeEncoded);
            //mobleEnvelopeAtBackEnd.Verify(); //ToDo: exception is thrown because it is self-signed
            Envelope finalBackEndEnvelope = new Envelope(prg.trustedIdentity, mobileEnvelope.SubjectId, 120);
            finalBackEndEnvelope.AddMessage(mobleEnvelopeAtBackEnd.Messages[0]);
            finalBackEndEnvelope.AddMessage(mobleEnvelopeAtBackEnd.Messages[1]);
            finalBackEndEnvelope.Seal(prg.trustedKeypair.Key);
            string finalBackEndEnvelopeEncoded = finalBackEndEnvelope.Export();
            // ==> Send 'finalBackEndEnvelopeEncoded' to service provider
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine + "Backend Envelope -> Service Provider Back End");
            Console.WriteLine(backEndEnvelopeEncoded);
            Console.WriteLine("++++++++++++++++++++++++++++++++++++++++++++++" + Environment.NewLine);

            /** At service provider side **/
            Envelope finalBackEndEnvelopeAtServiceProvider = Dime.Import<Envelope>(finalBackEndEnvelopeEncoded);
            //finalBackEndEnvelopeAtServiceProvider.Verify(); //ToDo: exception is thrown because it is self-signed
            string responcePayload = System.Text.Encoding.UTF8.GetString(finalBackEndEnvelopeAtServiceProvider.Messages[1].GetPayload(), 0, finalBackEndEnvelopeAtServiceProvider.Messages[1].GetPayload().Length);
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
                Message serviceProviderMessage = prg.GenerateMessage(prg.mobileIdentity.SubjectId, prg.serviceProviderIdentity, "Racecar is racecar backwards.");
                serviceProviderMessage.Seal(prg.serviceProviderKeypair.Key);
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
