using System;
using System.Text;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMEConsole
{
    class Program
    {
        public Identity trustedIdentity;
        public Keypair trustedKeypair;
        public Identity issuerIdentity;
        public Keypair issuerKeypair;
        public Identity subjectIdentity;

        public Program()
        {
            this.trustedKeypair = Keypair.GenerateKeypair(KeypairType.IdentityKey);
            this.trustedIdentity = GenerateIdentity(this.trustedKeypair);
            this.issuerKeypair = Keypair.GenerateKeypair(KeypairType.IdentityKey);
            this.issuerIdentity = GenerateIdentity(this.issuerKeypair);
            this.subjectIdentity = GenerateIdentity(Keypair.GenerateKeypair(KeypairType.IdentityKey));
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
            return new Message(subjectId, issuerIdentity, issuerKeypair.privateKey, Encoding.UTF8.GetBytes(payload), expiresAt);
        }

        static void Main(string[] args)
        {
            Program program = new Program();
            Message msg = program.GenerateMessage(program.subjectIdentity.subjectId, 
                                                  program.issuerIdentity,
                                                  "Racecar is racecar backwards.");
            string encoded = msg.Export();
            Console.WriteLine(encoded);

            Envelope env = new Envelope(program.issuerIdentity, program.subjectIdentity.subjectId, msg.parameters.issuedAt, msg.parameters.expiresAt);
            env.AddMessage(msg);
            string envEncoded = env.Export(program.issuerKeypair.privateKey);

            Envelope env2 = Envelope.Import(envEncoded);
            
        }
    }
}
