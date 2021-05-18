using System;
using System.Text;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMEConsole
{
    class Program
    {

        public Identity issuerIdentity;
        public Keypair issuerKeypair;
        public Identity subjectIdentity;

        public Program()
        {
            this.issuerKeypair = Keypair.GenerateKeypair(KeypairType.IdentityKey);
            this.issuerIdentity = Program.GenerateIdentity(this.issuerKeypair);
            this.subjectIdentity = Program.GenerateIdentity(Keypair.GenerateKeypair(KeypairType.IdentityKey));
            
        }

        public static Identity GenerateIdentity(Keypair keypair)
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.GenerateRequest(keypair);
            return Identity.IssueIdentity(iir, Guid.NewGuid(), keypair);
        }


        public Message GenerateMessage(Guid subjectId, Identity issuerIdentity, string payload)
        {
            long expiresAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 120;
            return new Message(subjectId, issuerIdentity, Encoding.UTF8.GetBytes(payload), expiresAt);
        }

        static void Main(string[] args)
        {
            Program program = new Program();
            Message msg = program.GenerateMessage(program.subjectIdentity.subjectId, 
                                                  program.issuerIdentity,
                                                  "Racecar is racecar backwards.");
            string encoded = msg.Export(program.issuerKeypair.privateKey);
            Console.WriteLine(encoded);


        }
    }
}
