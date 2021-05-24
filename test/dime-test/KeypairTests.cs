using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class KeypairTests
    {
        [TestMethod]
        public void KeypairTest1()
        {
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity);
            Assert.IsTrue(keypair.Profile == 1);
            Assert.IsTrue(keypair.Type == KeypairType.Identity);
            Assert.IsNotNull(keypair.Id);
            Assert.IsNotNull(keypair.PublicKey);
            Assert.IsNotNull(keypair.PrivateKey);
        }

        [TestMethod]
        public void ImportTest1()
        {
            string encoded = "k1.eyJraWQiOiI1ZDA4NDVlNS0zNzg2LTQyNjYtYTc3YS01ZTQwYzAxZWNiYjkiLCJrdHkiOjEsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUFGVmNjay8zT1J1NGNJSmtrQmp4SHBjVktTYzYzQjUyS0xOMVlZYjExQmxjIiwicHJ2IjoiTUM0Q0FRQXdCUVlESzJWd0JDSUVJRnRsZWlLUGtuVUN4RTFDV0I3UVlXMUNiYU5ZT2FKZG5vcGdXSzRnV1x1MDAyQkNQIn0";
            Keypair keypair = Keypair.Import(encoded);
            Assert.AreEqual(1, keypair.Profile);
            Assert.IsTrue(keypair.Type == KeypairType.Identity);
            Assert.AreEqual(new Guid("5d0845e5-3786-4266-a77a-5e40c01ecbb9"), keypair.Id);
            Assert.AreEqual("MCowBQYDK2VwAyEAFVcck/3ORu4cIJkkBjxHpcVKSc63B52KLN1YYb11Blc", keypair.PublicKey);
            Assert.AreEqual("MC4CAQAwBQYDK2VwBCIEIFtleiKPknUCxE1CWB7QYW1CbaNYOaJdnopgWK4gW\u002BCP", keypair.PrivateKey);
        }

        [TestMethod]
        public void KeypairTest3()
        {
            try {
                Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity, 0);
            } catch (UnsupportedProfileException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

    }
}