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
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.IdentityKey);
            Assert.IsTrue(keypair.profile == 1);
            Assert.IsTrue(keypair.type == KeypairType.IdentityKey);
            Assert.IsNotNull(keypair.id);
            Assert.IsNotNull(keypair.publicKey);
            Assert.IsNotNull(keypair.privateKey);
        }

        [TestMethod]
        public void ImportTest1()
        {
            string encoded = "k1.eyJraWQiOiI1ZDA4NDVlNS0zNzg2LTQyNjYtYTc3YS01ZTQwYzAxZWNiYjkiLCJrdHkiOjEsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUFGVmNjay8zT1J1NGNJSmtrQmp4SHBjVktTYzYzQjUyS0xOMVlZYjExQmxjIiwicHJ2IjoiTUM0Q0FRQXdCUVlESzJWd0JDSUVJRnRsZWlLUGtuVUN4RTFDV0I3UVlXMUNiYU5ZT2FKZG5vcGdXSzRnV1x1MDAyQkNQIn0";
            Keypair keypair = Keypair.Import(encoded);
            Assert.AreEqual(1, keypair.profile);
            Assert.IsTrue(keypair.type == KeypairType.IdentityKey);
            Assert.AreEqual(new Guid("5d0845e5-3786-4266-a77a-5e40c01ecbb9"), keypair.id);
            Assert.AreEqual("MCowBQYDK2VwAyEAFVcck/3ORu4cIJkkBjxHpcVKSc63B52KLN1YYb11Blc", keypair.publicKey);
            Assert.AreEqual("MC4CAQAwBQYDK2VwBCIEIFtleiKPknUCxE1CWB7QYW1CbaNYOaJdnopgWK4gW\u002BCP", keypair.privateKey);
        }

        [TestMethod]
        public void KeypairTest3()
        {
            try
            {
                Keypair keypair = Keypair.GenerateKeypair(KeypairType.IdentityKey, 0);
            } 
            catch (UnsupportedProfileException)
            {
                // All is well
            }
            
        }


    }
}