//
//  ICryptoSuite.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Linq;
using ASodium;
using DiME.Capability;

namespace DiME.Crypto;

/// <summary>
/// Implements the Dime standard cryptographic suite (STN).
/// </summary>
internal class StandardSuite: ICryptoSuite
{
    private const string SuiteName = "STN";

    public string Name()
    {
        return SuiteName;
    }

    public byte[] GenerateKeyName(byte[][] key)
    {
        // This only supports key identifier for public keys, may be different for other crypto suites
        var bytes = key[(int)KeyIndex.PublicKey];
        if (bytes is not {Length: > 0}) return null;
        var hash = GenerateHash(bytes);
        return Utility.SubArray(hash, 0, 8); // First 8 bytes are used as an identifier
    }

    public byte[] GenerateSignature(byte[] data, byte[] key)
    {
        if (key == null || key.Length == 0) { throw new ArgumentNullException(nameof(key), "Unable to sign, key must not be null."); }
        if (data == null || data.Length == 0) { throw new ArgumentNullException(nameof(data), "Unable to sign, data must not be null."); }
        var signature = SodiumPublicKeyAuth.SignDetached(data, key);
        return signature;
    }

    public bool VerifySignature(byte[] data, byte[] signature, byte[] key)
    {
        if (key == null || key.Length == 0) { throw new ArgumentNullException(nameof(key), "Unable to verify, key must not be null."); }
        if (data == null || data.Length == 0) { throw new ArgumentNullException(nameof(data), "Unable to verify, data must not be null."); }
        if (signature == null || signature.Length == 0) { throw new ArgumentNullException(nameof(signature), "Unable to verify, signature must not be null."); }
        return SodiumPublicKeyAuth.VerifyDetached(signature, data, key);
    }

    public byte[][] GenerateKey(List<KeyCapability> capabilities)
    {
        if (capabilities is not {Count: 1}) { throw new ArgumentNullException(nameof(capabilities), "Unable to generate, invalid key usage requested."); }
        var firstUse = capabilities[0];
        if (firstUse == KeyCapability.Encrypt)
        {
            var secretKey = Utility.RandomBytes(NbrSKeyBytes);
            return new [] { secretKey };
        }
        // If it wasn't Encryption or Authentication generation continues here
        var keypair = firstUse switch
        {
            KeyCapability.Sign => SodiumPublicKeyAuth.GenerateRevampedKeyPair(),
            KeyCapability.Exchange => SodiumKeyExchange.GenerateRevampedKeyPair(),
            _ => throw new ArgumentException($"Unknown key type: {firstUse}.", nameof(capabilities))
        };
        return new [] { keypair.PrivateKey.ToArray(), keypair.PublicKey.ToArray() };
    }

    public byte[] GenerateSharedSecret(byte[][] clientKey, byte[][] serverKey, List<KeyCapability> capabilities)
    {
        if (!capabilities.Contains(KeyCapability.Encrypt)) { throw new ArgumentNullException(nameof(capabilities), "Unable to generate, key usage for shared secret must be Encrypt."); }
        if (capabilities.Count > 1) { throw new ArgumentNullException(nameof(capabilities), "Unable to generate, key usage for shared secret may only be Encrypt."); }
        byte[] shared;
        if (clientKey[(int)KeyIndex.SecretKey] != null && clientKey.Length == 2) // has both private and public key 
        {
            var clientSharedSecretBox = SodiumKeyExchange.CalculateClientSharedSecret(clientKey[(int)KeyIndex.PublicKey], clientKey[(int)KeyIndex.SecretKey], serverKey[(int)KeyIndex.PublicKey]);
            shared = clientSharedSecretBox.TransferSharedSecret;
        } 
        else  if (serverKey[(int)KeyIndex.SecretKey] != null && serverKey.Length == 2) // has both private and public key 
        {
            var serverSharedSecretBox = SodiumKeyExchange.CalculateServerSharedSecret(serverKey[(int)KeyIndex.PublicKey], serverKey[(int)KeyIndex.SecretKey], clientKey[(int)KeyIndex.PublicKey]);
            shared = serverSharedSecretBox.ReadSharedSecret;
        }
        else
            throw new ArgumentException("Unable to generate, invalid keys provided.");
        return shared;
    }

    public byte[] Encrypt(byte[] data, byte[] key)
    {
        if (data == null || data.Length == 0) { throw new ArgumentNullException(nameof(data), "Unable to encrypt, data to encrypt must not be null or empty."); }
        if (key == null || key.Length == 0) { throw new ArgumentNullException(nameof(key), "Unable to encrypt, key must not be null or empty."); }
        var nonce = Utility.RandomBytes(NbrNonceBytes);
        var cipherText = SodiumSecretBox.Create(data, nonce, key);
        return Utility.Combine(nonce, cipherText);
    }

    public byte[] Decrypt(byte[] data, byte[] key)
    {
        if (data == null || data.Length == 0) { throw new ArgumentNullException(nameof(data), "Unable to decrypt, data to decrypt must not be null or empty."); }
        if (key == null || key.Length == 0) { throw new ArgumentNullException(nameof(key), "Unable to decrypt, key must not be null or empty."); }
        var nonce = Utility.SubArray(data, 0, NbrNonceBytes);
        var cipherText = Utility.SubArray(data, NbrNonceBytes);
        return SodiumSecretBox.Open(cipherText, nonce, key);
    }

    public byte[] GenerateHash(byte[] data)
    {
        return SodiumGenericHash.ComputeHash(NbrHashBytes, data);
    }

    #region --- PRIVATE ---

    private const int NbrSKeyBytes = 32;
    private const int NbrHashBytes = 32;
    private const int NbrNonceBytes = 24;

    #endregion
}
