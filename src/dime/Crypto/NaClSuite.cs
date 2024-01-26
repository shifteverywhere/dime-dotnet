//
//  ICryptoSuite.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using ASodium;
using DiME.Capability;

namespace DiME.Crypto;

/// <summary>
/// Implements the NaCl (salt) cryptographic algorithm suite defined in the DiME data format specification.
/// </summary>
internal class NaClSuite: ICryptoSuite
{

    #region -- PUBLIC --
    
    /// <summary>
    /// Default constructor.
    /// </summary>
    /// <param name="name">The name of the suite.</param>
    public NaClSuite(string name)
    {
        _suiteName = name;
    }
    
    /// <inheritdoc />
    public string Name()
    {
        return _suiteName;
    }

    /// <inheritdoc />
    public string GenerateKeyName(Key key)
    {
        // This only supports key names for public keys, may be different for other crypto suites
        var bytes = key.KeyBytes(Claim.Pub);
        return bytes is not {Length: > 0} ? null 
            : Utility.ToHex(Utility.SubArray(Hash(bytes), 0, KeyNameLength)); // First 8 bytes are used as an identifier
    }

    /// <inheritdoc />
    public virtual byte[] GenerateSignature(Item item, Key key)
    {
        var data = Hash(item.RawEncoded(false));
        return data is not { Length: > 0 } ? null : SodiumPublicKeyAuth.SignDetached(data, key.KeyBytes(Claim.Key));
    }

    /// <inheritdoc />
    public virtual bool VerifySignature(Item item, byte[] signature, Key key)
    {
        var data = Hash(item.RawEncoded(false));
        if (data is not { Length: > 0 }) throw new ArgumentException("Failed to generate signature, item thumbprint was null or empty.", nameof(item));
        return SodiumPublicKeyAuth.VerifyDetached(signature,
            data,
            key.KeyBytes(Claim.Pub));
    }

    /// <inheritdoc />
    public Key GenerateKey(List<KeyCapability> capabilities)
    {
        if (capabilities is not {Count: 1}) { throw new ArgumentNullException(nameof(capabilities), "Unable to generate, invalid key usage requested."); }
        var firstUse = capabilities[0];
        if (firstUse == KeyCapability.Encrypt)
        {
            var secretKey = SodiumSecretBox.GenerateKey();
            return new Key(capabilities, secretKey, null, _suiteName);
        }
        // If it wasn't Encrypt
        var keypair = firstUse switch
        {
            KeyCapability.Sign => SodiumPublicKeyAuth.GenerateRevampedKeyPair(),
            KeyCapability.Exchange => SodiumKeyExchange.GenerateRevampedKeyPair(),
            _ => throw new ArgumentException($"Unknown key type: {firstUse}.", nameof(capabilities))
        };
        return new Key(capabilities, keypair.PrivateKey.ToArray(), keypair.PublicKey.ToArray(), _suiteName);
    }

    /// <inheritdoc />
    public Key GenerateSharedSecret(Key clientKey, Key serverKey, List<KeyCapability> capabilities)
    {
        if (!capabilities.Contains(KeyCapability.Encrypt)) { throw new ArgumentNullException(nameof(capabilities), "Unable to generate, key usage for shared secret must be Encrypt."); }
        if (capabilities.Count > 1) { throw new ArgumentNullException(nameof(capabilities), "Unable to generate, key usage for shared secret may only be Encrypt."); }
        var rawClientKeys = new[] { clientKey.KeyBytes(Claim.Key), clientKey.KeyBytes(Claim.Pub) };
        var rawServerKeys = new[] { serverKey.KeyBytes(Claim.Key), serverKey.KeyBytes(Claim.Pub) };
        byte[] shared;
        if (rawClientKeys[0] != null && rawClientKeys.Length == 2) // has both private and public key 
        {
            var clientSharedSecretBox = SodiumKeyExchange.CalculateClientSharedSecret(rawClientKeys[1], rawClientKeys[0], rawServerKeys[1]);
            shared = clientSharedSecretBox.TransferSharedSecret;
        } 
        else  if (rawServerKeys[0] != null && rawServerKeys.Length == 2) // has both private and public key 
        {
            var serverSharedSecretBox = SodiumKeyExchange.CalculateServerSharedSecret(rawServerKeys[1], rawServerKeys[0], rawClientKeys[1]);
            shared = serverSharedSecretBox.ReadSharedSecret;
        }
        else
            throw new ArgumentException("Unable to generate, invalid keys provided.");
        return new Key(capabilities, shared, null, _suiteName);
    }

    /// <inheritdoc />
    public byte[] Encrypt(byte[] data, Key key)
    {
        var nonce = Utility.RandomBytes(NbrNonceBytes);
        var cipherText = SodiumSecretBox.Create(data, nonce, key.KeyBytes(Claim.Key));
        return Utility.Combine(nonce, cipherText);
    }

    /// <inheritdoc />
    public byte[] Decrypt(byte[] data, Key key)
    {
        var nonce = Utility.SubArray(data, 0, NbrNonceBytes);
        var cipherText = Utility.SubArray(data, NbrNonceBytes);
        return SodiumSecretBox.Open(cipherText, nonce, key.KeyBytes(Claim.Key));
    }

    /// <inheritdoc />
    public string GenerateHash(byte[] data)
    {
        return Utility.ToHex(Hash(data));
    }

    /// <inheritdoc />
    public virtual string EncodeKeyBytes(byte[] rawKey, Claim claim)
    {
        return Utility.ToBase64(rawKey);
    }

    /// <inheritdoc />
    public virtual byte[] DecodeKeyBytes(string encodedKey, Claim claim)
    {
        return Utility.FromBase64(encodedKey);
    }
    
    #endregion

    #region --- INTERNAL ---

    internal const string SuiteName = "NaCl";

    #endregion

    #region --- PROTECTED ---
    
    protected NaClSuite()
    {
        _suiteName = SuiteName;
    }

    #endregion
    
    #region --- PRIVATE ---

    private const int NbrSKeyBytes = 32;
    private const int NbrHashBytes = 32;
    private const int NbrNonceBytes = 24;
    private const int KeyNameLength = 8;
    protected string _suiteName;

    private static byte[] Hash(byte[] data)
    {
        return SodiumGenericHash.ComputeHash(NbrHashBytes, data);
    }
    
    #endregion
}
