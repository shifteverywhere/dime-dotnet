//
//  Dime.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
namespace DiME;

/**
 * Central class that handles a few important settings and constants.
 */
public abstract class Dime
{

    #region -- PUBLIC --

    /// <summary>
    ///  Manager of cryptographic suites and operations. May be used to add additional cryptographic suits in run-time.
    /// </summary>
    public static readonly Crypto Crypto = new Crypto();
    /// <summary>
    /// The maximum length that the context claim may hold.
    /// </summary>
    public const int MaxContextLength = 84;
    /// <summary>
    /// The current version of the implemented Di:ME specification.
    /// </summary>
    public const int Version = 1;
    /// <summary>
    /// A convenience constant for no expiration date.
    /// </summary>
    public const long NoExpiration = -1L;
   /// <summary>
    /// A convenience constant holding the number of seconds for a minute.
    /// </summary>
    public const long ValidFor1Minute = 60L;
    /// <summary>
    /// A convenience constant holding the number of seconds for an hour.
    /// </summary>
    public const long ValidFor1Hour = ValidFor1Minute * 60L;
    /// <summary>
    /// A convenience constant holding the number of seconds for a day.
    /// </summary>
    public const long ValidFor1Day = ValidFor1Hour * 24L;
    /// <summary>
    /// A convenience constant holding the number of seconds for a year (based on 365 days).
    /// </summary>
    public const long ValidFor1Year = ValidFor1Day * 365L;

    /// <summary>
    /// The trusted identity. This is normally the root identity of a trust chain.
    /// </summary>
    public static Identity TrustedIdentity
    {
        get
        {
            lock(Lock) 
                return _trustedIdentity;
        }
        set
        {
            lock(Lock)
                _trustedIdentity = value;
        }
    }
    
    #endregion

    #region -- INTERNAL --
    
    internal const char ComponentDelimiter = '.';
    internal const char SectionDelimiter = ':';
    
    #endregion

    #region -- PRIVATE --

    private static readonly object Lock = new();
    private static Identity _trustedIdentity;
    
    #endregion
    
}
