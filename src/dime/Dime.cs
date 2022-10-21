//
//  Dime.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//

using System;
using DiME.KeyRing;

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
    public static readonly DiME.Crypto.Crypto Crypto = new();
    /// <summary>
    /// A set of keys and identities that are set to be trusted.
    /// </summary>
    public static readonly DiME.KeyRing.KeyRing KeyRing = new();
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
    /// Gets/sets the grace period, in seconds, that is used to allow for a grace period when comparing and validating dates
    /// (issued at and expires at). A value of 2 will allow a grace margin of +/-2 seconds, given a total window of 4
    /// seconds.
    /// </summary>
    public static long GracePeriod
    {
        get
        {
            lock (TimeLock)
                return _gracePeriod;
        }
        set
        {
            lock (TimeLock)
                _gracePeriod = Math.Abs(value);
        }
    }
    /// <summary>
    /// Gets/sets the global modifier, in seconds, for all captured timestamps. This may be used in clients with a
    /// calculated time different from a server, or network base time. This may be either a positive, or negative
    /// number, setting 0 will turn time modification off. Generally it is more recommended that all entities in a
    /// network have synced their local time with a common time-server. Servers, with multiple clients, should not use
    /// this.
    /// </summary>
    public static long TimeModifier
    {
        get
        {
            lock (TimeLock)
                return _timeModifier;
        }
        set
        {
            lock (TimeLock)
                _timeModifier = value;
        }
    }

    /// <summary>
    /// Overrides the internal time with a provided time. This time is used to verify any timestamps and overriding this
    /// should be used carefully and never in a production environment. Set to null, to use current system time
    /// (default).
    /// </summary>
    public static DateTime? OverrideTime { get; set; }

    /// <summary>
    /// Returns if the IntegrityState may be considered successfully validated and may be considered trusted.
    /// </summary>
    /// <param name="state">True if valid, false otherwise.</param>
    /// <returns></returns>
    public static bool IsIntegrityStateValid(IntegrityState state)
    {
        return state is IntegrityState.Complete 
            or IntegrityState.ValidSignature or IntegrityState.ValidDates or IntegrityState.ValidItemLinks;
    }
    
    #endregion

    #region -- INTERNAL --
    
    internal const char ComponentDelimiter = '.';
    internal const char SectionDelimiter = ':';
    
    #endregion

    #region -- PRIVATE --

    private static readonly object TimeLock = new();
    private static long _gracePeriod;
    private static long _timeModifier;

    #endregion

}
