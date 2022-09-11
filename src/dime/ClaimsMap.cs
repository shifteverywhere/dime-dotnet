//
//  ClaimsMap.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Text.Json;

namespace DiME;

internal class ClaimsMap
{
    #region -- INTERNAL --

    internal ClaimsMap()
    {
        _claims = new Dictionary<string, object>();
    }

    internal ClaimsMap(string encoded)
    {
        _claims = JsonSerializer.Deserialize<Dictionary<string, object>>(encoded);
    }

    internal string ToJson()
    {
        return JsonSerializer.Serialize(_claims);
    }

    internal int size()
    {
        return _claims.Count;
    }
    
    internal T Get<T>(Claim claim)
    {
        return (T)_claims[ClaimsMap.ClaimToString(claim)];
    }

    internal Guid? GetGuid(Claim claim)
    {
        switch (Get<object>(claim))
        {
            case null:
                return null;
            case Guid guid:
                return guid;
            case string str:
            {
                var uuid = new Guid(str);
                Put(claim, uuid);
                return uuid;
            }
            default:
                throw new ArgumentException("Requested claim is not a Guid.", nameof(claim));
        }
    }

    internal DateTime? GetDateTime(Claim claim)
    {
        switch (Get<object>(claim))
        {
            case null:
                return null;
            case DateTime dateTime:
                return dateTime;
            case string str:
            {
                var dateTime = Utility.FromTimestamp(str);
                Put(claim, dateTime);
                return dateTime;
            }
            default:
                throw new ArgumentException("Requested claim is not a DateTime.", nameof(claim));
        }
    }

    internal byte[] GetBytes(Claim claim)
    {
        var obj = Get<object>(claim);
        if (obj is string str)
        {
            return Base58.Decode(str);
        }
        return null;
    }
    
    internal void Put(Claim claim, object value)
    {
        if (value is byte[] bytes)
        {
            _claims[ClaimsMap.ClaimToString(claim)] = Base58.Encode(bytes, null);
        }
        else
        {
            _claims[ClaimsMap.ClaimToString(claim)] = value;
        }
    }

    internal void Remove(Claim claim)
    {
        _claims.Remove(ClaimsMap.ClaimToString(claim));
    }

    #endregion
    
    #region -- PRIVATE --

    private readonly Dictionary<string, object> _claims;

    private static string ClaimToString(Claim claim)
    {
        return claim.ToString().ToLower();
    }
    
    #endregion
    
}
