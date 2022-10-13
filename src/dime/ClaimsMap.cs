//
//  ClaimsMap.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//

#nullable enable
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using jsoncanonicalizer;

namespace DiME;

public class ClaimsMap
{
    #region -- INTERNAL --

    internal ClaimsMap()
    {
        _claims = new Dictionary<string, object>();
    }

    internal ClaimsMap(string encoded)
    {
        var serializeOptions = new JsonSerializerOptions
        {
            WriteIndented = true,
            Converters =
            {
                new ClaimsJsonConverter()
            }
        };
        _claims = JsonSerializer.Deserialize<Dictionary<string, object>>(encoded, serializeOptions);
        if (_claims == null)
            throw new FormatException("Unable to parse claims of Dime item.");
    }

    internal string? ToJson()
    {
        if (_claims == null) return null;
        var jsonString = JsonSerializer.Serialize(_claims);
        var jsonCanonicalizer = new JsonCanonicalizer(jsonString);
        return jsonCanonicalizer.GetEncodedString();
    }

    internal int Size()
    {
        return _claims!.Count;
    }
    
    internal T? Get<T>(Claim claim)
    {
        var key = ClaimToString(claim);
        if (_claims != null && !_claims.ContainsKey(key)) return default;
        return (T) _claims?[key]!;
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
           return Base58.Decode(str);
        return Array.Empty<byte>();
    }

    internal Key? GetKey(Claim claim, List<KeyCapability> use)
    {
        var value = Get<string>(claim);
        return string.IsNullOrEmpty(value) ? null : new Key(use, value, claim);
    }
    
    internal List<ItemLink>? GetItemLinks(Claim claim) {
        var value = Get<string>(claim);
        return string.IsNullOrEmpty(value) ? null : ItemLink.FromEncodedList(value);
    }
    
    internal void Put(Claim claim, object? value)
    {
        switch (value)
        {
            case null:
                return;
            case byte[] bytes:
                _claims![ClaimToString(claim)] = Base58.Encode(bytes);
                break;
            default:
                _claims![ClaimToString(claim)] = value;
                break;
        }
    }

    internal void Remove(Claim claim)
    {
        _claims!.Remove(ClaimToString(claim));
    }

    #endregion
    
    #region -- PRIVATE --

    private readonly Dictionary<string, object>? _claims;

    private static string ClaimToString(Claim claim)
    {
        return claim.ToString().ToLower();
    }
    
    private class ClaimsJsonConverter : JsonConverter<Dictionary<string, object>>
    {
        public override Dictionary<string, object> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartObject)
                throw new JsonException($"Unsupported JsonTokenType: {reader.TokenType}.");
            var claims = new Dictionary<string, object>();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                    return claims;
                if (reader.TokenType != JsonTokenType.PropertyName)
                    throw new JsonException($"Unexpected JsonTokenType, got {reader.TokenType}, expected PropertyName.");
                var propertyName = reader.GetString();
                if (string.IsNullOrWhiteSpace(propertyName))
                    throw new JsonException("Unable to get property name.");
                reader.Read();
                var obj = ExtractObject(ref reader, propertyName, options);
                if (obj is not null)
                    claims.Add(propertyName, obj);
            }
            return claims;
        }

        public override void Write(Utf8JsonWriter writer, Dictionary<string, object> value, JsonSerializerOptions options)
        {
            JsonSerializer.Serialize(writer, value, options);
        }

        private object? ExtractObject(ref Utf8JsonReader reader, string propertyName, JsonSerializerOptions options)
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.StartObject:
                    return Read(ref reader, null, options);
                case JsonTokenType.StartArray:
                    var list = new List<object>();
                    var isStringType = true;
                    while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                    {
                        var obj = ExtractObject(ref reader, propertyName, options);
                        if (obj is not null)
                        {
                            list.Add(obj);
                            if (isStringType)
                                isStringType = obj is string;
                        }
                    }

                    if (isStringType)
                        return list.ConvertAll(obj => obj.ToString());
                    else
                        return list;
                case JsonTokenType.String:
                    return reader.GetString();
                case JsonTokenType.Number:
                    return true;
                case JsonTokenType.True:
                    break;
                case JsonTokenType.False:
                    return false;
                case JsonTokenType.None:
                case JsonTokenType.EndObject:
                case JsonTokenType.EndArray:
                case JsonTokenType.PropertyName:
                case JsonTokenType.Null:
                case JsonTokenType.Comment:
                default:
                    break;
            }
            return null;
        }
    }
    
    #endregion
    
}
