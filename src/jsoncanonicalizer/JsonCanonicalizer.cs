/*
 *  Copyright 2006-2019 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
// Some clean up and C#10/.NET 6 updates made by Shift Everywhere

using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using es6numberserializer;

// JSON canonicalizer for .NET Core
namespace jsoncanonicalizer;

public class JsonCanonicalizer
{
    readonly StringBuilder _buffer;

    public JsonCanonicalizer(string jsonData)
    {
        _buffer = new StringBuilder();
        Serialize(new JsonDecoder(jsonData).Root);
    }

    public JsonCanonicalizer(byte[] jsonData)
        : this(new UTF8Encoding(false, true).GetString(jsonData))
    {

    }

    private void Escape(char c)
    {
        _buffer.Append('\\').Append(c);
    }

    private void SerializeString(string value)
    {
        _buffer.Append('"');
        foreach (var c in value)
        {
            switch (c)
            {
                case '\n':
                    Escape('n');
                    break;

                case '\b':
                    Escape('b');
                    break;

                case '\f':
                    Escape('f');
                    break;

                case '\r':
                    Escape('r');
                    break;

                case '\t':
                    Escape('t');
                    break;

                case '"':
                case '\\':
                    Escape(c);
                    break;

                default:
                    if (c < ' ')
                    {
                        _buffer.Append("\\u").Append(((int)c).ToString("x04"));
                    }
                    else
                    {
                        _buffer.Append(c);
                    }
                    break;
            }
        }
        _buffer.Append('"');
    }

    private void Serialize(object o)
    {
        switch (o)
        {
            case SortedDictionary<string, object> objects:
            {
                _buffer.Append('{');
                bool next = false;
                foreach (var keyValuePair in objects)
                {
                    if (next)
                    {
                        _buffer.Append(',');
                    }
                    next = true;
                    SerializeString(keyValuePair.Key);
                    _buffer.Append(':');
                    Serialize(keyValuePair.Value);
                }
                _buffer.Append('}');
                break;
            }
            case List<object> list:
            {
                _buffer.Append('[');
                var next = false;
                foreach (var value in list)
                {
                    if (next)
                    {
                        _buffer.Append(',');
                    }
                    next = true;
                    Serialize(value);
                }
                _buffer.Append(']');
                break;
            }
            case null:
                _buffer.Append("null");
                break;
            case string s:
                SerializeString(s);
                break;
            case bool:
                _buffer.Append(o.ToString()!.ToLowerInvariant());
                break;
            case double d:
                _buffer.Append(NumberToJson.SerializeNumber(d));
                break;
            default:
                throw new InvalidOperationException("Unknown object: " + o);
        }
    }

    public string GetEncodedString()
    {
        return _buffer.ToString();
    }

}

internal static class JsonToNumber
{
    public static double Convert(string number)
    {
        return double.Parse(number, NumberStyles.Float, CultureInfo.InvariantCulture);
    }
}

internal class JsonDecoder
{
    private const char LeftCurlyBracket  = '{';
    private const char RightCurlyBracket = '}';
    private const char DoubleQuote        = '"';
    private const char ColonCharacter     = ':';
    private const char LeftBracket        = '[';
    private const char RightBracket       = ']';
    private const char CommaCharacter     = ',';
    private const char BackSlash          = '\\';

    private static readonly Regex NumberPattern  = new Regex("^-?[0-9]+(\\.[0-9]+)?([eE][-+]?[0-9]+)?$");
    private static readonly Regex BooleanPattern = new Regex("^true|false$");

    private int _index;
    private readonly string _jsonData;

    internal readonly object Root;

    internal JsonDecoder(string jsonData)
    {
        _jsonData = jsonData;
        if (TestNextNonWhiteSpaceChar() == LeftBracket)
        {
            Scan();
            Root = ParseArray();
        }
        else
        {
            ScanFor(LeftCurlyBracket);
            Root = ParseObject();
        }
        while (_index < jsonData.Length)
        {
            if (!IsWhiteSpace(jsonData[_index++]))
            {
                throw new IOException("Improperly terminated JSON object");
            }
        }
    }

    private object? ParseElement()
    {
        return Scan() switch
        {
            LeftCurlyBracket => ParseObject(),
            DoubleQuote => ParseQuotedString(),
            LeftBracket => ParseArray(),
            _ => ParseSimpleType()
        };
    }

    private object ParseObject()
    {
        var dict =
            new SortedDictionary<string, object?>(StringComparer.Ordinal);
        var next = false;
        while (TestNextNonWhiteSpaceChar() != RightCurlyBracket)
        {
            if (next)
            {
                ScanFor(CommaCharacter);
            }
            next = true;
            ScanFor(DoubleQuote);
            var name = ParseQuotedString();
            ScanFor(ColonCharacter);
            dict.Add(name, ParseElement());
        }
        Scan();
        return dict;
    }

    private object ParseArray()
    {
        var list = new List<object>();
        var next = false;
        while (TestNextNonWhiteSpaceChar() != RightBracket)
        {
            if (next)
                ScanFor(CommaCharacter);
            else
                next = true;

            var obj = ParseElement(); 
            if (obj is not null)
                list.Add(obj);
        }
        Scan();
        return list;
    }

    private object? ParseSimpleType()
    {
        _index--;
        var tempBuffer = new StringBuilder();
        char c;
        while ((c = TestNextNonWhiteSpaceChar()) != CommaCharacter && c != RightBracket && c != RightCurlyBracket)
        {
            if (IsWhiteSpace(c = NextChar()))
                break;
            tempBuffer.Append(c);
        }
        var token = tempBuffer.ToString();
        if (token.Length == 0)
            throw new IOException("Missing argument");
        if (NumberPattern.IsMatch(token))
            return JsonToNumber.Convert(token);
        if (BooleanPattern.IsMatch(token))
            return bool.Parse(token);
        if (token.Equals("null"))
            return null;
        throw new IOException("Unrecognized or malformed JSON token: " + token);
    }

    private string ParseQuotedString()
    {
        StringBuilder result = new StringBuilder();
        while (true)
        {
            var c = NextChar();
            if (c < ' ')
                throw new IOException(c == '\n' ? "Unterminated string literal" :
                    "Unescaped control character: 0x" + ((int)c).ToString("x02"));
            if (c == DoubleQuote)
                break;
            if (c == BackSlash)
            {
                switch (c = NextChar())
                {
                    case '"':
                    case '\\':
                    case '/':
                        break;
                    case 'b':
                        c = '\b';
                        break;
                    case 'f':
                        c = '\f';
                        break;
                    case 'n':
                        c = '\n';
                        break;
                    case 'r':
                        c = '\r';
                        break;
                    case 't':
                        c = '\t';
                        break;
                    case 'u':
                        c = (char)0;
                        for (var i = 0; i < 4; i++)
                            c = (char)((c << 4) + GetHexChar());
                        break;

                    default:
                        throw new IOException("Unsupported escape:" + c);
                }
            }
            result.Append(c);
        }
        return result.ToString();
    }

    private char GetHexChar()
    {
        var c = NextChar();
        switch (c)
        {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                return (char)(c - '0');
            case 'a':
            case 'b':
            case 'c':
            case 'd':
            case 'e':
            case 'f':
                return (char)(c - 'a' + 10);
            case 'A':
            case 'B':
            case 'C':
            case 'D':
            case 'E':
            case 'F':
                return (char)(c - 'A' + 10);
        }
        throw new IOException("Bad hex in \\u escape: " + c);
    }

    private char TestNextNonWhiteSpaceChar()
    {
        var save = _index;
        var c = Scan();
        _index = save;
        return c;
    }

    private void ScanFor(char expected)
    {
        var c = Scan();
        if (c != expected)
            throw new IOException("Expected '" + expected + "' but got '" + c + "'");
    }

    private char NextChar()
    {
        if (_index < _jsonData.Length)
            return _jsonData[_index++];
        throw new IOException("Unexpected EOF reached");
    }

    private static bool IsWhiteSpace(char c)
    {
        return c == 0x20 || c == 0x0A || c == 0x0D || c == 0x09;
    }

    private char Scan()
    {
        while (true)
        {
            var c = NextChar();
            if (IsWhiteSpace(c))
                continue;
            return c;
        }
    }
    
}