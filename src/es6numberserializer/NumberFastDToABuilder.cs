/* -*- Mode: java; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 4 -*-
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Ported to C# from the Mozilla "Rhino" project by Anders Rundgren.
// Some clean up and C#10/.NET 6 updates made by Shift Everywhere

namespace es6numberserializer;

/// <summary>
/// This is an internal part of a ES6 compatible JSON Number serializer.
/// </summary>
internal class NumberFastDToABuilder
{
    // allocate buffer for generated digits + extra notation + padding zeroes
    private readonly char[] _chars = new char[NumberFastDToA.kFastDtoaMaximalLength + 8];
    internal int End;
    internal int Point;
    private bool _formatted;

    public void Append(char c)
    {
        _chars[End++] = c;
    }

    public void DecreaseLast()
    {
        _chars[End - 1]--;
    }

    public void Reset()
    {
        End = 0;
        _formatted = false;
    }

    public string Format()
    {
        if (_formatted) return new string(_chars, 0, End);
        // check for minus sign
        var firstDigit = _chars[0] == '-' ? 1 : 0;
        var decPoint = Point - firstDigit;
        if (decPoint < -5 || decPoint > 21)
            ToExponentialFormat(firstDigit, decPoint);
        else
            ToFixedFormat(firstDigit, decPoint);
        _formatted = true;
        return new string(_chars, 0, End);

    }

    private void ArrayFill0(int from, int to)
    {
        while (from < to)
        {
            _chars[from++] = '0';
        }
    }

    private void ToFixedFormat(int firstDigit, int decPoint)
    {
        if (Point < End)
        {
            // insert decimal point
            if (decPoint > 0)
            {
                // >= 1, split decimals and insert point
                Array.Copy(_chars, Point, _chars, Point + 1, End - Point);
                _chars[Point] = '.';
                End++;
            }
            else
            {
                // < 1,
                int target = firstDigit + 2 - decPoint;
                Array.Copy(_chars, firstDigit, _chars, target, End - firstDigit);
                _chars[firstDigit] = '0';
                _chars[firstDigit + 1] = '.';
                if (decPoint < 0)
                {
                    ArrayFill0(firstDigit + 2, target);
                }
                End += 2 - decPoint;
            }
        }
        else if (Point > End)
        {
            // large integer, add trailing zeroes
            ArrayFill0(End, Point);
            End += Point - End;
        }
    }

    private void ToExponentialFormat(int firstDigit, int decPoint)
    {
        if (End - firstDigit > 1)
        {
            // insert decimal point if more than one digit was produced
            int dot = firstDigit + 1;
            Array.Copy(_chars, dot, _chars, dot + 1, End - dot);
            _chars[dot] = '.';
            End++;
        }
        _chars[End++] = 'e';
        char sign = '+';
        int exp = decPoint - 1;
        if (exp < 0)
        {
            sign = '-';
            exp = -exp;
        }
        _chars[End++] = sign;

        int charPos = exp > 99 ? End + 2 : exp > 9 ? End + 1 : End;
        End = charPos + 1;

        // code below is needed because Integer.getChars() is not internal
        for (;;)
        {
            var r = exp % 10;
            _chars[charPos--] = Digits[r];
            exp = exp / 10;
            if (exp == 0) break;
        }
    }

    private static readonly char[] Digits = 
    {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    };
}