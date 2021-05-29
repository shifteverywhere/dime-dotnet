using System;
using System.ComponentModel;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;

namespace ShiftEverywhere.DiME
{
    /// <summary></summary>
    public enum Capability
    {
        /// <summary></summary>
        Self, 
        /// <summary></summary>
        Generic, 
        /// <summary></summary>
        Identify, 
        /// <summary></summary>
        Issue
    }

}