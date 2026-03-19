using System;
using System.Collections.Generic;

namespace ThreatIntelPlatform.Models
{
    public class Case
    {
        public string id { get; set; }
        public string Title { get; set; }
        public string Severity { get; set; }
        public string Status { get; set; }
        
        // --- NEW DASHBOARD FIELDS ---
        public string Source { get; set; }
        public int Score { get; set; }
        public List<string> Iocs { get; set; }
        public string Snippet { get; set; }
        public DateTime Timestamp { get; set; }
    }
}