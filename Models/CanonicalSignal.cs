using System;
using System.Collections.Generic;

namespace ThreatIntelPlatform.Models
{
    public class CanonicalSignal
    {
        // Cosmos DB strictly requires every document to have a lowercase 'id' property
        public string id { get; set; } = Guid.NewGuid().ToString(); 

        public string Source { get; set; } // e.g., "Enzoic", "CertStream", "PhishingCrawler"
        
        public string TenantId { get; set; } // Which client does this belong to?
        
        public string Type { get; set; } // e.g., "credential_exposure", "suspicious_domain"
        
        public int Score { get; set; } // 0-100 severity score
        
        public List<string> ReasonCodes { get; set; } = new List<string>(); // e.g., ["Stealer_Log"]
        
        public List<string> Iocs { get; set; } = new List<string>(); // Indicators of Compromise
        
        public string Snippet { get; set; } // <=300 chars preview
        
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
}