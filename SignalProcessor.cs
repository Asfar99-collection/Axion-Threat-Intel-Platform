using System;
using System.Linq;
using System.Text.Json;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using ThreatIntelPlatform.Models;

namespace ThreatIntelPlatform
{
    public class SignalProcessorOutput
    {
        [CosmosDBOutput(databaseName: "ThreatIntelDb", containerName: "cases", Connection = "CosmosDbConnection")]
        public Case NewCase { get; set; }
    }

    public class SignalProcessor
    {
        private readonly ILogger _logger;

        public SignalProcessor(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<SignalProcessor>();
        }

        [Function("SignalProcessor")]
        public SignalProcessorOutput Run([ServiceBusTrigger("signals.incoming", Connection = "ServiceBusConnection")] string queueMessage)
        {
            _logger.LogInformation("Picked up a new signal from the conveyor belt!");

            var signal = JsonSerializer.Deserialize<CanonicalSignal>(queueMessage);
            
            string severity = "None";
            string matchedRule = "None";

            // ==========================================
            // SCORING RULES
            // ==========================================
            
            // RULE A: Enzoic VIP Exposure
            if (signal.Type == "credential_exposure")
            {
                if (signal.Iocs.Any(ioc => ioc.Contains("ceo@demo_client.com")))
                {
                    matchedRule = "VIP Credential Exposure (CEO)";
                    severity = "Critical";
                }
                else if (signal.Score >= 90)
                {
                    matchedRule = "High-Confidence Credential Exposure";
                    severity = "High";
                }
            }
            // RULE B: CertStream Brand Impersonation
            else if (signal.Type == "brand_impersonation" && signal.Score >= 80)
            {
                matchedRule = "Brand Impersonation Domain";
                severity = "High";
            }
            // RULE C: DNSTwist Typosquatting
            else if (signal.Type == "suspicious_domain" && signal.Score >= 80)
            {
                matchedRule = "Active Typosquatting Site";
                severity = "High";
            }
            // RULE D: Phishing Crawler (Day 8 Validation)
            else if (signal.Type == "phishing" && signal.Score >= 80)
            {
                matchedRule = "Confirmed Credential Harvesting Site";
                severity = "Critical";
            }

            // ==========================================
            // CASE AUTO-CREATION
            // ==========================================
            if (severity == "High" || severity == "Critical")
            {
                _logger.LogInformation($"Threshold met. Auto-opening a new {severity} security case...");

                var newCase = new Case
                {
                    id = Guid.NewGuid().ToString(),
                    Title = $"[{severity}] {matchedRule}",
                    Severity = severity,
                    Status = "Open",
                    // ---> THIS IS THE FIX! Copy the data for the Dashboard <---
                    Source = signal.Source,
                    Score = signal.Score,
                    Iocs = signal.Iocs,
                    Snippet = signal.Snippet,
                    Timestamp = DateTime.UtcNow 
                };

                return new SignalProcessorOutput { NewCase = newCase };
            }

            _logger.LogInformation("Signal score too low. Dropping.");
            return null;
        }
    }
}