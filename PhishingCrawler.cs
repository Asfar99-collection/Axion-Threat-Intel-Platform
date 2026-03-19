using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Azure.Storage.Blobs; // Lets us upload raw files
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Playwright; // The headless browser
using ThreatIntelPlatform.Models;

namespace ThreatIntelPlatform
{
    public class PhishingCrawler
    {
        private readonly ILogger _logger;

        public PhishingCrawler(ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.CreateLogger<PhishingCrawler>();
        }

        [Function("PhishingCrawler")]
        public async Task<IngestionOutput> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequestData req)
        {
            _logger.LogInformation("Phishing Crawler initializing hidden browser...");

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            using JsonDocument data = JsonDocument.Parse(requestBody);
            string targetUrl = data.RootElement.GetProperty("url").GetString();

            // ==========================================
            // 1. SPIN UP THE HEADLESS BROWSER
            // ==========================================
            using var playwright = await Playwright.CreateAsync();
            await using var browser = await playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions { Headless = true });
            var page = await browser.NewPageAsync();

            // Setup a trap to catch sneaky Redirect Chains (e.g., bit.ly -> fake-login -> evil-malware)
            var redirectChain = new List<string>();
            page.Response += (_, response) => 
            {
                if (response.Status >= 300 && response.Status <= 399)
                {
                    redirectChain.Add($"[{response.Status}] Redirect to: {response.Headers["location"]}");
                }
            };

            // ==========================================
            // 2. NAVIGATE & CAPTURE EVIDENCE
            // ==========================================
            _logger.LogInformation($"Crawling URL: {targetUrl}");
            
            // WaitUntilState.NetworkIdle ensures the page finishes loading all the fake hacker images!
            await page.GotoAsync(targetUrl, new PageGotoOptions { WaitUntil = WaitUntilState.NetworkIdle });
            
            byte[] screenshotBytes = await page.ScreenshotAsync(new PageScreenshotOptions { FullPage = true });
            string htmlContent = await page.ContentAsync();

            // ==========================================
            // 3. ISOLATE ARTIFACTS IN BLOB STORAGE
            // ==========================================
            string blobConnStr = Environment.GetEnvironmentVariable("BlobStorageConnection");
            var blobServiceClient = new BlobServiceClient(blobConnStr);
            var containerClient = blobServiceClient.GetBlobContainerClient("evidence");
            
            string fileId = Guid.NewGuid().ToString().Substring(0, 8); // Short random ID
            string screenshotName = $"phish-{fileId}.png";
            string htmlName = $"phish-{fileId}.html";

            // Upload Screenshot
            var screenshotBlob = containerClient.GetBlobClient(screenshotName);
            await screenshotBlob.UploadAsync(new BinaryData(screenshotBytes), overwrite: true);

            // Upload HTML source code
            var htmlBlob = containerClient.GetBlobClient(htmlName);
            await htmlBlob.UploadAsync(new BinaryData(htmlContent), overwrite: true);

            _logger.LogInformation($"Evidence isolated: {screenshotName} and {htmlName}");

            // ==========================================
            // 4. PUSH TO SIGNAL PIPELINE
            // ==========================================
            var signal = new CanonicalSignal
            {
                Source = "PhishingCrawler",
                TenantId = "Demo_Client_001",
                Type = "phishing",
                Score = 95, // High severity because we proved it exists!
                ReasonCodes = new List<string> { "Malicious_Page_Captured" },
                Iocs = new List<string> { $"SuspiciousURL:{targetUrl}" },
                Snippet = $"Redirects found: {redirectChain.Count}. Evidence saved to Blob: {screenshotName}",
                Timestamp = DateTime.UtcNow
            };

            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteStringAsync($"Crawled {targetUrl}. Evidence successfully captured to Azure.");

            return new IngestionOutput
            {
                CosmosDocument = signal,
                ServiceBusMessage = JsonSerializer.Serialize(signal),
                HttpResponse = response
            };
        }
    }
}