function handleFileSelect() {
    var fileInput = document.getElementById("file-input");
    var statusElement = document.getElementById("status");
    var headerElement = document.getElementById("email-header");
    var senderIpElement = document.getElementById("sender-ip");
    var abuseInfoElement = document.getElementById("abuse-info");
    var emailContentElement = document.getElementById("email-content"); // Added line

    if (fileInput.files.length > 0) {
        var file = fileInput.files[0];

        if (file.name.endsWith(".eml")) {
            var reader = new FileReader();

            reader.onload = function (e) {
                var content = e.target.result;

                // Parse headers and body
                var headerEnd = content.indexOf("\r\n\r\n");
                if (headerEnd !== -1) {
                    var headers = content.substring(0, headerEnd);
                    var body = content.substring(headerEnd + 4); // Skip the double line break

                    // Extract sender's IP address using a more permissive regular expression
                    var match = headers.match(/Received:.*\[(\S+)\]/);
                    var senderIp = match ? match[1] : "IP not found";

                    // Display the content of the .eml file
                    headerElement.textContent = `Email Headers:\n${headers}`;
                    senderIpElement.innerHTML = `Sender's IP: ${senderIp}`;
                    emailContentElement.textContent = `Email Content:\n${body}`; // Added line

                    // Check if the IP is malicious using the VirusTotal API
                    console.log("Checking IP for abuse:", senderIp);
                    checkIPForAbuse(senderIp);
                    statusElement.textContent = ""; // Clear any previous status messages
                } else {
                    // Handle case where headers are not found
                    headerElement.textContent = "Invalid .eml file. Headers not found.";
                    senderIpElement.textContent = "";
                    abuseInfoElement.textContent = ""; // Clear abuse info
                    emailContentElement.textContent = ""; // Added line
                    statusElement.textContent = "";
                }
            };

            reader.readAsText(file);
            statusElement.textContent = "Selected file: " + file.name;
        } else {
            statusElement.textContent = "Please select a valid .eml file.";
            // Clear the file input
            fileInput.value = "";
            headerElement.textContent = "";
            senderIpElement.textContent = "";
            abuseInfoElement.textContent = ""; // Clear abuse info
            emailContentElement.textContent = ""; // Added line
        }
    } 
}


function checkIPForAbuse(ip) {
    console.log("Checking IP for abuse:", ip);

    fetch('/check_ip', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip: ip }),
    })
        .then(response => response.json())
        .then(data => {
            console.log("VirusTotal response:", data);
            // Display the VirusTotal information
            displayAbuseInfo(data, ip);
        })
        .catch(error => {
            console.error('Error fetching data:', error);
        });
}

function displayAbuseInfo(abuseData, ip) {
    var senderIpElement = document.getElementById("sender-ip");
    var abuseInfoElement = document.getElementById("abuse-info");

    senderIpElement.innerHTML = `Sender's IP: ${ip}`;

    console.log("Displaying Abuse Info:", abuseData); // Log the received data for debugging

    if (abuseData && abuseData.data) {
        var abuseConfidenceScore = abuseData.data.abuseConfidenceScore || 0;
        var suspiciousConfidenceScore = abuseData.data.suspiciousConfidenceScore || 0;
        var numReports = abuseData.data.numReports || 0;
        var scanDate = abuseData.data.scanDate || 'N/A';
        var scanResults = abuseData.data.scanResults || 'N/A';
        var country = abuseData.data.country || 'N/A';

        abuseInfoElement.innerHTML = `VirusTotal Information:`;
        abuseInfoElement.innerHTML += `<br>Abuse Confidence Score: ${abuseConfidenceScore}`;
        abuseInfoElement.innerHTML += `<br>Suspicious Confidence Score: ${suspiciousConfidenceScore}`;
        abuseInfoElement.innerHTML += `<br>Number of Reports: ${numReports}`;
        abuseInfoElement.innerHTML += `<br>Last Analysis Date: ${scanDate}`;
        abuseInfoElement.innerHTML += `<br>Last Analysis Results: ${scanResults}`;
        abuseInfoElement.innerHTML += `<br>Country: ${country}`;
    } else {
        abuseInfoElement.innerHTML = `<br>No VirusTotal information available for this IP.`;
    }
}
