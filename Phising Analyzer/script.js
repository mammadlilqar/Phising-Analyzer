function handleFileSelect() {
    var fileInput = document.getElementById("file-input");
    var statusElement = document.getElementById("status");
    var headerElement = document.getElementById("email-header");
    var bodyElement = document.getElementById("email-body");
    var senderIpElement = document.getElementById("sender-ip");

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
                    bodyElement.textContent = `Email Body:\n${body}`;
                    senderIpElement.innerHTML = `Sender's IP: ${senderIp}`;

                    // Check if the IP is malicious using the AbuseIPDB API
                    checkIPForAbuse(senderIp);
                    statusElement.textContent = ""; // Clear any previous status messages
                } else {
                    // Handle case where headers are not found
                    headerElement.textContent = "Invalid .eml file. Headers not found.";
                    bodyElement.textContent = "";
                    senderIpElement.textContent = "";
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
            bodyElement.textContent = "";
            senderIpElement.textContent = "";
        }
    } else {
        statusElement.textContent = "Please select a file.";
    }
}



function checkIPForAbuse(ip) {
    // Replace [API_KEY] with your actual AbuseIPDB API key
    var apiKey = "a2fc9158c6a99979b4ee6d36040158a71e8d3e57f69fd793c4acd04dc44e356d294ce73fa88152b0	";
    // Replace [DAYS] with the number of days you want to check (e.g., 30)
    var days = 30;

    // Make a request to the AbuseIPDB API
    var apiUrl = `https://www.abuseipdb.com/check/${ip}/json?key=${apiKey}&days=${days}`;
    fetch(apiUrl)
        .then(response => response.json())
        .then(data => {
            displayAbuseInfo(data, ip);
        })
        .catch(error => {
            console.error('Error fetching data:', error);
        });
}

function displayAbuseInfo(abuseData, ip) {
    var senderIpElement = document.getElementById("sender-ip");
    senderIpElement.innerHTML = `Sender's IP: ${ip}`;

    if (abuseData && abuseData.data) {
        var isMalicious = abuseData.data.abuseConfidenceScore >= 50;
        senderIpElement.innerHTML += `<br>AbuseIPDB Information:`;
        senderIpElement.innerHTML += `<br>Is Malicious: ${isMalicious ? 'Yes' : 'No'}`;
        senderIpElement.innerHTML += `<br>Abuse Confidence Score: ${abuseData.data.abuseConfidenceScore}`;
        senderIpElement.innerHTML += `<br>Number of Reports: ${abuseData.data.numReports}`;
    } else {
        senderIpElement.innerHTML += `<br>No AbuseIPDB information available for this IP.`;
    }
}
