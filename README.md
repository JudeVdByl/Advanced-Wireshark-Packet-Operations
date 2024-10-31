# Advanced Wireshark Packet Operations

## Objective
This project delves into advanced packet analysis techniques in Wireshark, focusing on identifying and filtering specific traffic patterns, addresses, and protocol types. I examine various aspects such as resolved addresses, IP conversations, DNS queries, and TCP/HTTP packet details to answer predefined questions about network traffic.

## Skills Learned
- Advanced packet filtering techniques in Wireshark
- Identifying specific IP address patterns and MAC address activity
- Utilizing DNS statistics and query types to pinpoint traffic origins
- Using HTTP and TCP filters to isolate specific server and request data
- Configuring and applying custom profiles, such as "Checksum Control," for error analysis

## Tools Used
- **Wireshark**: For detailed network analysis, filtering, and diagnostics
- **Linux OS**: Ubuntu-based environment for system navigation

## Steps

### 1. Resolved Addresses Lookup
- **Task**: Identify the IP address for the hostname starting with "bbc".
- **Solution**: Found the IP `199.232.24.81` associated with `bbc.map.fastly.net`.

   ![image](https://github.com/user-attachments/assets/81352949-6a99-49db-a0c2-d7aead73614d)

### 2. Counting IPv4 Conversations
- **Task**: Determine the number of IPv4 conversations in the capture.
- **Solution**: Located `435` IPv4 conversations using the conversation statistics.

   ![image](https://github.com/user-attachments/assets/7f088d52-fd06-40e5-86f6-172319b165fe)

### 3. Calculating Data Transferred by MAC Address
- **Task**: Check how many bytes were transferred from the "Micro-St" MAC address.
- **Solution**: `7474k` bytes were transferred from this address, as identified in the endpoint details.

   ![image](https://github.com/user-attachments/assets/a707f68b-bc35-4acf-864b-ce5e2245eee8)

### 4. IP Addresses Linked with Kansas City
- **Task**: Find the number of IP addresses linked with "Kansas City".
- **Solution**: Identified `4` IP addresses associated with Kansas City.

   ![image](https://github.com/user-attachments/assets/1b1db000-afa5-4aeb-8170-fc95f86c196b)

### 5. Analyzing DNS Request-Response Times
- **Task**: Determine the max service request-response time for DNS packets.
- **Solution**: The maximum request-response time was `0.467897` seconds.

   ![image](https://github.com/user-attachments/assets/c5aeebb5-232f-4e45-9903-36d18d8b72df)

### 6. HTTP Requests for Specific Domains
- **Task**: Find the number of HTTP requests for "rad[.]msn[.]com".
- **Solution**: Found `39` HTTP requests for this domain.

   ![image](https://github.com/user-attachments/assets/c0d920f5-bf71-4522-9ac0-a365859ee25a)

### 7. Counting Total IP Packets
- **Task**: Count the total number of IP packets in the capture file.
- **Solution**: The file contained `81420` IP packets.

   ![image](https://github.com/user-attachments/assets/ad7ab2cb-e7a0-434e-bdd7-0a16f61d4754)

### 8. Filtering Packets with TTL Value < 10
- **Task**: Find the number of packets with TTL less than 10.
- **Solution**: Located `66` packets with TTL values below 10 using `ip.ttl < 10`.

   ![image](https://github.com/user-attachments/assets/6e5a0088-c7c8-452e-af15-68bdf5515d2c)

### 9. Filtering TCP Packets Using Port 4444
- **Task**: Determine the number of packets using TCP port 4444.
- **Solution**: Filtered out `632` packets with TCP port 4444 using `tcp.port == 4444`.

   ![image](https://github.com/user-attachments/assets/2620a03a-7910-4b63-86c8-e5b3746f097f)

### 10. HTTP GET Requests on Port 80
- **Task**: Find the count of "HTTP GET" requests sent to port 80.
- **Solution**: Identified `527` HTTP GET requests directed to port 80 using `http.request.method == “Get” and tcp.port == 80`.

   ![image](https://github.com/user-attachments/assets/6962607a-f151-4df1-96c1-6a91e18eaf6f)

### 11. Analyzing Type A DNS Queries
- **Task**: Find the number of "type A" DNS queries.
- **Solution**: Found `51` type A DNS queries using `dns.a`.

   ![image](https://github.com/user-attachments/assets/e8206792-a6c3-4a2b-aa54-3afb2fa32a7f)

### 12. Filtering Non-Port 80 Microsoft IIS Traffic
- **Task**: Count packets from Microsoft IIS servers not originating from port 80.
- **Solution**: Identified `21` such packets using `!(tcp.port == 80) and lower(http.server) contains "microsoft"`.

   ![image](https://github.com/user-attachments/assets/8be5e673-e368-4984-aab5-433ff2b2e476)

### 13. Filtering Specific TCP Ports (3333, 4444, 9999)
- **Task**: Find the total number of packets using TCP ports 3333, 4444, or 9999.
- **Solution**: Located `2235` packets on these ports using `tcp.port == 3333 || tcp.port == 4444 || tcp.port == 9999`.

   ![image](https://github.com/user-attachments/assets/0a235fbd-eae9-422c-af91-a598992e615c)

### 14. Microsoft IIS Server Version 7.5
- **Task**: Identify packets with Microsoft IIS server version 7.5.
- **Solution**: Found `71` packets associated with version 7.5 using `http.server contains "Microsoft-IIS/7.5"`.

   ![image](https://github.com/user-attachments/assets/9ab2c0a7-2982-422c-b82c-d4287289a185)

### 15. Packets with Even TTL Numbers
- **Task**: Find packets with even TTL numbers.
- **Solution**: Located `77289` packets with even TTL values using `I used string(ip.ttl) matches "[02468]$"`.

   ![image](https://github.com/user-attachments/assets/ad68b1d2-cb2a-476b-a0cd-560bad6551ca)

### 16. Bad TCP Checksum Detection
- **Task**: Switch to "Checksum Control" and count "Bad TCP Checksum" packets.
- **Solution**: Detected `34185` packets with bad TCP checksums using `Tcp.checksum_bad.expert`.

   ![image](https://github.com/user-attachments/assets/a1fc6ee2-456f-42cd-ab04-5b2983ae21f1)

### 17. Filtering Traffic by HTTP Response and Content Type
- **Task**: Use a filter to display packets with HTTP response code 200 and content type as images.
- **Solution**: Applied the filter, resulting in `261` displayed packets using `(http.response.code == 200 ) && (http.content_type matches "image(gif||jpeg)")`.

   ![image](https://github.com/user-attachments/assets/1d08216d-837a-4a71-bfe7-786266036882)

---

## Conclusion
This advanced Wireshark project reinforced my knowledge of packet filtering, error analysis, and detailed traffic diagnostics. By examining specific fields like TTL values, DNS response times, and TCP checksums, I further developed my skills in network protocol analysis and packet inspection, gaining a deeper understanding of network traffic patterns.

