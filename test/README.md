## Usage

Unit Test cases for gtpv1c information elements and messages with the help of CUnit framework.
For performing UT for each functions Used for encoding and decoding of Messages and IEs, list of supported Messages in Table 1.1 and supported IE's in Table 1.2.

## Tables

|No.|Messages|Support|
|---|---|---|
|1.| Echo Request| Yes|
|2.| Echo Response| Yes|
|3.| Version Not Supported| Yes|
|4.| Create PDP Context Request| Yes|
|5.| Create PDP Context Response| Yes|
|6.| Update PDP Context Request (SGSN-Initiated)| Yes|
|7.| Update PDP Context Request (GGSN-Initiated)| Yes|
|8.| Update PDP Context Response (sent by GGSN)| Yes|
|9.| Update PDP Context Response (sent by SGSN)| Yes|
|10.| Delete PDP Context Request| Yes|
|11.| Delete PDP Context Response| Yes|
|12.| PDU Notification Request| Yes|
|13.| PDU Notification Response| Yes|
|14.| PDU Notification Reject Request| Yes|
|15.| PDU Notification Reject Response| Yes|
|16.| Initiate PDP Context Activation Request| Yes|
|17.| Initiate PDP Context Activation Response| Yes|
|18.| Send Routeing Information for GPRS Request| Yes|
|19.| Send Routeing Information for GPRS Response| Yes|
|20.| Failure Report Request| Yes|
|21.| Failure Report Response| Yes|
|22.| Note MS GPRS Present Request| Yes|
|23.| Note MS GPRS Present Response| Yes|
|24.| SGSN Context Request| Yes|
|25.| SGSN Context Response| Yes|
|26.| UE Registration Query Request| No|
|27.| UE Registration Query Response| No|
|28.| RAN Information Relay| Yes|
|29.| MBMS Notification Request| Yes|
|30.| MBMS Notification Response| Yes|
|31.| Forward Relocation Request| Yes|
|32.| Forward Relocation Response| Yes|
|33.| Identification Request| Yes|
|34.| Identification Response| Yes|
|35.| MS Info Change Notification Request| Yes|
|36.| MS Info Change Notification Response| Yes|
|37.| Relocation Cancel Request| Yes|
|38.| Relocation Cancel Response| Yes|
|39.| Forward Relocation Complete Acknowledge| Yes|
|40.| Forward Relocation Complete| Yes|
|41.| Forward SRNS Context Acknowledge| Yes|
|42.| Forward SRNS Context| Yes|
|43.| SGSN Context Acknowledge| Yes|
|44.| Supported Extension Headers Notification| Yes|
|45.| Error Indication| No|
|46.| MBMS Notification Reject Request| No|
|47.| MBMS Notification Reject Response| No|
|48.| Create MBMS Context Request| No|
|49.| Create MBMS Context Response| No|
|50.| Update MBMS Context Request| No|
|51.| Update MBMS Context Response| No|
|52.| Delete MBMS Context Request| No|
|53.| Delete MBMS Context Response| No|
|55.| MBMS Registration Request| No|
|56.| MBMS Registration Response| No|
|57.| MBMS De-registration Request| No|
|58.| MBMS De-registration Response| No|
|59.| MBMS Session Start Request| No|
|60.| MBMS Session Start Response| No|
|61.| MBMS Session Stop Request| No|
|62.| MBMS Session Stop Response| No|
|63.| MBMS Session Update Request| No|
|64.| MBMS Session Update Response| No|

**Table 1.1 GTPv1C Messages**

|No.|IEs|Support|
|---|---|---|
|1.| Cause| Yes|
|2.| International Mobile Subscriber Identity (IMSI)| Yes|
|3.| Routeing Area Identity (RAI)| Yes|
|4.| Temporary Logical Link Identity (TLLI)| Yes|
|5.| Packet TMSI (P-TMSI)| Yes|
|6.| Reordering Required| Yes|
|7.| Authentication Triplet| Yes|
|8.| MAP Cause| Yes|
|9.| P-TMSI Signature| Yes|
|10.| MS Validated| Yes|
|11.| Recovery| Yes|
|12.| Selection Mode| Yes|
|13.| Tunnel Endpoint Identifier Data I| Yes|
|14.| Tunnel Endpoint Identifier Control Plane| Yes|
|15.| Tunnel Endpoint Identifier Data II| Yes|
|16.| Teardown Ind| Yes|
|17.| NSAPI| Yes|
|18.| RANAP Cause| Yes|
|19.| RAB Context| Yes|
|20.| Radio Priority SMS| Yes|
|21.| Radio Priority| Yes|
|22.| Packet Flow Id| Yes|
|23.| Charging Characteristics| Yes|
|24.| Trace Reference| Yes|
|25.| Trace Type| Yes|
|26.| MS Not Reachable Reason| Yes|
|27.| Radio Priority LCS| Yes|
|28.| Charging ID| Yes|
|29.| End User Address| Yes|
|30.| MM Context| Yes|
|31.| PDP Context| Yes|
|32.| Access Point Name| Yes|
|33.| Protocol Configuration Options| Yes|
|34.| GSN Address| Yes|
|35.| MS International PSTN/ISDN Number (MSISDN)| Yes|
|36.| Quality of Service Profile| Yes|
|37.| Authentication Quintuplet| Yes|
|38.| Traffic Flow Template| Yes|
|39.| Target Identification| Yes|
|40.| UTRAN Transparent Container| No|
|41.| RAB Setup Information| Yes|
|42.| Extension Header Type List| Yes|
|43.| Trigger Id| Yes|
|44.| OMC Identity| Yes|
|45.| RAN Transparent Container| Yes|
|46.| Charging Gateway Address| Yes|
|47.| PDP Context Prioritization| Yes|
|48.| Additional RAB Setup Information| Yes|
|49.| Private Extension| Yes|
|50.| SGSN Number| Yes|
|51.| Common Flags| Yes|
|52.| APN Restriction| Yes|
|53.| RAT Type| Yes|
|54.| User Location Information| Yes|
|55.| MS Time Zone| Yes|
|56.| IMEI(SV)| Yes|
|57.| CAMEL Charging Information Container| No|
|58.| MBMS UE Context| Yes|
|59 | Temporary Mobile Group Identity| No|
|60.| RIM Routing Address| Yes|
|61.| MBMS Protocol Configuration Options| No|
|62.| MBMS Session Duration| No|
|63.| MBMS Service Area| No|
|64.| Source RNC PDCP context info| Yes|
|65.| Additional Trace Info| Yes|
|66.| Hop Counter| Yes|
|67.| Selected PLMN ID| Yes|
|68.| MBMS Session Identifier| No|
|69.| MBMS 2G/3G Indicator| No|
|70.| Enhanced NSAPI| No|
|71.| Additional MBMS Trace Info| No|
|72.| MBMS Session Repetition Number| No|
|73.| MBMS Time To Data Transfer| No|
|74.| BSS Container| No|
|75.| Cell Identification| Yes|
|76.| PDU Numbers| Yes|
|77.| BSSGP Cause| Yes|
|78.| Required MBMS Bearer Capabilities| No|
|79.| RIM Routing Address Discriminator| Yes|
|80.| List of set-up PFCs| Yes|
|81.| PS Handover XID Parameters| No|
|82.| MS Info Change Reporting Action| Yes|
|83.| Direct Tunnel Flags| Yes|
|84.| Correlation-ID| Yes|
|85.| Bearer Control Mode| Yes|
|86.| MBMS Flow Identifier| No|
|87.| MBMS IP Multicast Distribution| No|
|88.| MBMS Distribution Acknowledgement| No|
|89.| Reliable INTER RAT HANDOVER INFO| No|
|90.| RFSP Index| Yes|
|91.| PDP Type| No|
|92.| Fully Qualified Domain Name (FQDN)| Yes|
|93.| Evolved Allocation/Retention Priority I| Yes|
|94.| Evolved Allocation/Retention Priority II| Yes|
|95.| Extended Common Flags| Yes|
|96.| User CSG Information (UCI)| Yes|
|97.| CSG Information Reporting Action| Yes|
|98.| CSG ID| No|
|99.| CSG Membership Indication (CMI)| Yes|
|100.| Aggregate Maximum Bit Rate (AMBR)| Yes|
|101.| UE Network Capability| Yes|
|102.| UE-AMBR| Yes|
|103.| APN-AMBR with NSAPI| Yes|
|104.| GGSN Back-Off Time| Yes|
|105.| Signalling Priority Indication| Yes|
|106.| Signalling Priority Indication with NSAPI| Yes|
|107.| Higher bitrates than 16 Mbps flag| Yes|
|108.| Additional MM context for SRVCC| Yes|
|109.| Additional flags for SRVCC| Yes|
|110.| STN-SR| No|
|111.| C-MSISDN| Yes|
|112.| Extended RANAP Cause| Yes|
|113.| eNodeB ID| Yes|
|114.| Selection Mode with NSAPI| Yes|
|115.| ULI Timestamp| Yes|
|116.| Local Home Network ID (LHN-ID) with NSAPI| Yes|
|117.| CN Operator Selection Entity| Yes|
|118.| UE Usage Type| Yes|
|119.| Extended Common Flags II| Yes|
|120.| Node Identifier| Yes|
|121.| CIot Optimiztions Support Indication| No|
|122.| SCEF PDN Connection| No|
|123.| IOV updates counter| Yes|
|124.| Mapped UE Usage Type| Yes|
|125.| UP Function Selection Indication Flags| Yes|

**Table 1.2 Information elements**

## Prerequisite

1. Linus OS
2. make 
3. CUnit
4. libgtpv1c

## How to build library

1. get libgtpv1c from repo.

2. Move inside libgtpv1c folder
```
$ cd libgtpv1c
```

3. Build libgtpv1c library
```
$ make
```

4. Move inside test folder
```
$ cd test
```

5. Export libgtpv1c library path for unit test run
```
$ export LD_LIBRARY_PATH=./../lib
```

6. Build UT binary
```
$ make
```

7. Run unit test cases
```
$ ./lib/gtpv1c_test
```
