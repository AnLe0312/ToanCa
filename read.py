import struct
from datetime import datetime, timezone
import pandas as pd

input_path = '/Users/wind2808/Documents/Wind/Project/ToanCa/project_may_24/b0000806448.bil'
record_length = 177 * 4
unpacking_format = '177I'

def convert_to_datetime(timestamp):
    datetime_obj = datetime.fromtimestamp(timestamp, timezone.utc)
    formatted_datetime = datetime_obj.strftime("%Y-%m-%d %H:%M:%S")
    return formatted_datetime
    
with open(input_path,'rb') as input_file:
    content = input_file.read()

for i in range(0, len(content), record_length):
    record = content[i:i+record_length]

    if len(record) == record_length:
        parsed_record = struct.unpack(unpacking_format,record)

    for datetime_index in [9,10,24]:
        timestamp = parsed_record[datetime_index]
        formatted_datetime = convert_to_datetime(timestamp)
    
        print("CHR Version:", parsed_record[0])
        print("CHR Type:", parsed_record[1])
        print("CHR Content Length", parsed_record[2])
        print("CHR Module No:", hex(parsed_record[3]))
        print("Network Element Type: MME")
        print("CHR Type Detail:", parsed_record[5])
        print("Type:",parsed_record[6])
        print("Version",parsed_record[7])
        print("Device NO",parsed_record[8])
        print("System Time",formatted_datetime)
        print("Date Time:", formatted_datetime)
        print("Board Subrack No.:", parsed_record[11])
        print("RU ID:", parsed_record[12])
        print("BoardProc No.:", parsed_record[13])
        print("CHR SN:", hex(parsed_record[14]))
        print("Procedure Identification:", parsed_record[15])
        print("Init proc cause:", parsed_record[16])
        print("Procedure Delay Time:", parsed_record[17])
        print("IMSI:", parsed_record[18])
        print("MSISDN:", parsed_record[19])
        print("IMEISV:", parsed_record[20])
        print("eNB PLMN:", parsed_record[21])
        print("eNB ID:", parsed_record[22])
        print("MME UE S1AP ID:", hex(parsed_record[23]))
        print("MME S1AP ID UTC second:", formatted_datetime)
        print("Current TAI PLMN:", parsed_record[25])
        print("Current TAC:", hex(parsed_record[26]))
        print("New GUTI PLMN:",parsed_record[27])
        print("New GUTI MMEGI:", hex(parsed_record[28]))
        print("New GUTI MMEC:", hex(parsed_record[29]))
        print("New GUTI MTMSI:", hex(parsed_record[30]))
        print("Old GUTI PLMN:",parsed_record[31])
        print("Old GUTI MMEGI:", hex(parsed_record[32]))
        print("Old GUTI MMEC:", hex(parsed_record[33]))
        print("Old GUTI MTMSI:", hex(parsed_record[34]))
        print("Old TAI PLMN	:",parsed_record[35])
        print("Old TAC:", hex(parsed_record[36]))
        print("Target ID PLMN:",parsed_record[37])
        print("Target ID:",parsed_record[38])
        print("Target MME UE S1AP ID:", hex(parsed_record[39]))
        print("Target MME S1AP ID UTC second:",parsed_record[40])
        print("Target TAI PLMN:",parsed_record[41])
        print("Target TAC:", hex(parsed_record[42]))
        print("Protocol Cause:",parsed_record[43])
        print("External Cause:",parsed_record[44])
        print("Inner Cause:",parsed_record[45])
        print("Internal Flag:",parsed_record[46])
        print("BitMap1:", hex(parsed_record[47]))
        print("BitMap2:", hex(parsed_record[48]))
        print("BitMap3:", hex(parsed_record[49]))
        print("Serving Gateway Address:",parsed_record[50])
        print("Serving Gateway Host Name:",parsed_record[51])
        print("MS P-TMSI:", hex(parsed_record[52]))
        print("Allocated P-TMSI:", hex(parsed_record[53]))
        print("SAccessType:",parsed_record[54])
        print("MCC:",parsed_record[55])
        print("MNC:",parsed_record[56])
        print("LAC:", hex(parsed_record[57]))
        print("RAC:", hex(parsed_record[58]))
        print("Ncgi:", hex(parsed_record[59]))
        print("Old MCC:",parsed_record[60])
        print("Old MNC:",parsed_record[61])
        print("Old LAC:", hex(parsed_record[62]))
        print("Old RAC:", hex(parsed_record[63]))
        print("Authentication Flag:",parsed_record[64])
        print("IMEI check Flag:",parsed_record[65])
        print("PTMSI Reallocation Flag:",parsed_record[66])
        print("Old SGSN Address:",parsed_record[67])
        print("User Home PLMN:",parsed_record[68])
        print("ENODB UES1AP ID	:",parsed_record[69])
        print("Special Service Indication:",parsed_record[70])
        print("User Index:", hex(parsed_record[71]))
        print("VLR No.:",parsed_record[72])
        print("Internal Physical Location:", hex(parsed_record[73]))
        print("VTimeZone:",parsed_record[74])
        print("ECI:", hex(parsed_record[75]))
        print("MS network capability:", hex(parsed_record[76]))
        print("UE network capability:", hex(parsed_record[77]))
        print("Reference Access type:",parsed_record[78])
        print("Inter CN Node Type:",parsed_record[79])
        print("SGW Change Flag:",parsed_record[80])
        print("EPS attach result:",parsed_record[81])
        print("EPS update result:",parsed_record[82])
        print("Additional update result:",parsed_record[83])
        print("SRVCC Cause:",parsed_record[84])
        print("SGS RePaging Count:",parsed_record[85])
        print("VoIMS Bear Status:",parsed_record[86])
        print("Voice domain preference and UE's usage setting:", hex(parsed_record[87]))
        print("EPS network feature support	:",parsed_record[88])
        print("DNS Domain Type:",parsed_record[89])
        print("RFSP(RAT/Frequency Selection Priority) ID:",parsed_record[90])
        print("TMSI	:", hex(parsed_record[91]))
        print("Paging Priority:",parsed_record[92])
        print("LRC Trigger:",parsed_record[93])
        print("LRC Trigger Event:",parsed_record[94])
        print("Area Location Type:",parsed_record[95])
        print("Preferred CIoT network behaviour	:",parsed_record[96])
        print("Negotiated CIoT network behaviour:",parsed_record[97])
        print("Data service type:",parsed_record[98])
        print("SRVCC Preparation Period:",parsed_record[99])
        print("S1 Paging Count	:",parsed_record[100])
        print("Handover Cancel Phase:",parsed_record[101])
        print("UE Usage Type:",parsed_record[102])
        print("Procedure Messages:",parsed_record[103])
        print("State Machine Name:",parsed_record[104])
        print("Main State:",parsed_record[105])
        print("Sub State:",parsed_record[106])
        print("Sub Sub State:",parsed_record[107])
        print("Message Type:",parsed_record[108])
        print("eDRX parameter validity ID issued by Mme:",parsed_record[109])
        print("Paging Time Window:",parsed_record[110])
        print("eDRX value:",parsed_record[111])
        print("PSM parameter validity ID issued by Mme:",parsed_record[112])
        print("Active Timer:",parsed_record[113])
        print("UE Radio Capability:",parsed_record[114])
        print("Serving Gateway Address2:",parsed_record[115])
        print("UE status:",parsed_record[116])
        print("Reserved1:", hex(parsed_record[117]))
        print("Reserved2:", hex(parsed_record[118]))
        print("Reserved3:", hex(parsed_record[119]))
        print("Reserved4:", hex(parsed_record[120]))
        print("Reserved5:", hex(parsed_record[121]))
        print("Reserved6:", hex(parsed_record[122]))
        print("Reserved7:", hex(parsed_record[123]))
        print("Reserved8:", hex(parsed_record[124]))
        print("Reserved9:", hex(parsed_record[125]))
        print("Reserved10:", hex(parsed_record[126]))
        print("Reserved11:", hex(parsed_record[127]))
        print("Reserved12:", hex(parsed_record[128]))
        print("PDN Type:",parsed_record[129])
        print("APN NI:",parsed_record[130])
        print("APN OI:",parsed_record[131])
        print("Serving Gateway Address1:",parsed_record[132])
        print("PDN Gateway Address:",parsed_record[133])
        print("PDN Gateway Host Name:",parsed_record[134])
        print("UE Uplink Max Bandwidth:",parsed_record[135])
        print("UE Downlink Max Bandwidth:",parsed_record[136])
        print("APN Uplink Max Bandwidth:",parsed_record[137])
        print("APN Downlink Max Bandwidth:",parsed_record[138])
        print("QCI:",parsed_record[139])
        print("ARP:",parsed_record[140])
        print("GBR Uplink:",parsed_record[141])
        print("GBR Downlink:",parsed_record[142])
        print("MBR Uplink:",parsed_record[143])
        print("MBR Downlink:",parsed_record[144])
        print("Special User Indication:",parsed_record[145])
        print("PDN Type in used:",parsed_record[146])
        print("PDN Address in uesd:",parsed_record[147])
        print("APN NI in used:",parsed_record[148])
        print("APN OI in used:",parsed_record[149])
        print("IMS Flag:",parsed_record[150])
        print("S1-U Serving Gateway Address1:",parsed_record[151])
        print("S1-U Serving Gateway Address2:",parsed_record[152])
        print("S1-U eNodeB Address1:",parsed_record[153])
        print("S1-U eNodeB Address2:",parsed_record[154])
        print("PDN Gateway Address2:",parsed_record[155])
        print("Bearer ID:",parsed_record[156])
        print("QoS Equal Flag( to indicate Qos Equal between QoS in CHR and subscription data):",parsed_record[157])
        print("UE Uplink Max Bandwidth In Sub:",parsed_record[158])
        print("UE Downlink Max Bandwidth In Sub:",parsed_record[159])
        print("APN Uplink Max Bandwidth in Sub:",parsed_record[160])
        print("APN Downlink Max Bandwidth in Sub:",parsed_record[161])
        print("QCI in Sub:",parsed_record[162])
        print("ARP in Sub:",parsed_record[163])
        print("GBR Uplink in Sub:",parsed_record[164])
        print("GBR Downlink in Sub	:",parsed_record[165])
        print("MBR Uplink in Sub:",parsed_record[166])
        print("MBR Downlink in Sub	:",parsed_record[167])
        print("NSA Information:",parsed_record[168])
        print("UE Uplink Max Bandwidth(extended):",parsed_record[169])
        print("UE Downlink Max Bandwidth(extended):",parsed_record[170])
        print("APN Uplink Max Bandwidth(extended)	:",parsed_record[171])
        print("APN Downlink Max Bandwidth(extended):",parsed_record[172])
        print("GBR Uplink(extended):",parsed_record[173])
        print("GBR Downlink(extended):",parsed_record[174])
        print("MBR Uplink(extended):",parsed_record[175])
        print("MBR Downlink(extended):",parsed_record[176])
        print("PDN Address2 in used	:",parsed_record[177])





