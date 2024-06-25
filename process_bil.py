import tkinter as tk
from tkinter import filedialog, ttk
import struct
from datetime import datetime, timezone
import pandas as pd
import threading

# Function to convert timestamp to formatted datetime string
def convert_to_datetime(timestamp):
    datetime_obj = datetime.fromtimestamp(timestamp, timezone.utc)
    datetime_obj = datetime_obj.astimezone()
    formatted_datetime = datetime_obj.strftime("%Y-%m-%d %H:%M:%S")
    return formatted_datetime

# Function to read binary file content
def read_bil_file(file_path):
    with open(file_path, 'rb') as input_file:
        data = input_file.read()
    return data

# Function to process data
def process_data(data):
    record_length = 177 * 4
    unpacking_format = '177I'
    records = []
    for i in range(0, len(data), record_length):
        record = data[i:i+record_length]

        if len(record) == record_length:
            parsed_record = struct.unpack(unpacking_format, record)

            # Extract relevant datetime fields and convert them
            formatted_datetimes = {}
            for datetime_index in [9, 10, 23]:
                timestamp = parsed_record[datetime_index]
                formatted_datetimes[datetime_index] = convert_to_datetime(timestamp)

            # Collect the data into a list (or dictionary)
            record_data = {
                "CHR Version": parsed_record[0],
                "CHR Type": parsed_record[1],
                "CHR Content Length": parsed_record[2],
                "CHR Module No": hex(parsed_record[3]),
                "Network Element Type": parsed_record[4],
                "CHR Type Detail": parsed_record[5],
                "Type": parsed_record[6],
                "Version": parsed_record[7],
                "Device NO": parsed_record[8],
                "System Time": formatted_datetimes[9],
                "Date Time": formatted_datetimes[10],
                "Board Subrack No": parsed_record[10],
                "RU ID": parsed_record[11],
                "BoardProc No.": parsed_record[12],
                "CHR SN": hex(parsed_record[13]),
                "Procedure Identif": parsed_record[14],
                "Init proc cause": parsed_record[15],
                "Procedure Delay T": parsed_record[16],
                "IMSI": parsed_record[17],
                "MSISDN": parsed_record[18],
                "IMEISV": parsed_record[19],
                "eNB PLMN": parsed_record[20],
                "eNB ID": parsed_record[21],
                "MME UE S1AP ID": hex(parsed_record[22]),
                "MME S1AP ID UTC s": formatted_datetimes[23],
                "Current TAI PLMN": parsed_record[24],
                "Current TAC": hex(parsed_record[25]),
                "New GUTI PLMN":parsed_record[26],
                "New GUTI MMEGI": hex(parsed_record[27]),
                "New GUTI MMEC": hex(parsed_record[28]),
                "New GUTI MTMSI": hex(parsed_record[29]),
                "Old GUTI PLMN":parsed_record[30],
                "Old GUTI MMEGI": hex(parsed_record[31]),
                "Old GUTI MMEC": hex(parsed_record[32]),
                "Old GUTI MTMSI": hex(parsed_record[33]),
                "Old TAI PLMN ":parsed_record[34],
                "Old TAC": hex(parsed_record[35]),
                "Target ID PLMN":parsed_record[36],
                "Target ID":parsed_record[37],
                "Target MME UE S1A": hex(parsed_record[38]),
                "Target MME S1AP I":parsed_record[39],
                "Target TAI PLMN":parsed_record[40],
                "Target TAC": hex(parsed_record[41]),
                "Protocol Cause":parsed_record[42],
                "External Cause":parsed_record[43],
                "Inner Cause":parsed_record[44],
                "Internal Flag":parsed_record[45],
                "BitMap1": hex(parsed_record[46]),
                "BitMap2": hex(parsed_record[47]),
                "BitMap3": hex(parsed_record[48]),
                "Serving Gateway A":parsed_record[49],
                "Serving Gateway H":parsed_record[50],
                "MS P-TMSI": hex(parsed_record[51]),
                "Allocated P-TMSI": hex(parsed_record[52]),
                "SAccessType":parsed_record[53],
                "MCC":parsed_record[54],
                "MNC":parsed_record[55],
                "LAC": hex(parsed_record[56]),
                "RAC": hex(parsed_record[57]),
                "Ncgi": hex(parsed_record[58]),
                "Old MCC":parsed_record[59],
                "Old MNC":parsed_record[60],
                "Old LAC": hex(parsed_record[61]),
                "Old RAC": hex(parsed_record[62]),
                "Authentication Fl":parsed_record[63],
                "IMEI check Flag":parsed_record[64],
                "PTMSI Reallocatio":parsed_record[65],
                "Old SGSN Address":parsed_record[66],
                "User Home PLMN":parsed_record[67],
                "ENODB UES1AP ID":parsed_record[68],
                "Special Service I":parsed_record[69],
                "User Index": hex(parsed_record[70]),
                "VLR No.":parsed_record[71],
                "Internal Physical": hex(parsed_record[72]),
                "VTimeZone":parsed_record[73],
                "ECI": hex(parsed_record[74]),
                "MS network capabi": hex(parsed_record[75]),
                "UE network capabi": hex(parsed_record[76]),
                "Reference Access ":parsed_record[77],
                "Inter CN Node Typ":parsed_record[78],
                "SGW Change Flag":parsed_record[79],
                "EPS attach result":parsed_record[80],
                "EPS update result":parsed_record[81],
                "Additional update":parsed_record[82],
                "SRVCC Cause":parsed_record[83],
                "SGS RePaging Coun":parsed_record[84],
                "VoIMS Bear Status":parsed_record[85],
                "Voice domain pref": hex(parsed_record[86]),
                "EPS network featu":parsed_record[87],
                "DNS Domain Type":parsed_record[88],
                "RFSP(RAT/Frequency Selection Priority) ID":parsed_record[89],
                "TMSI ": hex(parsed_record[90]),
                "Paging Priority":parsed_record[91],
                "LRC Trigger":parsed_record[92],
                "LRC Trigger Event":parsed_record[93],
                "Area Location Typ":parsed_record[94],
                "Preferred CIoT ne":parsed_record[95],
                "Negotiated CIoT n":parsed_record[96],
                "Data service type":parsed_record[97],
                "SRVCC Preparation":parsed_record[98],
                "S1 Paging Count":parsed_record[99],
                "Handover Cancel P":parsed_record[100],
                "UE Usage Type":parsed_record[101],
                "Procedure Message":parsed_record[102],
                "State Machine Nam":parsed_record[103],
                "Main State":parsed_record[104],
                "Sub State":parsed_record[105],
                "Sub Sub State":parsed_record[106],
                "Message Type":parsed_record[107],
                "eDRX parameter va":parsed_record[108],
                "Paging Time Windo":parsed_record[109],
                "eDRX value":parsed_record[110],
                "PSM parameter val":parsed_record[111],
                "Active Timer":parsed_record[112],
                "UE Radio Capabili":parsed_record[113],
                "Serving Gateway A":parsed_record[114],
                "UE status":parsed_record[115],
                "Reserved1": hex(parsed_record[116]),
                "Reserved2": hex(parsed_record[117]),
                "Reserved3": hex(parsed_record[118]),
                "Reserved4": hex(parsed_record[119]),
                "Reserved5": hex(parsed_record[120]),
                "Reserved6": hex(parsed_record[121]),
                "Reserved7": hex(parsed_record[122]),
                "Reserved8": hex(parsed_record[123]),
                "Reserved9": hex(parsed_record[124]),
                "Reserved10": hex(parsed_record[125]),
                "Reserved11": hex(parsed_record[126]),
                "Reserved12": hex(parsed_record[127]),
                "PDN Type":parsed_record[128],
                "APN NI":parsed_record[129],
                "APN OI":parsed_record[130],
                "Serving Gateway A":parsed_record[131],
                "PDN Gateway Addre":parsed_record[132],
                "PDN Gateway Host ":parsed_record[133],
                "UE Uplink Max Ban":parsed_record[134],
                "UE Downlink Max B":parsed_record[135],
                "APN Uplink Max Ba":parsed_record[136],
                "APN Downlink Max ":parsed_record[137],
                "QCI":parsed_record[138],
                "ARP":parsed_record[139],
                "GBR Uplink":parsed_record[140],
                "GBR Downlink":parsed_record[141],
                "MBR Uplink":parsed_record[142],
                "MBR Downlink":parsed_record[143],
                "Special User Indi":parsed_record[144],
                "PDN Type in used":parsed_record[145],
                "PDN Address in ue":parsed_record[146],
                "APN NI in used":parsed_record[147],
                "APN OI in used":parsed_record[148],
                "IMS Flag":parsed_record[149],
                "S1-U Serving Gate":parsed_record[150],
                "S1-U Serving Gate":parsed_record[151],
                "S1-U eNodeB Addre":parsed_record[152],
                "S1-U eNodeB Addre":parsed_record[153],
                "PDN Gateway Addre":parsed_record[154],
                "Bearer ID":parsed_record[155],
                "QoS Equal Flag( to indicate Qos Equal between QoS in CHR and subscription data)":parsed_record[156],
                "UE Uplink Max Ban":parsed_record[157],
                "UE Downlink Max B":parsed_record[158],
                "APN Uplink Max Ba":parsed_record[159],
                "APN Downlink Max ":parsed_record[160],
                "QCI in Sub":parsed_record[161],
                "ARP in Sub":parsed_record[162],
                "GBR Uplink in Sub":parsed_record[163],
                "GBR Downlink in S":parsed_record[164],
                "MBR Uplink in Sub":parsed_record[165],
                "MBR Downlink in S":parsed_record[166],
                "NSA Information":parsed_record[167],
                "UE Uplink Max Bandwidth(extended)": parsed_record[168],
                "UE Downlink Max Bandwidth(extended)":parsed_record[169],
                "APN Uplink Max Bandwidth(extended)":parsed_record[170],
                "APN Downlink Max Bandwidth(extended)":parsed_record[171],
                "GBR Uplink(extended)":parsed_record[172],
                "GBR Downlink(extended)":parsed_record[173],
                "MBR Uplink(extended)":parsed_record[174],
                "MBR Downlink(extended)":parsed_record[175],
                "PDN Address2 in u":parsed_record[176]
            }
            records.append(record_data)

    df = pd.DataFrame(records)
    return df

# Function to save DataFrame to CSV file
def save_to_csv(dataframe):
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if file_path:
        dataframe.to_csv(file_path, index=False)
        print(f"CSV file saved: {file_path}")

# Function to handle file selection button click
def select_file_and_process():
    file_path = filedialog.askopenfilename(filetypes=[("BIL files", "*.bil")])
    if file_path:
        threading.Thread(target=process_and_display_progress, args=(file_path,)).start()

# Function to process file and display progress
def process_and_display_progress(file_path):
    data = read_bil_file(file_path)
    processed_data = process_data(data)
    root.after(100, lambda: update_progress(processed_data))

# Function to update progress bar and show "Save File .csv" button
def update_progress(processed_data):
    progress_bar.stop()
    progress_bar['value'] = 100
    save_button = tk.Button(root, text="Save File .csv", command=lambda: save_to_csv(processed_data))
    save_button.pack(pady=20)

# Main GUI window
root = tk.Tk()
root.title("Convert CHR files")

# Header label
header_label = tk.Label(root, text="Convert .bil files to .csv files", font=("Helvetica", 16))
header_label.pack(pady=20)

# Progress bar
progress_bar = ttk.Progressbar(root, mode='indeterminate')
progress_bar.pack(fill=tk.X, padx=20, pady=10)
progress_bar.start()

# File selection button
select_button = tk.Button(root, text="Select File .bil", command=select_file_and_process)
select_button.pack(pady=20)

root.mainloop()