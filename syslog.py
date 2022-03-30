import pandas as pd
from datetime import datetime
import re
df = pd.read_csv('practica_syslog_FW_v2.csv')

#Severity Recurso * 8 + Severidad    (uso local) 16*8+6 (mensajes informativos)
array=[]
for i in range(0,48):
    array.append("<134>")
df.insert(0, "Severity", array)

#Formato de la fecha
time = df['Time']
array=[]
for line in time:
    x=datetime.strptime(line, "%m/%d/%Y %I:%M:%S %p")
    res=x.strftime("%a %d %H:%M:%S")
    array.append(res)
df['Time'] = array

#Nombe del equipo (hostname o direccion IP)
src = df['Traffic_Source']
array=[]
for line in src:
    if line.find('(') != -1:
        linea = line[:line.find('(')-1]
        array.append(linea)
    else:
        array.append(line)
df.insert(2, 'Device_Name', array)

#Tag (En nuestro caso es Firewall)
tag = df['Device']
array=[]
for line in tag:
    array.append(line+":")
df['Device'] = array

#Content (contenido del mensaje)
# TYPE
type = df['Type']
array=[]
for line in type:
    array.append("TYPE="+line)
df['Type'] = array
# ACTION
action = df['Action']
array=[]
for line in action:
    array.append("ACTION="+line)
df['Action'] = array
# SRV_ID
service = df['Service']
array=[]
for line in service:
    linea = line[:line.find('(')-1]
    array.append("SRV_ID="+linea)
df['Service'] = array
# IP_SRC
src = df['Traffic_Source']
array=[]
for line in src:
    ip_list = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )
    array.append("IP_SRC="+ip_list[0])
df['Traffic_Source'] = array
# IP_DEST
dest = df['Traffic_Destination']
array=[]
for line in dest:
    ip_list = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )
    array.append("IP_DEST="+ip_list[0])
df['Traffic_Destination'] = array
# PORT_SRC
psrc = df['Source Port']
array=[]
for line in psrc:
    if pd.isna(line):
        array.append("PORT_SRC=''")
    else:
       array.append("PORT_SRC="+str(int(line)))
df['Source Port'] = array
# PORT_DST
pdest = df['Destination Port']
array=[]
for line in pdest:
    if pd.isna(line):
        array.append("PORT_DST=''")
    else:
       array.append("PORT_DST="+str(int(line)))
df['Destination Port'] = array
# SRC_ZONE
srcZone = df['Source Zone']
array=[]
for line in srcZone:
    if pd.isna(line):
        array.append("SRC_ZONE=''")
    else:
        array.append("SRC_ZONE="+line)
df['Source Zone'] = array
# DST_ZONE
destZone = df['Destination Zone']
array=[]
for line in destZone:
    if pd.isna(line):
        array.append("DST_ZONE=''")
    else:
        array.append("DST_ZONE="+line)
df['Destination Zone'] = array
# IFACE_NAME
iface = df['Interface Name']
array=[]
for line in iface:
    array.append("IFACE_NAME="+line)
df['Interface Name'] = array
# USER
user = df['User']
array=[]
for line in user:
    if pd.isna(line):
        array.append("USER=''")
    else:
        linea = (line[:line.find('(')-1]).replace(" ", "_")
        array.append("USER="+linea)
df['User'] = array
# ID
id = df['Id']
array=[]
for line in id:
    array.append("ID="+line)
df['Id'] = array
# CON_DIR
condir = df['Connection Direction']
array=[]
for line in condir:
    if pd.isna(line):
        array.append("CON_DIR=''")
    else:
        array.append("CON_DIR="+line)
df['Connection Direction'] = array

#Reordenamos el dataframe
df = df[['Severity','Time','Device_Name','Device','Type','Action','Service',
    'Traffic_Source','Traffic_Destination','Source Port', 'Destination Port',
    'Source Zone','Destination Zone','Interface Name','User','Id','Connection Direction']]
df.to_csv("practica_sys.syslog", header=None, index=None, sep=' ')
