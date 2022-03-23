import pandas as pd
from datetime import datetime
df = pd.read_csv('practica_syslog_FW_v2.csv')

#Severity Recurso * 8 + Severidad 

#Formato de la fecha
time = df["Time"]
array=[]
for line in time:
    x=datetime.strptime(line, "%m/%d/%Y %I:%M:%S %p")
    res=x.strftime("%a %d %H:%M:%S")
    array.append(res)
df["Time"] = array

#Nombe del equipo (hostname o direccion IP)

#Tag (En nuestro caso es Firewall)

#Content (contenido del mensaje)
# TYPE
type = df["Type"]
array=[]
for line in type:
    array.append("TYPE="+line)
df["Type"] = array
# ACTION
action = df["Action"]
array=[]
for line in action:
    array.append("ACTION="+line)
df["Action"] = array
# SRV_ID
service = df["Service"]
array=[]
for line in service:
    linea = line[:line.find('(')-1]
    array.append("SRV_ID="+linea)
df["Service"] = array
print(df["Service"])
# IP_SRC
# IP_DEST
# PORT_SRC
# PORT_DST
# SRC_ZONE
# DST_ZONE
# IFACE_NAME
# USER
# ID
# CON_DIR

