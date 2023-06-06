import matplotlib.pyplot as plt
from sklearn.model_selection import GridSearchCV, train_test_split, cross_val_score
from sklearn.metrics import classification_report,confusion_matrix, accuracy_score, roc_auc_score,roc_curve
from sklearn.preprocessing import StandardScaler, LabelEncoder
from xgboost import XGBClassifier
import numpy as np 
import pandas as pd


og=pd.read_csv('csv/dump_ISCX.csv')

og.drop(['Flow ID','Src Port','Dst IP','Protocol','Timestamp'], inplace=True, axis=1)
og.rename(columns = {'Dst Port':' Destination Port', 'Total Bwd packets':'Total Backward Packets','Packet Length Min':' Min Packet Length','Packet Length Max':' Max Packet Length','CWR Flag Count':' CWE Flag Count','Fwd Segment Size Avg':' Avg Fwd Segment Size','Bwd Segment Size Avg':' Avg Bwd Segment Size','Fwd Bytes/Bulk Avg':'Fwd Avg Bytes/Bulk'}, inplace = True)
og.rename(columns={'Fwd Packet/Bulk Avg':' Fwd Avg Packets/Bulk','Fwd Bulk Rate Avg':' Fwd Avg Bulk Rate','Bwd Bytes/Bulk Avg':' Bwd Avg Bytes/Bulk','Bwd Packet/Bulk Avg':' Bwd Avg Bytes/Bulk','Bwd Bulk Rate Avg':'Bwd Avg Bulk Rate','FWD Init Win Bytes':'Init_Win_bytes_forward','Bwd Init Win Bytes':' Init_Win_bytes_backward','Fwd Act Data Pkts':' act_data_pkt_fwd'}, inplace=True)
og.rename(columns={'Fwd Seg Size Min':' min_seg_size_forward'}, inplace=True)


og =  og.drop_duplicates(keep="first")

to_drop=[]

for i in range(len(og)):
    if og[" Destination Port"][i] == 'Dst Port':
        to_drop.append(i)

for i in to_drop:
    og = og.drop(i).reset_index()

og.to_csv('intfile_2.csv')

temp = pd.read_csv('intfile_2.csv')

x_test = temp.drop(["index"],axis=1)
x_test.drop(columns=x_test.columns[0],axis=1,inplace=True)
# print(x_test)

    
x_test.columns =  x_test.columns.str.strip()

x_test = x_test[~x_test.isin([np.nan, np.inf, -np.inf]).any(1)]



l= np.array(['BENIGN', 'DDoS', 'PortScan', 'Bot', 'Infiltration', 'Web Attack',
       'FTP-Patator', 'SSH-Patator', 'DoS slowloris', 'DoS Slowhttptest',
       'DoS Hulk', 'DoS GoldenEye', 'Heartbleed'])
r= [0,1,2,3,4,5,6,7,8,9,10,11,12]


x_test=x_test.drop(["Label"],axis=1)

y_test =og["Label"]

to_drop = []
for i in range(len(x_test)):
    if x_test["Destination Port"][i] == 'Dst Port':
        to_drop.append(i)

for i in to_drop:
    x_test = x_test.drop(i).reset_index()

# for i in range(len(x_test)):
#     if x_test["Flow Duration"][i] == 'Flow Duration':
#         print('FOUNDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD')
#         print(i)

# x_test.to_csv('after2.csv')

#print(x_test)

lis = x_test['Src IP'].to_list()

x_test.drop(['Src IP'], inplace=True, axis=1)

print(x_test)

xgb = XGBClassifier(random_state=42)
xgb.load_model('dis_model.json')
xgbpreds = xgb.predict(x_test)
# comp_list = ['Destination Port','Flow Duration','Total Fwd Packet','Total Backward Packets','Total Length of Fwd Packet','Total Length of Bwd Packet','Fwd Packet Length Max','Fwd Packet Length Min','Fwd Packet Length Mean','Fwd Packet Length Std',]
# for i in range(len(x_test)):
#     if x_test

temp=pd.DataFrame(xgbpreds,columns=['Label_prediction'])
temp=temp.replace(r,l)
print('\n')
print('Classifications:')
print(temp)
malicious_indexes = []
for i in range(len(temp)):
    if temp['Label_prediction'][i] != 'BENIGN':
        malicious_indexes.append(i)

ip=[]
for i in malicious_indexes:
    ip.append(lis[i])
    
print(ip)
file = open('ips.txt','w')
for item in ip:
	file.write(item+"\n")
 
print('\n\n')
print('---------------------------------------------------------------------')
print('Wrote IPs to ips.txt')
print('\n\n')
 
temp.to_csv('label_pred.csv')