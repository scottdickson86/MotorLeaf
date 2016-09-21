#!/usr/bin/python
import glob
import hashlib
import os
import random
import string
import subprocess
import sys
import time
import json, ast
import io
#from datetime import datetime,time
#import time
import datetime
from Crypto.Cipher import AES
from azure.servicebus import ServiceBusService
import serial
#Motorleaf modules
import mailer as mailer
#import lib.sql as sql
import lib.wifi as wifi
import lib.accessibility as acc
import json
import os
import pdb
import sqlite3 as lite


import thread
import motorleafEmail
from collections import deque


oldSetPoint_pH1 = " "
oldSetPoint_Temp = " "
oldSetPoint_RH = " "
oldSetPoint_TDS1 = " "
oldSetPoint_CO2 = " "
oldSetPoint_Light = " "
oldSetPoint_H2OTemp = " "
oldSetPoint_H2OLevel = " "




def getCalSettingIdDigit(calSettingId,value):
    global calSettingIdDigit
    calSettingIdDigit = 0

# do not delete the second part of the IF statement (need to be here for the testing without Arduino)

    if (calSettingId == "calPH" and value == "clear") or (calSettingId == "PHCal" and value == "clear"):
        calSettingIdDigit = "12"
    elif (calSettingId == "calPH" and value == "mid") or (calSettingId == "PHCal" and value == "mid"):
        calSettingIdDigit = "4"
    elif (calSettingId == "calPH" and value == "low") or (calSettingId == "PHCal" and value == "low"):
        calSettingIdDigit = "5"
    elif (calSettingId == "calPH" and value == "high") or (calSettingId == "PHCal" and value == "high"):
        calSettingIdDigit = "6"
    elif (calSettingId == "calTDSProbe") or (calSettingId == "TDSProbeCal"):
        calSettingIdDigit = "13"
    elif (calSettingId == "calTDS" and value == "clear") or (calSettingId == "TDSCal" and value == "clear"):
        calSettingIdDigit = "14"
    elif (calSettingId == "calTDS" and value == "dry") or (calSettingId == "TDSCal" and value == "dry"):
        calSettingIdDigit = "15"
    elif (calSettingId == "calTDS" and value == "one") or (calSettingId == "TDSCal" and value == "one"):
        calSettingIdDigit = "7"
    elif (calSettingId == "calTDS" and value == "low") or (calSettingId == "TDSCal" and value == "low"):
        calSettingIdDigit = "8" 
    elif (calSettingId == "calTDS" and value == "high") or (calSettingId == "TDSCal" and value == "high"):
        calSettingIdDigit = "8"
    elif (calSettingId == "calH2OLevel" and value == "low") or  (calSettingId == "H2OLevelCal" and value == "low"):
        calSettingIdDigit = "9"
    elif( calSettingId == "calH2OLevel" and value == "high") or (calSettingId == "H2OLevelCal" and value == "high"):
        calSettingIdDigit = "9"
    elif calSettingId == "calH2OTemp" or calSettingId == "H2OTempCal":
        calSettingIdDigit = "10"
    elif calSettingId == "calDrip" or calSettingId == "DripCal":
        calSettingIdDigit = "16"
    return calSettingIdDigit

def multiCal(calSettingId,value,pointValue):
    global calSettingIdDigit
    res = 0
    point = 0
    calSettingIdDigit = getCalSettingIdDigit(calSettingId,value)
    currDate = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    if calSettingId == "calPH":
        if value == "mid":
            point = "7"
        elif value == "low":
            point = "4"
        elif value == "high":
            point = "10"
        elif value == "clear":
            point = " "
        if fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = 4") != None:
            res = 4
        elif fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = 5") != None:
            res = 5
        elif fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = 6") != None:
            res = 6
        elif fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = 12") != None:
            res = 12
        if res == 0:
            query = "INSERT INTO 'CalibrationQueue' (CalibrationSettingId,Point,StatusId,StartDate) values(" + calSettingIdDigit + ",'" + point + "',1,'" + currDate + "')"
            update_sql(query)
        else:
            query = "UPDATE  CalibrationQueue SET CalibrationSettingId = '" + calSettingIdDigit + "', StatusId = '1', Point = ' " + str(point) + "', StartDate = '"+currDate +"', EndDate = '' where CalibrationSettingId = '" + str(res) + "'"
            update_sql(query)

    elif calSettingId == "calTDSProbe":
        insertUpdateTDS(calSettingIdDigit,currDate,value)
    elif calSettingId == "calTDS":
        if value == "dry":
            point = " "
        elif value == "one":
            point = pointValue
        elif value == "low":
            point = pointValue
        elif value == "high":
            point = pointValue
        elif value == "clear":
            point = " "
        insertUpdateTDS(calSettingIdDigit,currDate,point)
    elif calSettingId == "calH2OLevel":
        if value == "low":
            point = "0"
        elif value == "high":
            point = "100"
        if fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = 9") == None:
            query = "INSERT INTO 'CalibrationQueue' (CalibrationSettingId,Point,StatusId,StartDate) values(" + calSettingIdDigit + "," + point + ",1,'" + currDate + "')"
            update_sql(query)
        else:
            query = "UPDATE  CalibrationQueue SET Point = '" + point + "', CalibrationSettingId = '" + calSettingIdDigit + "', StatusId = '1', StartDate = '"+currDate +"', EndDate = '' where CalibrationSettingId = '9'"
            update_sql(query)
    elif calSettingId == "calH2OTemp":
        if fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = 10") == None:
            query = "INSERT INTO 'CalibrationQueue' (CalibrationSettingId,Point,StatusId,StartDate) values(" + calSettingIdDigit + "," + value + ",1,'" + currDate + "')"
            update_sql(query)
        else:
            query = "UPDATE  CalibrationQueue SET Point = '" + value + "', CalibrationSettingId = '" + calSettingIdDigit + "', StatusId = '1', StartDate = '"+currDate +"', EndDate = '' where CalibrationSettingId = '10'"
            update_sql(query)
    elif calSettingId == "calDrip":
        if fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = 16") == None:
            query = "INSERT INTO 'CalibrationQueue' (CalibrationSettingId,Point,StatusId,StartDate) values(" + calSettingIdDigit + "," + pointValue + ",1,'" + currDate + "')"
            update_sql(query)
        else:
            query = "UPDATE  CalibrationQueue SET Point = '" + pointValue + "', CalibrationSettingId = '" + calSettingIdDigit + "', StatusId = '1', StartDate = '"+currDate +"', EndDate = '' where CalibrationSettingId = '16'"
            update_sql(query)

def insertUpdateTDS(calSettingIdDigit,currDate,pointValue):
    res = 0
    if fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = 7") != None:
        res = 7
    elif fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = 8") != None:
        res = 8
    elif fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = 13") != None:
        res = 13
    elif fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = 14") != None:
        res = 14
    elif fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = 15") != None:
        res = 15
    if res == 0:
        query = "INSERT INTO 'CalibrationQueue' (CalibrationSettingId,Point,StatusId,StartDate) values('" + calSettingIdDigit + "', '" + pointValue + "','1','" + currDate + "')"
        update_sql(query)
    else:
        query = "UPDATE  CalibrationQueue SET Point = '" + pointValue + "', CalibrationSettingId = '" + calSettingIdDigit + "', StatusId = '1', StartDate = '"+currDate +"', EndDate = '' where CalibrationSettingId = '" + str(res) + "'"
        update_sql(query)


def insertUpdateTDSArduino(calSettingIdDigit,point,value,endDate):
    res = 0
    if fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = 7") != None:
        res = 7
    elif fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = 8") != None:
        res = 8
    elif fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = 13") != None:
        res = 13
    elif fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = 14") != None:
        res = 14
    elif fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = 15") != None:
        res = 15
    query = "UPDATE CalibrationQueue SET StatusId = '4', EndDate = '" + endDate + "' where CalibrationSettingId = " + str(calSettingIdDigit) + ""
    update_sql(query)
    if res == 0:
        query = "INSERT INTO 'Calibration' (CalibrationSettingId,Point,Value) values(" + str(calSettingIdDigit) + ", '" + point + "', '" + value + "')"
        update_sql(query)
    else:
        query = "UPDATE  Calibration SET Point = '" + point + "', CalibrationSettingId = '" + str(calSettingIdDigit) + "', Value = '" + value + "' where CalibrationSettingId = '" + str(res) + "'"
        update_sql(query)


def getMultiPointsCalData(calSettingId,point,value):
    addMessageLog(calSettingId + " - " + point +  " - " + value)
    #printMessageLog()
    res = 0
    calSettingIdDigit = getCalSettingIdDigit(calSettingId,point)
    global endDate
    endDate = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    if value == "OK":
        value = ""
    if calSettingId == "PHCal":
        if point == "mid":
            po = "7"
        elif point == "low":
            po = "4"
        elif point == "high":
            po = "10"
        elif point == "clear":
            po = ""
        if fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = 3") != None:
            res = 3
        elif fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = 4") != None:
            res = 4
        elif fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = 5") != None:
            res = 5
        elif fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = 6") != None:
            res = 6
        elif fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = 12") != None:
            res = 12
        query = "UPDATE CalibrationQueue SET StatusId = '4', EndDate = '" + endDate + "' where CalibrationSettingId = " + str(calSettingIdDigit) + ""
        update_sql(query)
        if res == 0 :
            query = "INSERT INTO 'Calibration' (CalibrationSettingId,Point,Value) values(" + str(calSettingIdDigit)+", '" + po + "','" + str(value) + "')"
            update_sql(query)
        else:
            query = "UPDATE Calibration SET CalibrationSettingId = '" + str(calSettingIdDigit) +"', Point = '" + po + "', Value = '" + value + "' where CalibrationSettingId = '"+ str(res) +"'"
            update_sql(query)
    elif calSettingId == "TDSProbeCal":
        insertUpdateTDSArduino(calSettingIdDigit,point,value,endDate)
    elif calSettingId == "TDSCal":
        insertUpdateTDSArduino(calSettingIdDigit,'','',endDate)
    elif calSettingId == "H2OLevelCal":
        query = "UPDATE CalibrationQueue SET StatusId = '4', EndDate = '" + endDate + "' where CalibrationSettingId = '9'"
        update_sql(query)
        if fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = '9'") == None:
            query = "INSERT INTO 'Calibration' (CalibrationSettingId, Value, Point) values('9', '','')"
            update_sql(query)
        else: 
            query = "UPDATE Calibration SET CalibrationSettingId = '9', Point = ' ', Value = ' ' where CalibrationSettingId = '9'"
            update_sql(query)
    elif calSettingId == "H2OTempCal":
        query = "UPDATE CalibrationQueue SET StatusId = '4', EndDate = '" + endDate + "' where CalibrationSettingId = '10'"
        update_sql(query)
        if fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = '10'") == None:
            query = "INSERT INTO 'Calibration' (CalibrationSettingId, Value, Point) values('10', '','')"
            update_sql(query)
        else: 
            query = "UPDATE Calibration SET CalibrationSettingId = '10', Point = ' ', Value = ' ' where CalibrationSettingId = '10'"
            update_sql(query)
    elif calSettingId == "DripCal":
        query = "UPDATE CalibrationQueue SET StatusId = '4', EndDate = '" + endDate + "' where CalibrationSettingId = '16'"
        update_sql(query)
        if fetch_sql("SELECT * FROM Calibration WHERE CalibrationSettingId = '16'") == None:
            query = "INSERT INTO 'Calibration' (CalibrationSettingId, Value, Point) values('16', '','')"
            update_sql(query)
        else: 
            query = "UPDATE Calibration SET CalibrationSettingId = '16', Point = ' ', Value = ' ' where CalibrationSettingId = '16'"
            update_sql(query)

def cal(calSettingId,value):
    calSettingIdDigit = None
    if calSettingId == "calTemp":
        calSettingIdDigit = "1"
    elif calSettingId == "calRH":
        calSettingIdDigit = "2"
    elif calSettingId == "calLight":
        calSettingIdDigit = "3"
    currDate = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    power_query = fetch_sql("SELECT * FROM CalibrationQueue WHERE CalibrationSettingId = " + calSettingIdDigit + "")

    if power_query == None :
        query = "INSERT INTO 'CalibrationQueue' (CalibrationSettingId,StatusId,StartDate) values(" + calSettingIdDigit + ",1,'" + currDate + "')"
        update_sql(query)
    else:
        query = "UPDATE  CalibrationQueue SET StatusId = '1', StartDate = '"+currDate +"', EndDate = '' where CalibrationSettingId = '" + calSettingIdDigit + "'"
        update_sql(query)

def getCalibratedData(calSettingId, value):
    global endDate
    endDate = str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    query = "UPDATE CalibrationQueue SET StatusId = '4', EndDate = '" + endDate + "' where CalibrationSettingId = " + str(calSettingId) + ""
    update_sql(query)

    power_query = fetch_sql("SELECT * FROM Calibration  WHERE CalibrationSettingId = " + str(calSettingId) + "")

    #if power_query == None :
    #query = "INSERT INTO 'Calibration' (CalibrationSettingId,Value) values(" + str(calSettingId) + ",'" + str(value) + "')"
    #update_sql(query)
    #else:
    #query = "UPDATE  Calibration SET  Value  = '" + str(value) +"'  where CalibrationSettingId = '" + str(calSettingId) + "'"
    #update_sql(query)

def addMessageLog(logmessage):
    global now
    now = datetime.datetime.now()
    i = 9
    while i > 0:
        messagelog[i] = messagelog[i-1]
        i = i - 1
    messagelog[0] = now.strftime("%Y/%m/%d %H:%M:%S") + ": " + logmessage
    if os.path.exists(app_path+"log.txt"):
            f_Log=open(app_path + 'log.txt','a')
            f_Log.write("\n" + now.strftime("%Y/%m/%d %H:%M:%S") + ": " + logmessage)
            f_Log.close()
    
    
def printMessageLog():
    print ('\033[1m') #Bold #Bold
    print ("\033[39;0H[  Lastest Messages  ]-------------------------------------------------------------------------------------")
    print ('\033[0m') #Un-Bold #Un-Bold
    i = 0
    print ("\033[39;0H")
    print ("\033[K")    
    while i < 10:
        if i == 9:
            print("\033[" + str(i+40) + ";0H")
            print ("\033[K")
            print("\033[" + str(i+40) + ";0H" + str(i+1) + ")" + str(messagelog[i]))    
        else:
            print("\033[" + str(i+40) + ";0H")
            print ("\033[K")
            print("\033[" + str(i+40) + ";0H" + str(i+1) + ") " + str(messagelog[i]))
        
        i=i+1
     
def drawInterface():
  print("\033[1m") #Bold
  print("\033[0;0H")
  os.system("clear")
  #os.system("cat splashscreen")
  print("\033[16;78HMotorLeaf v1.75")
  print("\033[7;75H[Interface IP Addresses]")
  print("\033[39;0H[  Latest Messages  ]-------------------------------------------------------------------------------------")
  print("\033[0m") #Un-Bold
  drawInterfaceIPs()


def serial_ports():
    if sys.platform.startswith('win'):
        ports = ['COM%s' % (i + 1) for i in range(256)]
    elif sys.platform.startswith('linux'):
        ports = glob.glob('/dev/tty[A-Za-z]*')
    else:
        raise EnvironmentError('Unsupported platform')
    result = []
    for port in ports:
        try:
            s = serial.Serial(port)
            s.close()
            result.append(port)
        except (OSError, serial.SerialException):
            pass
    return result[0]

#Thanks to: http://www.floyd.ch/?p=293 for the encrypt and decrypt functions.
def AESencrypt(password, plaintext, base64=False):
  try:
    SALT_LENGTH = 32
    DERIVATION_ROUNDS = 1337
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    MODE = AES.MODE_CBC
     
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(BLOCK_SIZE)
     
    paddingLength = 16 - (len(plaintext) % 16)
    paddedPlaintext = plaintext + chr(paddingLength) * paddingLength
    derivedKey = password
    for i in range(0,DERIVATION_ROUNDS):
      derivedKey = hashlib.sha256(derivedKey + salt).digest()
    derivedKey = derivedKey[:KEY_SIZE]
    cipherSpec = AES.new(derivedKey, MODE, iv)
    ciphertext = cipherSpec.encrypt(paddedPlaintext)
    ciphertext = ciphertext + iv + salt
    if base64:
      return base64.b64encode(ciphertext)
    else:
      return ciphertext.encode("hex")
  except Exception as e:
    print("\nError (AESencrypt): ") + str(e)
    addMessageLog("Error (AESencrypt): " + str(e))
    ##printMessageLog()
    return 0
def AESdecrypt(password, ciphertext, base64=False):
  try:
      SALT_LENGTH = 32
      DERIVATION_ROUNDS = 1337
      BLOCK_SIZE = 16
      KEY_SIZE = 32
      MODE = AES.MODE_CBC
       
      if base64:
          decodedCiphertext = base64.b64decode(ciphertext)
      else:
          decodedCiphertext = ciphertext.decode("hex")
      startIv = len(decodedCiphertext) - BLOCK_SIZE - SALT_LENGTH
      startSalt = len(decodedCiphertext) - SALT_LENGTH
      data, iv, salt = decodedCiphertext[:startIv], decodedCiphertext[startIv:startSalt], decodedCiphertext[startSalt:]
      derivedKey = password
      for i in range(0, DERIVATION_ROUNDS):
          derivedKey = hashlib.sha256(derivedKey + salt).digest()
      derivedKey = derivedKey[:KEY_SIZE]
      cipherSpec = AES.new(derivedKey, MODE, iv)
      plaintextWithPadding = cipherSpec.decrypt(data)
      paddingLength = ord(plaintextWithPadding[-1])
      plaintext = plaintextWithPadding[:-paddingLength]
      return plaintext
    #a = AESencrypt("password", "ABC")
    #print AESdecrypt("password", a)
  except Exception as e:
    print("\nError (AESencrypt): ",str(e))
    addMessageLog("Error (AESencrypt): " + str(e))
    ##printMessageLog()
    return 0
    
    

    
def getInterfaceIPs():
  try:
    proc = subprocess.Popen(["ifconfig | grep 'inet addr:'"], stdout=subprocess.PIPE, shell=True)
    (ifconfig, err) = proc.communicate()
    proc.wait()
    lines = ifconfig.split("\n")
    IP = []
    i = 0
    while i < (len(lines) - 1):
      line_split = lines[i].split(":")
      address_split = line_split[1].split(" ")
      if address_split[0] != "127.0.0.1":
        IP.append(address_split[0])
      i = i + 1
    return IP
  except:
    return ""
    print("\nError: Cannot get Interface IP Addresses.")
    addMessageLog("Error: Cannot get Interface IP Addresses.")
    ##printMessageLog()
    
def drawInterfaceIPs():
    IP_Addresses = getInterfaceIPs()
    i = 0
    while i < len(IP_Addresses):
      print("\033[" + str(i + 8) + ";80H")
      print("\033[" + str(i + 8) + ";80H" + str(i + 1) + ")" + str(IP_Addresses[i]))  
      i = i + 1
  

    

def main_loop():
    def update_sql(query):
        try:
            #db = lite.connect(sql_path + '/sql/motorleaf.sqlite3', timeout=10)
            #cursor =  db.cursor()
            cursor.execute(query)
            #db.commit()
            #db.close()
        except lite.IntegrityError as e:
            print(e)
            db.close()
    
    def update_script(query):
      try:
        #db = lite.connect(sql_path + '/sql/motorleaf.sqlite3', timeout=10)
        #cursor =  db.cursor()
        cursor.executescript(query)
        #db.commit()
        #db.close()
      except lite.IntegrityError as e:
        print(e)
        db.close()
    
    def fetch_sql(query):
        #db = lite.connect(sql_path + '/sql/motorleaf.sqlite3', timeout=10)
        #cursor = db.cursor()
        # Execute the SQL command
        cursor.execute(query)
        # Fetch the data at the cursor
        sql_data = cursor.fetchone()
        #db.close()
        # Assign fetched data to variables
        return sql_data
    
    def fetch_one_sql(query):
        #db = lite.connect(sql_path + '/sql/motorleaf.sqlite3', timeout=10)
        #cursor = db.cursor()
        cursor.execute(query)
        sql_data = [row[0] for row in cursor.fetchall()]
        #db.close()
        return sql_data
    
    
    def checktable_sql(tablename):
        #db = lite.connect(sql_path + '/sql/motorleaf.sqlite3', timeout=10)
        #cursor = db.cursor()
        cursor.execute('''
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_name = '{0}'
            '''.format(tablename.replace('\'', '\'\'')))
        if cursor.fetchone()[0] == 1:
            #db.close()
            return True
        #db.close()
        return False
    
    
    def checkrow_sql(tablename, rowname, row):
        #db = lite.connect(sql_path + '/sql/motorleaf.sqlite3')
        #cursor = db.cursor()
        cursor.execute("SELECT 1 FROM %s WHERE %s = %s", tablename, rowname, row)
        if cursor.fetchone()[0] == 1:
            #db.close()
            return True
        #db.close()
        return False
    
    def checkSerial():
        perform_commit = False
        try:
            global app_path
            global startTime
            global TakeDataPoint_Every
            global timesync
            global email_password
            global smtp_server
            global smtp_port
            global login_address
            global to_address   
            global oldRelays 
            global oldRelay_isAuto
            global oldLight_Schedule
            global oldWatering_Schedule
            global oldSetPoint_pH1
            global oldSetPoint_Temp
            global oldSetPoint_RH
            global oldSetPoint_TDS1
            global oldSetPoint_CO2
            global oldSetPoint_Light
            global oldSetPoint_H2OTemp
            global oldSetPoint_H2OLevel
            global oldPower
            global oldPower_unknown
            global serialnumber
            serialnumber = str(fetch_one_sql("Select Serial FROM Settings"))
            oldRelays = " "
            oldRelay_isAuto = " "
            oldLight_Schedule = " "
            oldWatering_Schedule = " "
            oldPower = " "
            oldPower_unknown = " "
            global LastDataPoint_Time
            global delta
            global first_timesync
            global Datapoint_count
            global sensordata
            global now
            #global time
            now = datetime.datetime.now()
            #Open up the 'Command' file to see if a command has been issued.
            f_Command = open(app_path + 'Command','r+')
            Command = f_Command.readline()
            Command = Command.rstrip('\n')
            f_Command.close()
            #If there is a command, do that command.
            if Command != '':
                print("\033[36;0H                                                                                                           ")
                if 'saveemailsettings' in Command:
                    print("\033[36;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") Received Command: saveemailsettings")
                else:
                    print("\033[36;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") Received Command: '" + Command + "'")
                if 'restart cam' in Command:
                    f = os.system("sudo " + app_path + "restart_mtn >/dev/null 2>&1")
                    addMessageLog("Restarted motion (camera)")
                    ##printMessageLog()
                elif 'stop cam' in Command:
                    f = os.system("sudo " + app_path + "stop_motion >/dev/null 2>&1")
                    addMessageLog("Stopped motion (camera)")
                    ##printMessageLog()
                elif 'wifisetup' in Command:
                    try:
                        wifisetup,ESSID, PASSWORD = Command.split(",")
                        #print("Wifi setup : " + ESSID)
                        result = wifi.setupwifi(ESSID,PASSWORD)
                        addMessageLog("Updated wifi settings")
                        ##printMessageLog()
                        #print(result)
                        #update_sql("UPDATE wifi SET ESSID='" + ESSID + "', PASSWORD='" + PASSWORD +"' WHERE rowID=1" )
                    except:
                        addMessageLog("Error in WifiSetup")
                        ##printMessageLog()
                elif 'calRH' in Command:
                    calRH,value = Command.split(",")
                    try:
                        cal("calRH", value)
                       #addMessageLog("Calibration for RH  started.")
                        ser.write(Command)
                        ser.write("\n")
                    except:
                        addMessageLog("Error calibrating RH")
                        ##printMessageLog()
                elif 'calTemp' in Command:
                    calTemp, value = Command.split(",")
                    try:
                        cal("calTemp",value)
                        #addMessageLog("Calibration for Temperature started ")
                        ser.write(Command)
                        ser.write("\n")
                    except:
                        print("Error calibrating temp")
                        addMessageLog("Error calibrating temp")
                        ##printMessageLog()
                elif 'calLight' in Command:
                    calLight, value = Command.split(",")
                    try:
                        cal("calLight", value)
                        #addMessageLog("Calibration for Light started")
                        ser.write(Command)
                        ser.write("\n")
                    except:
                      addMessageLog("Error calibrating Light")
                elif 'calPH' in Command:
                    pointValue = None
                    calPH, value = Command.split(",")
                    try:
                        multiCal("calPH",value,pointValue)
                        addMessageLog("Calibration for PH started....")
                        ser.write(Command)
                        ser.write("\n")
                    except:
                        addMessageLog("Error Calibrating PH")
                elif 'calTDSProbe' in Command:
                    pointValue = None
                    calTDSProbe,value = Command.split(",")
                    try:
                        multiCal("calTDSProbe",value,pointValue)
                        addMessageLog("Calibration for TDSProbe started....")
                        ser.write(Command)
                        ser.write("\n")
                    except:
                        addMessageLog("Error Calibrating TDSProbe")
                elif 'calTDS' in Command:
                    pointValue = None
                    if 'low'in Command  or 'high' in Command or 'one' in Command:
                        calTDS,value,pointValue = Command.split(",")
                    else:
                        calTDS,value = Command.split(",")
                    try:
                        multiCal("calTDS",value,pointValue)
                        addMessageLog("Calibration for TDS started....")
                        ser.write(Command)
                        ser.write("\n")
                    except:
                        addMessageLog("Error Calibrating TDS")
                elif 'calH2OLevel' in Command:
                    pointValue = None
                    calH2OLevel,value = Command.split(",")
                    try:
                        multiCal("calH2OLevel",value,pointValue)
                        addMessageLog("Calibration for H2OLevel started....")
                        ser.write(Command)
                        ser.write("\n")
                    except:
                        addMessageLog("Error Calibrating H2OLevel")
                elif 'calH2OTemp' in Command:
                    pointValue = None
                    calH2OLevel,value = Command.split(",")
                    try:
                        multiCal("calH2OTemp",value,pointValue)
                        addMessageLog("Calibration for H2OTemp started....")
                        ser.write(Command)
                        ser.write("\n")
                    except:
                        addMessageLog("Error Calibrating H2OTemp")
                elif 'calDrip' in Command:
                    pointValue = None
                    calDrip,value,pointValue = Command.split(",")
                    try:
                        multiCal("calDrip",value,pointValue)
                        addMessageLog("Calibration for Drip started....")
                        ser.write(Command)
                        ser.write("\n")
                    except:
                        addMessageLog("Error Calibrating Drip")
                elif 'update' in Command:
                    try:
                        #print 'Updating!!!!!!!'
                        addMessageLog("!!!Updating Firmware!!!")
                        ##printMessageLog()
                        ser.close()
                        time.sleep(20)
                        addMessageLog("Updating Step 1 of 6 - Making Temporary Directory")
                        ##printMessageLog()
                        f = os.system("sudo mkdir " + app_path + "upload/tmp")
                        time.sleep(5)
                        addMessageLog("Updating Step 2 of 6 - Unzipping Update")
                        ##printMessageLog()
                        f = os.system("sudo unzip -P runUpdate " + app_path + "upload/update*.zip -d " + app_path + "upload/tmp")
                        time.sleep(5)
                        addMessageLog("Updating Step 3 of 6 - Flashing PLC")
                        ##printMessageLog()
                        f = os.system("sudo avrdude -V -F -q -D -p atmega2560 -c wiring -b 115200 -P /dev/ttyUSB0 -U flash:w:" + app_path + "upload/tmp/heart.ino.hex")
                        time.sleep(5)
                        addMessageLog("Updating Step 4 of 6 - Permissions for Update Script")
                        ##printMessageLog()
                        f = os.system("sudo chmod u+x " + app_path + "upload/tmp/update.sh")
                        time.sleep(5)
                        addMessageLog("Updating Step 5 of 6 - Running Update Script")
                        ##printMessageLog()
                        f = os.system("sudo bash " + app_path + "upload/tmp/update.sh")
                        time.sleep(5)
                        addMessageLog("Updating Step 6 of 6 - Removing Update")
                        f = os.system("sudo rm -r " + app_path + "upload/tmp")
                        f = os.system("sudo rm -r " + app_path + "upload/update*.zip")
                        ##printMessageLog()
                        time.sleep(5)
                        ser.open()
                    except:
                        print("Error Updating")
                        addMessageLog("Error Updating")
                        ##printMessageLog()
                        time.sleep(120)
                elif 'Set Raspberry Pi\'s Time to Arduino\'s Time' in Command:
                    try:
                        row = fetch_sql("SELECT * FROM Arduino")
                        for row in data:
                            month = row[1]
                            day = row[2]
                            year = row[3]
                            hour = row[4]
                            minute = row[5]
                            sec = row[6]
                            print("month=%d,day=%d,year=%d,hour=%d,minute=%d,sec=%d" % (month, day, year, hour, minute, sec))
                            f = os.system("sudo date " + month + day + hour + minute + year + "." + sec)
                            print(f)
                            addMessageLog("Set Raspberry Pi Date and Time to Arduino's Date and Time.")
                            ##printMessageLog()
                    except:
                            print("Cannot fetch data from database:  Arduino Table")
                elif 'setraspberrypi' in Command:
                    try:
                        setraspberrypi,month,day,year,hour,minute,sec = Command.split(",")
                        print("%s%s%s%s%s%s%s%s" % ("sudo date ", month, day, hour, minute, year, ".", sec))
                        f = os.system("sudo date " + month + day + hour + minute + year + "." + sec)
                        addMessageLog("Set Raspberry Pi Date and Time.")
                        ##printMessageLog()
                    except:
                        print("Error updating Raspberry Pi Time.")
                elif 'refresh interface' in Command:
                    try:
                        drawInterface()
                        addMessageLog("Refreshed Interface.")
                        ##printMessageLog()
                    except:
                            print("Error refreshing interface.")
                elif 'saveemailsettings' in Command:
                    try:
                        saveemailsettings,login_address,email_password,to_address,smtp_server,smtp_port = Command.split(",")
                        print("%s,<password>,%s,%s,%s" % (login_address,to_address,smtp_server,smtp_port))
                        chars = string.ascii_uppercase + string.digits + string.ascii_lowercase
                        print("Generating new key...\n")
                        new_key = ''.join(random.choice(chars) for x in range(64))
                        print("Key: " + new_key + "\n")
                        app_path = str(os.path.dirname(os.path.realpath(__file__))) + "/"
                        print("Saving key to path: " + app_path + "sql/key\n")
                        os.system("echo '" + new_key + "' > '" + app_path + "sql/key'")
                        print("Encrypting Password...\n")
                        password_hash = AESencrypt(new_key, email_password)
                        print("Saving Hash to SQL Database.\n")
                        email_sql_query = "UPDATE `Email` SET smtp_server = '" + smtp_server + "', smtp_port = '" + smtp_port + "', login_email_address = '" + login_address + "', password_hash='" + password_hash + "', recipient = '" + to_address + "'"
                        print("SQL Query: " + email_sql_query)
                        update_sql(email_sql_query)
                        print("Successfully saved e-mail settings.")
                        addMessageLog("Saved new e-mail settings.")
                        #printMessageLog()
                        #time.sleep(20)
                    except:
                        print("Error setting email settings.")
                        addMessageLog("Error setting email settings.")
                        #printMessageLog()
                elif 'delpower' in Command:
                    delpower,power_UID = Command.split(",")
                    try:
                        ser.write(Command)
                        ser.write("\n")
                        update_sql("DELETE FROM Power WHERE power_UID = " + power_UID + "")
                        reindex_sql = 'CREATE TABLE "Power_temp" (`power_UID`  INT, `rowid`  INTEGER PRIMARY KEY AUTOINCREMENT, `power_R1` INT, `power_R2` INT, `status` INT, `alert_status` INT);INSERT INTO Power_temp (power_UID, power_R1, power_R2, status, alert_status) SELECT power_UID, power_R1, power_R2, status, alert_status FROM Power;DROP TABLE Power;ALTER TABLE Power_temp rename to Power;'
                        print(reindex_sql)
                        update_script(reindex_sql)
                        #db.commit()
                        perform_commit = True
                        print("\033[37;0H                                                                                                           ")
                        print("\033[37;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") %s'%s'" % ("Sent Command: ",Command))
                        addMessageLog("Sent Command: " + Command)
                        #printMessageLog()
                    except:
                        print('ololo')
                        e = sys.exc_info()[0]
                        addMessageLog("<p>Error: %s</p>" % str(e))
                        print("Error deleting PowerLeaf node.")
                        addMessageLog("Error deleting PowerLeaf node.")
                        #printMessageLog()
                elif 'setpower' in Command:
                    setpower,power_UID,power_R1,power_R2 = Command.split(",")
                    try:
                        ser.write(Command)
                        ser.write("\n")
                        update_sql("UPDATE `Power_unknown` SET power_UID = 99 WHERE power_UID = " + power_UID + "")
                        #db.commit()
                        perform_commit = True
                        print("\033[37;0H                                                                                                           ")
                        print("\033[37;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") %s'%s'" % ("Sent Command: ",Command))
                        addMessageLog("Sent Command: " + Command)
                        #printMessageLog()
                    except:
                        print("Error Assigning PowerLeaf node.")
                        addMessageLog("Error Assigning PowerLeaf node.")
                        #printMessageLog()
    ####Need to fix this!  --> where does it write to database??
                elif 'configpower' in Command:
                    configpower,power_UID,power_R1,power_R2 = Command.split(",")
                    try:
                        ser.write(Command)
                        ser.write("\n")
                        print("\033[37;0H                                                                                                           ")
                        print("\033[37;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") %s'%s'" % ("Sent Command: ",Command))
                        addMessageLog("Sent Command: " + Command)
                        #printMessageLog()
                    except:
                        print("Error Configuring PowerLeaf node.")
                        addMessageLog("Error Configuring PowerLeaf node.")
                        #printMessageLog()
                elif 'motiondetected' in Command:
                    motiondetected,media_file = Command.split(",")
                    Motion_Alarm = fetch_sql("SELECT Motion_Alarm FROM Motion")
                    global timeOk
                    timeNow = str(fetch_one_sql("SELECT time FROM Motion"))[3:-2]
                    dayOfWeek = str(fetch_one_sql("SELECT day_of_week FROM Motion"))[3:-2]
                    alert = str(fetch_sql("SELECT alerts FROM Motion"))[3:-3]
                    timeJ = json.loads(timeNow)
                    timeStart = str(timeJ['from'])
                    timeEnd = str(timeJ['to'])
                    currentTime = datetime.datetime.now().time()
                    beginH,beginM = timeStart.split(":")
                    endH,endM = timeEnd.split(":")
                    if datetime.time(int(beginH),int(beginM)) <= currentTime <= datetime.time(int(endH),int(endM)):
                        timeOK = "True"
                    else:
                        timeOK = "False"
                    alertJ = json.loads(alert)
                    alertOK = str(alertJ['email'])
                    dayJ = json.loads(dayOfWeek)
                    today = datetime.datetime.today()
                    today3lower = str(today.strftime('%a').lower())
                    sendDayOK = str(dayJ[today3lower])
        #           print("@@@@@@@@@@@@@@@@" + login_address, email_password, to_address)
                    if (alertOK == 'True' and sendDayOK == 'True' and timeOK == 'True'):
                        addMessageLog("Sending email.....")
                        #printMessageLog()
                        send_detection_mail = mailer.email_html_motion(login_address,email_password,to_address,"Motion Detected",smtp_server, smtp_port,media_file)
                    if Motion_Alarm[0] == 0:
                        if send_detection_mail == 1:
                            update_sql("UPDATE `Motion` SET Motion_Alarm = 2, Motion_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if send_detection_mail == 0:
                            update_sql("UPDATE `Motion` SET Motion_Alarm = 1, Motion_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                elif 'public_access,true' in Command:
                    acc.blockIPs("true")
                elif 'public_access,false' in Command:
                    acc.blockIPs("false")
                elif Command not in '':
                    ser.write(Command)
                    ser.write("\n")
                    #time.sleep(5)
                    print("\033[37;0H                                                                                                           ")
                    print("\033[37;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") %s'%s'" % ("Sent Command: ",Command))
                    addMessageLog("Sent Command: " + Command)
                    #printMessageLog()
                    if os.path.exists(device_path):
                        ser.flushInput()
                        ser.readline()
                    else:
                        print('Path doesn\'t exist!')
                f_Command=open(app_path + 'Command','w+')
                f_Command.write('')
                f_Command.close()
                #time.sleep(2)
            #Read Serial Device and Update according to the information that was received.
            if os.path.exists(device_path):
                try:
                    line = ser.readline()
                    if isinstance(line, basestring) == 0:
                        print("Expected String...  Serial Read Error?\n")
                        addMessageLog("Expected String...  Serial Read Error?")
                        #printMessageLog()
                        return 0
                except:
                    print("Error reading serial device: line not string.")
                    addMessageLog("Error reading Serial device: line not string.")
                    #printMessageLog()
                    return 0
            else:
                print("Error reading serial device: path empty.")
                addMessageLog("Error reading serial device: path empty.")
                #printMessageLog()
                return 0
            print("\033[35;0H                                                                                                           ")
            print("\033[35;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") Now: " + now.strftime('%s') + "  Last Data Point: " + LastDataPoint_Time.strftime('%s') + "   Next Data Point [sec]: " + str(float(now.strftime('%s')) - float(LastDataPoint_Time.strftime('%s'))) + "/" + str(TakeDataPoint_Every - (float(now.strftime('%s')) - float(LastDataPoint_Time.strftime('%s')))) + "/" + str(TakeDataPoint_Every))
            addMessageLog(line)
            #printMessageLog()
            now = datetime.datetime.now()
            if 'TempCal' in line:
                TempCal, TempValue = line.split(",")
                #addMessageLog("Temperature calibrated :" + TempValue + "\n" )
                getCalibratedData(1,TempValue)
            elif 'RHCal' in line:
                RHCal, RHValue = line.split(",")
                getCalibratedData(2,RHValue)
                #addMessageLog("Relative Humidity calibrated : " + RHValue + "\n" )
            elif 'LightCal' in line:
                LightCal, LightValue = line.split(",")
                getCalibratedData(3,LightValue)
                #addMessageLog("Light calibrated : " + LightValue +  "\n")
            elif 'PHCal' in line:
                PHCal,point,value = line.split(",")
                getMultiPointsCalData(PHCal,point,value)
            elif 'TDSProbeCal' in line:
                TDSProbeCal,value = line.split(",")
                getMultiPointsCalData(TDSProbeCal,'',value)
            elif 'TDSCal' in line:
                TDSCal,point,value = line.split(",")
                getMultiPointsCalData(TDSCal,point,value)
            elif 'H2OLevelCal' in line:
                H2OLevelCal, point,value = line.split(",")
                getMultiPointsCalData(H2OLevelCal,point,value)
            elif 'H2OTempCal' in line: 
                H2OTempCal, point, value = line.split(",")
                getMultiPointsCalData(H2OTempCal,point,value)
            elif 'DripCal' in line: 
                DripCal, point, value = line.split(",")
                getMultiPointsCalData(DripCal,point,value)
            elif 'Time' in line:
                    print("\r")
                    #print("\v%s"%(line))
                    T,longdate,longdate2,Arduino_month,Arduino_day,Arduino_year,Arduino_hour,Arduino_min,Arduino_sec = line.split(",")
                    T = T.replace("Readfail", "")
                    Arduino_sec = Arduino_sec.rstrip()
                    ArduinoTime = longdate + longdate2
                    if len(Arduino_month) < 2:
                        Arduino_month = '0' + Arduino_month
                    if len(Arduino_day) < 2:
                        Arduino_day = '0' + Arduino_day
                    if len(Arduino_year) < 2:
                        Arduino_year = '0' + Arduino_year
                    if len(Arduino_hour) < 2:
                        Arduino_hour = '0' + Arduino_hour
                    if len(Arduino_min) < 2:
                        Arduino_min = '0' + Arduino_min
                    if len(Arduino_sec) < 2:
                        Arduino_sec = '0' + Arduino_sec
                    if ArduinoTime != '':
                        print("\033[34;0H                                                                                                                       ")
                        print("\033[19;0H                                                                                                                       ")
                        print("\033[1m") #Bold
                        print("\033[19;0H[Arduino Time: " + ArduinoTime + "]------------------------[Raspberry Pi Time: " + now.strftime("%b %d %Y %I:%M:%S %p") + "]")
                        print("\033[0m") #Un-Bold
                        update_sql("UPDATE `Arduino` SET `Time` = '" + ArduinoTime + "' , Month=" + Arduino_month + ", Day=" + Arduino_day + ", Year=" + Arduino_year + ", Hour=" + Arduino_hour + ", Minute=" + Arduino_min + ", Second=" + Arduino_sec)
                        #If the 'timesync' counter value goes over 20, then update the Raspberry Pi's
                        #time to be that of the Arduino's.
                    if timesync > 20:
                        try:
                            f = os.system("sudo date " + Arduino_month + Arduino_day + Arduino_hour + Arduino_min + Arduino_year + "." + Arduino_sec + " >/dev/null 2>&1")
                            if first_timesync == False:
                                LastDataPoint_Time = datetime.datetime.now()
                            first_timesync = True
                            drawInterfaceIPs()
                        except:
                            print("Error updating Raspberry Pi Time.")
                        time.sleep(2) #Let the poor Raspberry Pi have some down time
                        timesync = 0
                    timesync = timesync + 1
            elif 'Sensors' in line:
                Sensors,pH1,Temp,RH,TDS1,CO2,Light,H2OTemp,H2OLevel,Relay1,Relay2,Relay3,Relay4,Relay5,Relay6,Relay7,Relay8,Relay9,Relay10,Relay11,Relay12,Relay13,Relay14 = line.split(",")
                Sensors = Sensors.replace("Read fail", "")
                #Light = Light.rstrip()
                Relay14 = Relay14.rstrip()
                elapsedTime = now - startTime
                elapsedSeconds = (elapsedTime.microseconds + (elapsedTime.days * 24 * 3600 + elapsedTime.seconds) * 10 ** 6) / 10 ** 6
                print("\033[20;0H\r")
                print("\033[20;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") Sensors: %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (pH1,Temp,RH,TDS1,CO2,Light,H2OTemp,H2OLevel,Relay1,Relay2,Relay3,Relay4,Relay5,Relay6,Relay7,Relay8,Relay9,Relay10,Relay11,Relay12,Relay13,Relay14))
                now = datetime.datetime.now()
                delta = float(now.strftime('%s')) - float(LastDataPoint_Time.strftime('%s'))
                if (delta < 0):
                    TimeString = LastDataPoint_Time.strftime("%Y-%m-%d %H:%M:%S")
                    update_sql("DELETE FROM Sensors_Log WHERE Time='" + TimeString + "'")
                    update_sql("DELETE FROM Relays_Log WHERE Time='" + TimeString + "'")
                    LastDataPoint_Time = datetime.datetime.now()
                    addMessageLog("Negative Delta - Deleting Last Record (Wrong Time?)")
                    #printMessageLog()
                if (delta >= TakeDataPoint_Every) or (Datapoint_count == 0 and first_timesync == True):
                    addMessageLog("Added a data point to the sensor values log.")
                    #printMessageLog()
                    update_sql("INSERT INTO 'Sensors_Log' (Time,pH1,Temp,RH,TDS1,CO2,Light,H2OTemp,H2OLevel) VALUES ('" + now.strftime("%Y-%m-%d %H:%M:%S") + "'," + pH1 + "," + Temp + "," + RH + "," + TDS1 + "," + CO2 + "," + Light + "," + H2OTemp + "," + H2OLevel + ")")
                    update_sql("INSERT INTO 'Relays_Log' (Time,Relay1,Relay2,Relay3,Relay4,Relay5,Relay6,Relay7,Relay8,Relay9,Relay10,Relay11,Relay12,Relay13,Relay14) VALUES ('" + now.strftime("%Y-%m-%d %H:%M:%S") + "'," + Relay1 + "," + Relay2 + "," + Relay3 + "," + Relay4 + "," + Relay5 + "," + Relay6 + "," + Relay7 + "," + Relay8 + "," + Relay9 + "," + Relay10 + "," + Relay11 + "," + Relay12 + "," + Relay13 + "," + Relay14 + ")")
                    LastDataPoint_Time = datetime.datetime.now()
                    timesync = 0 #do a timesync
                    Datapoint_count = Datapoint_count + 1
                #SENSOR VALUES
                update_sql("UPDATE `Sensors` SET pH1 = " + pH1 + ",  Temp = " + Temp + ", RH = " + RH + ", TDS1 =" + TDS1 + ", CO2 = " + CO2 + ", Light = " + Light + ", H2OTemp = " + H2OTemp + ", H2OLevel= " + H2OLevel + "")
                update_sql("UPDATE `Relays` SET Relay1 = '" + Relay1 + "', Relay2 = '" + Relay2 + "', Relay3 = '" + Relay3 + "', Relay4 = '" + Relay4 + "', Relay5 = '" + Relay5 + "', Relay6 = '" + Relay6 + "', Relay7 = '" + Relay7 + "', Relay8 = '" + Relay8 + "', Relay9 = '" + Relay9 + "', Relay10 = '" + Relay10 + "', Relay11 = '" + Relay11 + "', Relay12 = '" + Relay12 + "', Relay13 = '" + Relay13 + "', Relay14 = '" + Relay14 + "'")
                #db.commit()
                perform_commit = True
            elif 'SensorUpdate' in line:
                #SensorUpdate
                SensorUpdate,pH1,Temp,RH,TDS1,CO2,Light,H2OTemp,H2OLevel,Relay1,Relay2,Relay3,Relay4,Relay5,Relay6,Relay7,Relay8,Relay9,Relay10,Relay11,Relay12,Relay13,Relay14 = line.split(",")
                SensorUpdate = SensorUpdate.replace("Read fail", "")
                #Send data to Azure
                try:
                    #addMessageLog(serialnumber)
                    sbs = ServiceBusService("telemetry",shared_access_key_name = "SendPolicy", shared_access_key_value = "TSpMuDOtsM9bw+UnYv2jo7R1sias9XVcCLyfZlibaLA=")
                    aztemp = {'CustomerId':'12345678','DeviceId': serialnumber,'pH1':pH1,'Temp':Temp,'RH':RH,'TDS1':TDS1,'CO2':CO2,'Light':Light,'H2OTemp':H2OTemp,'H2OLevel':H2OLevel}
                    # 'Relay8', Relay8, 'Relay9' : Relay9, 'Relay10' : Relay10, 'Relay11' : Relay11, 'Relay12' : Relay12, 'Relay13' : RCMelay13, 'Relay14' : Relay14 }
                    sbs.send_event('motorleaf',json.dumps(aztemp))
                    #addMessageLog(json.dumps(aztemp))
                    #sbsrelay = ServiceBusService("telemetry",shared_access_key_name = "SendPolicy", shared_access_key_value = "TSpMuDOtsM9bw+UnYv2jo7R1sias9XVcCLyfZlibaLA=")
                    #azrelay1 = {'CustomerId':'12345678','DeviceId': serialnumber,'Relay1':Relay1,'Relay2':Relay2,'Relay3':Relay3,'Relay4':Relay4,'Relay5':Relay5,'Relay6':Relay6,'Relay7': Relay7}
                    #sbsrelay.send_event(json.dumps(azrelay1))
                    #addMessageLog(json.dumps(azrelay1))
                except:
                    addMessageLog("Problem sending data to Azure")
                    Relay14 = Relay14.rstrip()
                #elapsedTime = now-startTime
                #elapsedSeconds =
                #(elapsedTime.microseconds+(elapsedTime.days*24*3600+elapsedTime.seconds)*10**6)/10**6
                #print("\033[20;0H\r")
                #print("\033[20;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") Sensors: %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (pH1,Temp,RH,TDS1,CO2,Light,H2OTemp,H2OLevel,Relay1,Relay2,Relay3,Relay4,Relay5,Relay6,Relay7,Relay8,Relay9,Relay10,Relay11,Relay12,Relay13,Relay14))
                now = datetime.datetime.now()
                update_sql("INSERT INTO 'Sensors_Log' (Time,pH1,Temp,RH,TDS1,CO2,Light,H2OTemp,H2OLevel) VALUES ('" + now.strftime("%Y-%m-%d %H:%M:%S") + "'," + pH1 + "," + Temp + "," + RH + "," + TDS1 + "," + CO2 + "," + Light + "," + H2OTemp + "," + H2OLevel + ")")
                update_sql("INSERT INTO 'Relays_Log' (Time,Relay1,Relay2,Relay3,Relay4,Relay5,Relay6,Relay7,Relay8,Relay9,Relay10,Relay11,Relay12,Relay13,Relay14) VALUES ('" + now.strftime("%Y-%m-%d %H:%M:%S") + "'," + Relay1 + "," + Relay2 + "," + Relay3 + "," + Relay4 + "," + Relay5 + "," + Relay6 + "," + Relay7 + "," + Relay8 + "," + Relay9 + "," + Relay10 + "," + Relay11 + "," + Relay12 + "," + Relay13 + "," + Relay14 + ")")
                #db.commit()
                perform_commit = True
            elif 'Relays' in line:
                if oldRelays != line:
                    oldRelays = line
                    #print("%s"%(line)) For Debugging
                    Relays,Relay1,Relay2,Relay3,Relay4,Relay5,Relay6,Relay7,Relay8,Relay9,Relay10,Relay11,Relay12,Relay13,Relay14 = line.split(",")
                    Relays = Relays.replace("Read fail", "")
                    Relay14 = Relay14.rstrip()
                    print("\033[21;0H                                                                                                                       ")
                    print("\033[21;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") Relays: %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (Relay1,Relay2,Relay3,Relay4,Relay5,Relay6,Relay7,Relay8,Relay9,Relay10,Relay11,Relay12,Relay13,Relay14))
                    now = datetime.datetime.now()
                    delta = float(now.strftime('%s')) - float(LastDataPoint_Time.strftime('%s'))
                    #RELAYS
                    update_sql("UPDATE `Relays` SET Relay1 = '" + Relay1 + "', Relay2 = '" + Relay2 + "', Relay3 = '" + Relay3 + "', Relay4 = '" + Relay4 + "', Relay5 = '" + Relay5 + "', Relay6 = '" + Relay6 + "', Relay7 = '" + Relay7 + "', Relay8 = '" + Relay8 + "', Relay9 = '" + Relay9 + "', Relay10 = '" + Relay10 + "', Relay11 = '" + Relay11 + "', Relay12 = '" + Relay12 + "', Relay13 = '" + Relay13 + "', Relay14 = '" + Relay14 + "'")
                    #db.commit()
            elif 'Relay_isAuto' in line:
                if oldRelay_isAuto != line:
                    #print("%s"%(line)) For Debugging
                    oldRelay_isAuto = line;
                    Relay_isAuto,Relay1_isAuto,Relay2_isAuto,Relay3_isAuto,Relay4_isAuto,Relay5_isAuto,Relay6_isAuto,Relay7_isAuto,Relay8_isAuto,Relay9_isAuto,Relay10_isAuto,Relay11_isAuto,Relay12_isAuto,Relay13_isAuto,Relay14_isAuto = line.split(",")
                    Relay_isAuto = Relay_isAuto.replace("Read fail", "")
                    Relay14_isAuto = Relay14_isAuto.rstrip()
                    print("\033[22;0H                                                                                                                       ")
                    print("\033[22;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") Relay_isAuto: %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" % (Relay1_isAuto,Relay2_isAuto,Relay3_isAuto,Relay4_isAuto,Relay5_isAuto,Relay6_isAuto,Relay7_isAuto,Relay8_isAuto,Relay9_isAuto,Relay10_isAuto,Relay11_isAuto,Relay12_isAuto,Relay13_isAuto,Relay14_isAuto))
                    update_sql("UPDATE `Relays` SET Relay1_isAuto = " + Relay1_isAuto + ", Relay2_isAuto = " + Relay2_isAuto + ", Relay3_isAuto = " + Relay3_isAuto + ", Relay4_isAuto = " + Relay4_isAuto + ", Relay5_isAuto =" + Relay5_isAuto + ", Relay6_isAuto =" + Relay6_isAuto + ", Relay7_isAuto = " + Relay7_isAuto + ", Relay8_isAuto = " + Relay8_isAuto + ", Relay9_isAuto = " + Relay9_isAuto + ", Relay10_isAuto = " + Relay10_isAuto + ", Relay11_isAuto =" + Relay11_isAuto + ", Relay12_isAuto =" + Relay12_isAuto + ", Relay13_isAuto =" + Relay13_isAuto + ", Relay14_isAuto =" + Relay14_isAuto + "")
                    #db.commit()
            elif 'PowerUnknown' in line:
                if oldPower_unknown != line:
                    oldPower_unknown = line
                    #print("%s"%(line)) For Debugging
                    PowerUnknown,power_UID = line.split(",")
                    PowerUnknown = PowerUnknown.replace("Read fail", "")
                    power_UID = power_UID.rstrip()
                    print("\033[23;0H\r")
                    print("\033[23;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") PowerUnknown: %s" % (power_UID))
                    #Power_unknown
                    update_sql("UPDATE `Power_unknown` SET power_UID = " + power_UID + "")
                    #db.commit()
                    perform_commit = True
            elif 'Power' in line:
                if oldPower != line:
                    oldPower = line
                    #print("%s"%(line)) For Debugging
                    Power,power_UID,rowid,power_R1,power_R2 = line.split(",")
                    Power = Power.replace("Read fail", "")
                    power_R2 = power_R2.rstrip()
                    print("\033[23;0H\r")
                    print("\033[23;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") Power: %s,%s,%s,%s" % (power_UID,rowid,power_R1,power_R2))
                    #Power check to see if power is known
                    power_query = fetch_sql("SELECT count(*) FROM Power WHERE power_UID = " + power_UID + "")
                    #print(power_query[0])
                    if (power_query[0] >= 1):
                                update_sql("UPDATE 'Power' SET power_UID = " + power_UID + ", rowid = " + rowid + ", power_R1 = " + power_R1 + ", power_R2 = " + power_R2 + ", status = 1 WHERE power_UID = " + power_UID + "")
                    if (power_query[0] == 0):
                            update_sql("INSERT INTO 'Power' (power_UID,rowid,power_R1,power_R2,status) VALUES (" + power_UID + "," + rowid + "," + power_R1 + "," + power_R2 + ",1)")
                    #print("inserting power row")
                    #db.commit()
                    perform_commit = True
            elif 'Ploss' in line:
                if oldPloss != line:    #oldPloss is not defined
                    oldPloss = line
                    #print("%s"%(line)) For Debugging
                    Ploss,ploss_UID = line.split(",")
                    Ploss = Ploss.replace("Read fail", "")
                    ploss_UID = ploss_UID.rstrip()
                    print("\033[23;0H\r")
                    print("\033[23;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") Ploss: %s" % (ploss_UID))
                    #Ploss check to see if power is known
                    ploss_query = fetch_sql("SELECT count(*) FROM Power WHERE power_UID = " + ploss_UID + "")
                    #print(ploss_query[0])
                    if (ploss_query[0] >= 1):
                                update_sql("UPDATE 'Power' SET status = 0 WHERE power_UID = " + ploss_UID + "")
                    if (ploss_query[0] == 0):
                                #update_sql("INSERT INTO 'Power'
                                #(power_UID,rowid,power_R1,power_R2,status) VALUES (" + power_UID + ",0,0,0,0)")
                                addMessageLog("Lost PL not found: " + ploss_UID)
                                #printMessageLog()
                    #db.commit()
                    perform_commit = True
            elif 'Light_Schedule' in line:
                if oldLight_Schedule != line:
                    oldLight_Schedule = line
                    #print("%s"%(line)) For Debugging
                    Lighting,Light_ON_hour,Light_ON_min,Light_OFF_hour,Light_OFF_min = line.split(",")
                    Lighting = Lighting.replace("Read fail", "")
                    Light_OFF_min = Light_OFF_min.rstrip()
                    print("\033[23;0H                                                                                                                       ")
                    print("\033[23;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") Light_Schedule: %s,%s,%s,%s" % (Light_ON_hour,Light_ON_min,Light_OFF_hour,Light_OFF_min))
                    #LIGHTING
                    update_sql("UPDATE `Light_Schedule` SET Light_ON_hour = " + Light_ON_hour + ", Light_ON_min = " + Light_ON_min + ", Light_OFF_hour = " + Light_OFF_hour + ", Light_OFF_min = " + Light_OFF_min)
            elif 'Watering_Schedule' in line:
                if oldWatering_Schedule != line:
                    oldWatering_Schedule = line
                    #print("%s"%(line)) For Debugging
                    Watering,Pump1Int_AM,Pump1Int_PM,Pump1Int_ONAM,Pump1Int_ONPM,Pump1Timer_AM,Pump1Timer_PM = line.split(",")
                    Watering = Watering.replace("Read fail", "")
                    Pump1Timer_PM = Pump1Timer_PM.rstrip()
                    print("\033[24;0H                                                                                                                       ")
                    print("\033[24;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") Watering_Schedule: %s,%s,%s,%s,%s,%s" % (Pump1Int_AM,Pump1Int_PM,Pump1Int_ONAM,Pump1Int_ONPM,Pump1Timer_AM,Pump1Timer_PM))
                    #WATERING
                    update_sql("UPDATE `Watering_Schedule` SET Pump1Int_AM = " + Pump1Int_AM + ", Pump1Int_PM = " + Pump1Int_PM + ", Pump1Int_ONAM = " + Pump1Int_ONAM + ", Pump1Int_ONPM = " + Pump1Int_ONPM + ", Pump1Timer_AM =" + Pump1Timer_AM + ", Pump1Timer_PM =" + Pump1Timer_PM + "")
            elif 'SetPoint_pH1' in line:
                if oldSetPoint_pH1 != line:
                    #print("%s"%(line)) For Debugging
                    SetPoint_pH1,pH1Value_Low,pH1Value_High,PHUp_ON,PHUp_OFF,PHDown_ON,PHDown_OFF,pH1_Status = line.split(",")
                    SetPoint_pH1 = SetPoint_pH1.replace("Read fail", "")
                    pH1_Status = pH1_Status.rstrip()
                    print("\033[25;0H                                                                                                                       ")
                    print("\033[25;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") SetPoint_pH1: %s,%s,%s,%s,%s,%s,%s" % (pH1Value_Low,pH1Value_High,PHUp_ON,PHUp_OFF,PHDown_ON,PHDown_OFF,pH1_Status))
                    #SetPoint_pH
                    if (oldSetPoint_pH1.rsplit(",",1)[0] != line.rsplit(",",1)[0]) and (oldSetPoint_pH1 != " "):
                        update_sql("INSERT INTO 'pH1_Log' (Time,Low,High,PHUP_ON,PHUP_OFF,PHDOWN_ON,PHDOWN_OFF) VALUES ('" + now.strftime("%Y-%m-%d %H:%M:%S") + "'," + pH1Value_Low + "," + pH1Value_High + "," + PHUp_ON + "," + PHUp_OFF + "," + PHDown_ON + "," + PHDown_OFF + ")")
                    update_sql("UPDATE `pH1` SET Low='" + pH1Value_Low + "', High='" + pH1Value_High + "', PHUp_ON='" + PHUp_ON + "', PHUp_OFF='" + PHUp_OFF + "', PHDown_ON='" + PHDown_ON + "', PHDown_OFF='" + PHDown_OFF + "', Status='" + pH1_Status + "'")
                    pH1_Low_Alarm = fetch_sql("SELECT Low_Alarm FROM pH1")
                    pH1_High_Alarm = fetch_sql("SELECT High_Alarm FROM pH1")
                    pH1_Value = fetch_sql("SELECT pH1 FROM Sensors")
                    if pH1_Low_Alarm[0] == 1:
                        if mailer.email_html_tls(login_address,email_password,to_address,"pH is Low",smtp_server,smtp_port,pH1_Value[0],"") == 1:
                            update_sql("UPDATE `pH1` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if pH1_High_Alarm[0] == 1:
                        if mailer.email_html_tls(login_address,email_password,to_address,"pH1 is High",smtp_server, smtp_port,pH1_Value[0],"") == 1:
                            update_sql("UPDATE `pH1` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if 'LOW' in pH1_Status and pH1_Low_Alarm[0] == 0:
                        update_sql("UPDATE `pH1` SET Low_Alarm = 1, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if mailer.email_html_tls(login_address,email_password,to_address,"pH is Low",smtp_server,smtp_port,pH1_Value[0],"") == 1:
                            update_sql("UPDATE `pH1` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if 'HIGH' in pH1_Status and pH1_High_Alarm[0] == 0:
                        update_sql("UPDATE `pH1` SET High_Alarm = 1, High_Time= '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if mailer.email_html_tls(login_address,email_password,to_address,"pH1 is High",smtp_server, smtp_port,pH1_Value[0],"") == 1:
                            update_sql("UPDATE `pH1` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    oldSetPoint_pH1 = line
            elif 'SetPoint_Temp' in line:
                if oldSetPoint_Temp != line:
                    print("%s" % (line))  #For Debugging
                    SetPoint_Temp,TempValue_Low,TempValue_High,Heater_ON,Heater_OFF,AC_ON,AC_OFF,Temp_Status = line.split(",")
                    SetPoint_Temp = SetPoint_Temp.replace("Read fail", "")
                    Temp_Status = Temp_Status.rstrip()
                    print("\033[27;0H                                                                                                                       ")
                    print("\033[27;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") SetPoint_Temp: %s,%s,%s,%s,%s,%s,%s" % (TempValue_Low,TempValue_High,Heater_ON,Heater_OFF,AC_ON,AC_OFF,Temp_Status))
                    #SetPoint_TEMP
                    if (oldSetPoint_Temp.rsplit(",",1)[0] != line.rsplit(",",1)[0]) and (oldSetPoint_Temp != " "):
                        update_sql("INSERT INTO 'Temp_Log' (Time,Low,High,Heater_ON,Heater_OFF,AC_ON,AC_OFF) VALUES ('" + now.strftime("%Y-%m-%d %H:%M:%S") + "'," + TempValue_Low + "," + TempValue_High + "," + Heater_ON + "," + Heater_OFF + "," + AC_ON + "," + AC_OFF + ")")
                    update_sql("UPDATE `Temp` SET Low = " + TempValue_Low + ", High = " + TempValue_High + ", Heater_ON = " + Heater_ON + ", Heater_OFF = " + Heater_OFF + ", AC_ON =" + AC_ON + ", AC_OFF =" + AC_OFF + ", Status ='" + Temp_Status + "'")
                    Temp_Low_Alarm = fetch_sql("SELECT Low_Alarm FROM Temp")
                    Temp_High_Alarm = fetch_sql("SELECT High_Alarm FROM Temp")
                    Temp_Value = fetch_sql("SELECT Temp FROM Sensors")
                    if Temp_Low_Alarm[0] == 1:
                        if mailer.email_html_tls(login_address,email_password,to_address,"Air Temperature is Low",smtp_server, smtp_port, Temp_Value[0], "C") == 1:
                            update_sql("UPDATE `Temp` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if Temp_High_Alarm[0] == 1:
                        if mailer.email_html_tls(login_address,email_password,to_address,"Air Temperature is High",smtp_server, smtp_port, Temp_Value[0], "C") == 1:
                            update_sql("UPDATE `Temp` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if 'LOW' in Temp_Status and Temp_Low_Alarm[0] == 0:
                        update_sql("UPDATE `Temp` SET Low_Alarm = 1, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if mailer.email_html_tls(login_address,email_password,to_address,"Air Temperature is Low",smtp_server, smtp_port, Temp_Value[0], "C") == 1:
                            update_sql("UPDATE `Temp` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if 'HIGH' in Temp_Status and Temp_High_Alarm[0] == 0:
                            update_sql("UPDATE `Temp` SET High_Alarm = 1, High_Time= '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                            if mailer.email_html_tls(login_address,email_password,to_address,"Air Temperature is High",smtp_server, smtp_port, Temp_Value[0], "C") == 1:
                                update_sql("UPDATE `Temp` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    oldSetPoint_Temp = line
            elif 'SetPoint_RH' in line:
                if oldSetPoint_RH != line:
                        #print("%s"%(line)) For Debugging
                        SetPoint_RH,RHValue_Low,RHValue_High,Humidifier_ON,Humidifier_OFF,Dehumidifier_ON,Dehumidifier_OFF,RH_Status = line.split(",")
                        SetPoint_RH = SetPoint_RH.replace("Read fail", "")
                        RH_Status = RH_Status.rstrip()
                        print("\033[28;0H                                                                                                                       ")
                        print("\033[28;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") SetPoint_RH: %s,%s,%s,%s,%s,%s,%s" % (RHValue_Low,RHValue_High,Humidifier_ON,Humidifier_OFF,Dehumidifier_ON,Dehumidifier_OFF,RH_Status))
                        #SetPoint_RH
                        if (oldSetPoint_RH.rsplit(",",1)[0] != line.rsplit(",",1)[0]) and (oldSetPoint_RH != " "):
                            update_sql("INSERT INTO 'RH_Log' (Time,Low,High,Humidifier_ON,Humidifier_OFF,Dehumidifier_ON,Dehumidifier_OFF) VALUES ('" + now.strftime("%Y-%m-%d %H:%M:%S") + "'," + RHValue_Low + "," + RHValue_High + "," + Humidifier_ON + "," + Humidifier_OFF + "," + Dehumidifier_ON + "," + Dehumidifier_OFF + ")")
                        update_sql("UPDATE `RH` SET Low = " + RHValue_Low + ", High = " + RHValue_High + ", Humidifier_ON = " + Humidifier_ON + ", Humidifier_OFF = " + Humidifier_OFF + ", Dehumidifier_ON =" + Dehumidifier_ON + ", Dehumidifier_OFF =" + Dehumidifier_OFF + ", Status ='" + RH_Status + "'")
                        RH_Low_Alarm = fetch_sql("SELECT Low_Alarm FROM RH")
                        RH_High_Alarm = fetch_sql("SELECT High_Alarm FROM RH")
                        RH_Value = fetch_sql("SELECT RH FROM Sensors")
                        if RH_Low_Alarm[0] == 1:
                            if mailer.email_html_tls(login_address,email_password,to_address,"Humiditiy is Low",smtp_server, smtp_port,RH_Value[0],"%") == 1:
                                update_sql("UPDATE `RH` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if RH_High_Alarm[0] == 1:
                            if mailer.email_html_tls(login_address,email_password,to_address,"Humidity is High",smtp_server, smtp_port,RH_Value[0],"%") == 1:
                                update_sql("UPDATE `RH` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if 'LOW' in RH_Status and RH_Low_Alarm[0] == 0:
                            update_sql("UPDATE `RH` SET Low_Alarm = 1, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                            if mailer.email_html_tls(login_address,email_password,to_address,"Humiditiy is Low",smtp_server, smtp_port,RH_Value[0],"%") == 1:
                                update_sql("UPDATE `RH` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if 'HIGH' in RH_Status and RH_High_Alarm[0] == 0:
                            update_sql("UPDATE `RH` SET High_Alarm = 1, High_Time= '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                            if mailer.email_html_tls(login_address,email_password,to_address,"Humidity is High",smtp_server, smtp_port,RH_Value[0],"%") == 1:
                                update_sql("UPDATE `RH` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        oldSetPoint_RH = line
            elif 'SetPoint_TDS1' in line:
                if oldSetPoint_TDS1 != line:
                    #print("%s"%(line)) For Debugging
                    SetPoint_TDS1,TDS1Value_Low,TDS1Value_High,NutePump1_ON,NutePump1_OFF,MixPump1_Enabled,TDS1_Status = line.split(",")
                    SetPoint_TDS1 = SetPoint_TDS1.replace("Read fail", "")
                    TDS1_Status = TDS1_Status.rstrip()
                    print("\033[29;0H                                                                                                                       ")
                    print("\033[29;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") SetPoint_TDS1: %s,%s,%s,%s,%s,%s" % (TDS1Value_Low,TDS1Value_High,NutePump1_ON,NutePump1_OFF,MixPump1_Enabled,TDS1_Status))
                    #SetPoint_TDS1
                    if (oldSetPoint_TDS1.rsplit(",",1)[0] != line.rsplit(",",1)[0]) and (oldSetPoint_TDS1 != " "):
                        update_sql("INSERT INTO 'TDS1_Log' (Time,Low,High,NutePump1_ON,NutePump1_OFF) VALUES ('" + now.strftime("%Y-%m-%d %H:%M:%S") + "'," + TDS1Value_Low + "," + TDS1Value_High + "," + NutePump1_ON + "," + NutePump1_OFF + ")")
                    update_sql("UPDATE `TDS1` SET Low = " + TDS1Value_Low + ", High = " + TDS1Value_High + ", NutePump1_ON = " + NutePump1_ON + ", NutePump1_OFF = " + NutePump1_OFF + ", MixPump1_Enabled =" + MixPump1_Enabled + ", Status ='" + TDS1_Status + "'")
                    TDS1_Low_Alarm = fetch_sql("SELECT Low_Alarm FROM TDS1")
                    TDS1_High_Alarm = fetch_sql("SELECT High_Alarm FROM TDS1")
                    TDS1_Value = fetch_sql("SELECT TDS1 FROM Sensors")
                    if TDS1_Low_Alarm[0] == 1:
                        if mailer.email_html_tls(login_address,email_password,to_address,"Nutrient Levels are Low",smtp_server, smtp_port,TDS1_Value[0],"ppm") == 1:
                            update_sql("UPDATE `TDS1` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if TDS1_High_Alarm[0] == 1:
                        if mailer.email_html_tls(login_address,email_password,to_address,"Nutrient Levels are High",smtp_server, smtp_port,TDS1_Value[0],"ppm") == 1:
                            update_sql("UPDATE `TDS1` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if 'LOW' in TDS1_Status and TDS1_Low_Alarm[0] == 0:
                        update_sql("UPDATE `TDS1` SET Low_Alarm = 1, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if mailer.email_html_tls(login_address,email_password,to_address,"Nutrient Levels are Low",smtp_server, smtp_port,TDS1_Value[0],"ppm") == 1:
                            update_sql("UPDATE `TDS1` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if 'HIGH' in TDS1_Status and TDS1_High_Alarm[0] == 0:
                        update_sql("UPDATE `TDS1` SET High_Alarm = 1, High_Time= '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if mailer.email_html_tls(login_address,email_password,to_address,"Nutrient Levels are High",smtp_server, smtp_port,TDS1_Value[0],"ppm") == 1:
                            update_sql("UPDATE `TDS1` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    oldSetPoint_TDS1 = line
            elif 'SetPoint_CO2' in line:
                if oldSetPoint_CO2 != line:
                    #print("%s"%(line)) For Debugging
                    SetPoint_CO2,CO2Value_Low,CO2Value_High,CO2_ON,CO2_OFF,CO2_Enabled,CO2_Status = line.split(",")
                    SetPoint_CO2 = SetPoint_CO2.replace("Read fail", "")
                    CO2_Status = CO2_Status.rstrip()
                    print("\033[31;0H                                                                                                                       ")
                    print("\033[31;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") SetPoint_CO2: %s,%s,%s,%s,%s,%s" % (CO2Value_Low,CO2Value_High,CO2_ON,CO2_OFF,CO2_Enabled,CO2_Status))
                    #SetPoint_CO2
                    if (oldSetPoint_CO2.rsplit(",",1)[0] != line.rsplit(",",1)[0]) and (oldSetPoint_CO2 != " "):
                        update_sql("INSERT INTO 'CO2_Log' (Time,Low,High,CO2_ON,CO2_OFF) VALUES ('" + now.strftime("%Y-%m-%d %H:%M:%S") + "'," + CO2Value_Low + "," + CO2Value_High + "," + CO2_ON + "," + CO2_OFF + ")")
                    update_sql("UPDATE `CO2` SET Low = " + CO2Value_Low + ", High = " + CO2Value_High + ", CO2_ON = " + CO2_ON + ", CO2_OFF = " + CO2_OFF + ", CO2_Enabled =" + CO2_Enabled + ", Status = '" + CO2_Status + "'")
                    CO2_Low_Alarm = fetch_sql("SELECT Low_Alarm FROM CO2")
                    CO2_High_Alarm = fetch_sql("SELECT High_Alarm FROM CO2")
                    CO2_Value = fetch_sql("SELECT CO2 FROM Sensors")
                    if CO2_Low_Alarm[0] == 1:
                        if mailer.email_html_tls(login_address,email_password,to_address,"CO2 Levels are Low",smtp_server, smtp_port,CO2_Value[0],"ppm") == 1:
                            update_sql("UPDATE `CO2` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if CO2_High_Alarm[0] == 1:
                        if mailer.email_html_tls(login_address,email_password,to_address,"CO2 Levels are High",smtp_server, smtp_port,CO2_Value[0],"ppm") == 1:
                            update_sql("UPDATE `CO2` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if 'LOW' in CO2_Status and CO2_Low_Alarm[0] == 0:
                        update_sql("UPDATE `CO2` SET Low_Alarm = 1, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if mailer.email_html_tls(login_address,email_password,to_address,"CO2 Levels are Low",smtp_server, smtp_port,CO2_Value[0],"ppm") == 1:
                            update_sql("UPDATE `CO2` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if 'HIGH' in CO2_Status and CO2_High_Alarm[0] == 0:
                        update_sql("UPDATE `CO2` SET High_Alarm = 1, High_Time= '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if mailer.email_html_tls(login_address,email_password,to_address,"CO2 Levels are High",smtp_server, smtp_port,CO2_Value[0],"ppm") == 1:
                            update_sql("UPDATE `CO2` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    oldSetPoint_CO2 = line
            elif 'SetPoint_Light' in line:
                if oldSetPoint_Light != line:
                    #print("%s"%(line)) For Debugging
                    SetPoint_Light,LightValue_Low,LightValue_High,Light_Status = line.split(",")
                    SetPoint_Light = SetPoint_Light.replace("Read fail", "")
                    Light_Status = Light_Status.rstrip()
                    print("\033[32;0H                                                                                                           ")
                    print("\033[32;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") SetPoint_Light: %s,%s,%s" % (LightValue_Low,LightValue_High,Light_Status))
                    #SetPoint_pH
                    if (oldSetPoint_Light.rsplit(",",1)[0] != line.rsplit(",",1)[0]) and (oldSetPoint_Light != " "):
                        update_sql("INSERT INTO 'Light_Log' (Time,Low,High) VALUES ('" + now.strftime("%Y-%m-%d %H:%M:%S") + "'," + LightValue_Low + "," + LightValue_High + ")")
                    update_sql("UPDATE `Light` SET Low = '" + LightValue_Low + "', High = '" + LightValue_High + "', Status = '" + Light_Status + "'")
                    Light_Low_Alarm = fetch_sql("SELECT Low_Alarm FROM Light")
                    Light_High_Alarm = fetch_sql("SELECT High_Alarm FROM Light")
                    Light_Value = fetch_sql("SELECT Light FROM Sensors")
                    email_sensor_value[0] = Light_Value
                    if Light_Low_Alarm[0] == 1:
                        #if mailer.email_html_tls(login_address,email_password,to_address,"Light levels are Low",smtp_server, smtp_port,Light_Value[0],"%") == 1:
                            #update_sql("UPDATE `Light` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        #email then move on
                        #update sql only after email is done?
                        #email is going to be sent regardless so update sql right away
                        email_flag[0] = 1
                        addMessageLog("Sending low light level email alert.")
                        #printMessageLog()
                        while email_flag_sent[0] == 0:
                            pass
                        update_sql("UPDATE `Light` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        perform_commit = True
                    elif Light_High_Alarm[0] == 1:
                        #if mailer.email_html_tls(login_address,email_password,to_address,"Light levels are High",smtp_server, smtp_port,Light_Value[0],"%") == 1:
                            #update_sql("UPDATE `Light` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        email_flag[1]=1
                        addMessageLog("Sending high light level email alert.")
                        #printMessageLog()
                        while email_flag_sent[1] == 0:
                            pass
                        update_sql("UPDATE `Light` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        perform_commit = True
                    elif 'LOW' in Light_Status and Light_Low_Alarm[0] == 0:
                        update_sql("UPDATE `Light` SET Low_Alarm = 1, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        #if mailer.email_html_tls(login_address,email_password,to_address,"Light levels are Low",smtp_server, smtp_port,Light_Value[0],"%") == 1:
                            #update_sql("UPDATE `Light` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        email_flag[0]=1
                        addMessageLog("Sending low light level email alert.")
                        email_flag_sent[0] = 0
                        while email_flag_sent[0] == 0:
                            pass
                        #printMessageLog()
                        update_sql("UPDATE `Light` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        perform_commit = True
                    elif 'HIGH' in Light_Status and Light_High_Alarm[0] == 0:
                        update_sql("UPDATE `Light` SET High_Alarm = 1, High_Time= '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        #if mailer.email_html_tls(login_address,email_password,to_address,"Light levels are High",smtp_server, smtp_port,Light_Value[0],"%") == 1:
                            #update_sql("UPDATE `Light` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        email_flag[1]=1
                        addMessageLog("Sending high light level email alert.")
                        email_flag_sent[1] = 0
                        while email_flag_sent[1] == 0:
                            pass
                        #printMessageLog()
                        update_sql("UPDATE `Light` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        perform_commit = True
                    oldSetPoint_Light = line
            elif 'SetPoint_H2OTemp' in line:
                if oldSetPoint_H2OTemp != line:
                    #print("%s"%(line)) For Debugging
                    SetPoint_H2OTemp,H2OTempValue_Low,H2OTempValue_High,H2OHeater_ON,H2OHeater_OFF,H2OChiller_ON,H2OChiller_OFF,H2OTemp_Status = line.split(",")
                    SetPoint_H2OTemp = SetPoint_H2OTemp.replace("Read fail", "")
                    H2OTemp_Status = H2OTemp_Status.rstrip()
                    print("\033[27;0H                                                                                                                       ")
                    print("\033[27;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") SetPoint_Temp: %s,%s,%s,%s,%s,%s,%s" % (H2OTempValue_Low,H2OTempValue_High,H2OHeater_ON,H2OHeater_OFF,H2OChiller_ON,H2OChiller_OFF,H2OTemp_Status))
                    #SetPoint_H2OTemp
                    if (oldSetPoint_H2OTemp.rsplit(",",1)[0] != line.rsplit(",",1)[0]) and (oldSetPoint_H2OTemp != " "):
                        update_sql("INSERT INTO 'H2OTemp_Log' (Time,Low,High,H2OHeater_ON,H2OHeater_OFF,H2OChiller_ON,H2OChiller_OFF) VALUES ('" + now.strftime("%Y-%m-%d %H:%M:%S") + "'," + H2OTempValue_Low + "," + H2OTempValue_High + "," + H2OHeater_ON + "," + H2OHeater_OFF + "," + H2OChiller_ON + "," + H2OChiller_OFF + ")")
                    update_sql("UPDATE `H2OTemp` SET Low = " + H2OTempValue_Low + ", High = " + H2OTempValue_High + ", H2OHeater_ON = " + H2OHeater_ON + ", H2OHeater_OFF = " + H2OHeater_OFF + ", H2OChiller_ON =" + H2OChiller_ON + ", H2OChiller_OFF =" + H2OChiller_OFF + ", Status ='" + H2OTemp_Status + "'")
                    H2OTemp_Low_Alarm = fetch_sql("SELECT Low_Alarm FROM H2OTemp")
                    H2OTemp_High_Alarm = fetch_sql("SELECT High_Alarm FROM H2OTemp")
                    H2OTemp_Value = fetch_sql("SELECT H2OTemp FROM Sensors")
                    if H2OTemp_Low_Alarm[0] == 1:
                        if mailer.email_html_tls(login_address,email_password,to_address,"Reservoir Temperature is Low",smtp_server, smtp_port,H2OTemp_Value[0],"C") == 1:
                            update_sql("UPDATE `H2OTemp` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if H2OTemp_High_Alarm[0] == 1:
                        if mailer.email_html_tls(login_address,email_password,to_address,"Reservoir Temperature is High",smtp_server, smtp_port,H2OTemp_Value[0],"C") == 1:
                            update_sql("UPDATE `H2OTemp` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if 'LOW' in H2OTemp_Status and H2OTemp_Low_Alarm[0] == 0:
                        update_sql("UPDATE `H2OTemp` SET Low_Alarm = 1, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if mailer.email_html_tls(login_address,email_password,to_address,"Reservoir Temperature is Low",smtp_server, smtp_port,H2OTemp_Value[0],"C") == 1:
                            update_sql("UPDATE `H2OTemp` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if 'HIGH' in H2OTemp_Status and H2OTemp_High_Alarm[0] == 0:
                        update_sql("UPDATE `H2OTemp` SET High_Alarm = 1, High_Time= '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if mailer.email_html_tls(login_address,email_password,to_address,"Reservoir Temperature is High",smtp_server, smtp_port,H2OTemp_Value[0],"C") == 1:
                            update_sql("UPDATE `H2OTemp` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    oldSetPoint_H2OTemp = line
            elif 'SetPoint_H2OLevel' in line:
                if oldSetPoint_H2OLevel != line:
                    #print("%s"%(line)) For Debugging
                    SetPoint_H2OLevel,H2OLevelValue_Low,H2OLevelValue_High,H2OPump_ON,H2OPump_OFF,H2OLevel_Status = line.split(",")
                    SetPoint_H2OLevel = SetPoint_H2OLevel.replace("Read fail", "")
                    H2OLevel_Status = H2OLevel_Status.rstrip()
                    print("\033[31;0H                                                                                                                       ")
                    print("\033[31;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") SetPoint_H2OLevel: %s,%s,%s,%s,%s" % (H2OLevelValue_Low,H2OLevelValue_High,H2OPump_ON,H2OPump_OFF,H2OLevel_Status))
                    #SetPoint_H2OLevel
                    if (oldSetPoint_H2OLevel.rsplit(",",1)[0] != line.rsplit(",",1)[0]) and (oldSetPoint_H2OLevel != " "):
                        update_sql("INSERT INTO 'H2OLevel_Log' (Time,Low,High,H2OPump_ON,H2OPump_OFF) VALUES ('" + now.strftime("%Y-%m-%d %H:%M:%S") + "'," + H2OLevelValue_Low + "," + H2OLevelValue_High + "," + H2OPump_ON + ", " + H2OPump_OFF + ")")
                    update_sql("UPDATE `H2OLevel` SET Low = " + H2OLevelValue_Low + ", High = " + H2OLevelValue_High + ", H2OPump_ON = " + H2OPump_ON + ", H2OPump_OFF = " + H2OPump_OFF + ", Status = '" + H2OLevel_Status + "'")
                    H2OLevel_Low_Alarm = fetch_sql("SELECT Low_Alarm FROM H2OLevel")
                    H2OLevel_High_Alarm = fetch_sql("SELECT High_Alarm FROM H2OLevel")
                    H2OLevel_Value = fetch_sql("SELECT H2OLevel FROM Sensors")
                    if H2OLevel_Low_Alarm[0] == 1:
                        if mailer.email_html_tls(login_address,email_password,to_address,"Reservoir Level is Low",smtp_server, smtp_port,H2OLevel_Value[0],"%") == 1:
                            update_sql("UPDATE `H2OLevel` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if H2OLevel_High_Alarm[0] == 1:
                        if mailer.email_html_tls(login_address,email_password,to_address,"Reservoir Level is High",smtp_server, smtp_port,H2OLevel_Value[0],"%") == 1:
                            update_sql("UPDATE `H2OLevel` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if 'LOW' in H2OLevel_Status and H2OLevel_Low_Alarm[0] == 0:
                        update_sql("UPDATE `H2OLevel` SET Low_Alarm = 1, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if mailer.email_html_tls(login_address,email_password,to_address,"Reservoir Level is Low",smtp_server, smtp_port,H2OLevel_Value[0],"%") == 1:
                            update_sql("UPDATE `H2OLevel` SET Low_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    if 'HIGH' in H2OLevel_Status and H2OLevel_High_Alarm[0] == 0:
                        update_sql("UPDATE `H2OLevel` SET High_Alarm = 1, High_Time= '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                        if mailer.email_html_tls(login_address,email_password,to_address,"Reservoir Level is High",smtp_server, smtp_port,H2OLevel_Value[0],"%") == 1:
                            update_sql("UPDATE `H2OLevel` SET High_Alarm = 2, Low_Time = '" + now.strftime("%b %d %Y %I:%M:%S %p") + "'")
                    oldSetPoint_H2OLevel = line
            elif 'setdevice' in line:
                setdevice, devicetype, actual_status = line.split(",")
                setdevice = setdevice.replace("Read fail", "")
                actual_status = actual_status.rstrip()
                print("\033[31;0H                                                                                                                       ")
                print("\033[31;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") setdevice: %s,%s" % (devicetype,actual_status))
                recorded_status = fetch_sql("SELECT status FROM Devices")
                addMessageLog(recorded_status)
                #printMessageLog()
                if actual_status == 0:  #this status is issued when the droplet and heart
                                        #don't see each other, e.g.:
                                        #   1) fresh out of box setup
                                        #   2) connection loss
                    #overwrite sql status with 0 regardless of what's currently in it
                    update_sql("UPDATE `Devices` SET status = 0")
                    perform_commit = True
                elif actual_status == 1: #this status should only be issued if and when 
                                        #the heart detects the droplet
                    if recorded_status[0] == 0:
                        update_sql("UPDATE `Devices` SET status = 1")
                        perform_commit = True
                    elif recorded_status[0] == 1:
                        #this is the part where the UI attaches the droplet
                        #and it becomes viewbale in the dashboard 
                        update_sql("UPDATE `Devices` SET status = 2")
                        perform_commit = True
                    elif recorded_status[0] == 2:
                        pass #do nothing; droplet is detected and already attached
                    
    ## NEED TO FIX THIS - DEVICE DISCONNECTION/RECONNECTION
    #    elif 'setdevice' in line:
    #        setdevice,devicetype,stats = line.split(",")
    #        setdevice = setdevice.replace("Read fail", "")
    #        stats = stats.rstrip()
    #                   print("\033[31;0H                                                                                                                       ")
    #                  print("\033[31;0H(" + now.strftime("%Y/%m/%d %H:%M:%S") + ") setdevice: %s,%s" % (devicetype,stats))
    #        #SetDevice
    #        drop_stats = fetch_sql("SELECT status FROM Devices")
            #addMessageLog(drop_stats)
            ##printMessageLog()
    #        if stats == 0:
    #            update_sql("UPDATE 'Devices' SET status = 0)
    #            db.commit()
    #        if stats == 1 and drop_stats[0] == 0:
    #            update_sql("UPDATE 'Devices' SET status = 1)
    #            db.commit()
        #ser.flushInput()
    #    time.sleep(1)
        except ValueError as detail:
            print ("\nError: ", detail)
            addMessageLog("Error: " + str(detail))
            #printMessageLog()
            #time.sleep(5)
    
        return perform_commit
    
    #Open Database Connection
    db = lite.connect(app_path+ '/sql/motorleaf.sqlite3', timeout=10)
    cursor =  db.cursor()
    global email_column 
    email_column = fetch_sql("SELECT * FROM Email")
    global company_url
    company_url = fetch_sql("SELECT URL FROM Settings")

    while 1:
        perform_commit = False
        perform_commit = checkSerial()
        if perform_commit:
            db.commit()
        #print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        global now
        now = datetime.datetime.now()
        #print("###############################################################################")


def email_loop(smtp_server, smtp_port, login_address, email_password, to_address):
    while 1:
        if (email_flag[0] == 1) or (email_flag[1] == 1): # light alerts
            sensor_value = email_sensor_value[0]
            sensor_value_unit = "%"
            email_footer_url = company_url
            #low light levels
            if email_flag[0] == 1:
                message_alert = "Light levels are LOW "
                email_sent = motorleafEmail.sendEmail(smtp_server, smtp_port, login_address, email_password, to_address, message_alert, sensor_value, sensor_value_unit, email_footer_url)
                if email_sent:
                    email_flag[0] = 0
                    email_flag_sent[0] = 1
            #high light levels
            if email_flag[1] == 1:
                message_alert = "Light levels are HIGH "
                email_sent = motorleafEmail.sendEmail(smtp_server, smtp_port, login_address, email_password, to_address, message_alert)
                if email_sent:
                    email_flag[1] = 0
                    email_flag_sent[1] = 1




#####MAIN############################################################
#The Starting Point of the Program.                 #
#####################################################################
yieldbuddy_name = "MotorLeaf"
Datapoint_count = 0

messagelog = [" ", " ", " ", " ", " ", " ", " ", " ", " "," "]
i=0
for i in range(0,9):
    i=i+1
    messagelog[i] = " "

print("MotorLeaf v1.75\r\n")
app_path = str(os.path.dirname(os.path.realpath(__file__))) + "/"
print("Application Path: " + app_path + "\n")
print("Checking For Possible Serial Devices:")
f = os.system("ls /dev/tty*")
print("\r")
    #print("Enter the path to the serial device.  (/dev/ttyAMA0):")
    #device_path=raw_input()
device_path = '/dev/ttyUSB0'    #override device_path (no user input)
if device_path == '':
    device_path = '/dev/ttyUSB0'
    #device_path = device_path.strip("\n")
    print(", ".join(device_path))
serial_device_ok = False
try:
    ser = serial.Serial(device_path,9600,timeout=None)
    ser.flushInput()
    #lets send a command to initiate all getting all setpoints
    ser.write("sendSerialSetpoints")
    serial_device_ok = True
except:
    print("Error opening serial device: no connection established.")
    #sys.exit(0)
  


#Insert sensors datapoint into SQL db at this interval (in seconds):
TakeDataPoint_Every = 600   #default: 300 seconds (Every 5 minutes) (12 times per hour) --> 288
                            #Datapoints a day

#Start initial time sync counter at this number:
timesync = 17

LastDataPoint_Time = datetime.datetime.now()
first_timesync = False
startTime = datetime.datetime.now()
os.system('clear')
#os.system('cat splashscreen')
#time.sleep(3)
if serial_device_ok:
    ser.write("\n") #Send blank line to initiate serial communications

#Load AES key
f_AESkey = open(app_path + '/sql/key','r+')
AESkey = f_AESkey.readline()
AESkey = AESkey.rstrip('\n')
f_AESkey.close()



#print("Renicing to priority 15.")
#os.system("renice -n 15 -p " + str(os.getpid()))
#
#proc = subprocess.Popen(["sudo fuser " + app_path + "sql/motorleaf.sqlite3"], stdout=subprocess.PIPE, shell=True, universal_newlines=True)#universal_newlines=True --> allows returned values to be treated as string (instead of bytes); necessary for Python 3.5
#(fuser_result, err) = proc.communicate()
#proc.wait()
#openpid = fuser_result.split(" ")
#print("This program's pid is: ",str(os.getpid()))
#print(openpid)
#
#i = 1
#while (i < len(openpid)):
#    if (openpid[i] != str(os.getpid())) and (openpid[i] != ""):
#        addMessageLog("Terminated PID: " + openpid[i] + " (for accessing the database)")
#        os.system("sudo kill -9 " + openpid[i])
#    i = i + 1

#raw_input()
drawInterface()

addMessageLog("Started MotorLeaf. Priority 15. (outside  main loop)")
#printMessageLog()
static = {'CustomerId': '32423422', 'DeviceId': 'Device01', 'Temperature': '67','RoomTemperature' : '78'}


# Create two threads as follows
email_flag = []
email_flag_sent = []
email_sensor_value = []
total_flags = 2 #for now: low light, high light levels
flag_i = 0
while flag_i  < total_flags:
    email_flag.append(0)
    email_flag_sent.append(0)
    if flag_i%2==0:
        email_sensor_value.append(0)
    flag_i = flag_i + 1


email_column = ""
company_url = ""
try:    
    
    #to avoid SQL collisions, main_loop 
    #fetches email keys for the email_loop
    thread.start_new_thread( main_loop, ())
    print ("main loop thread started.")
    while (len(email_column)==0) or (len(company_url)==0): #main_loop hasn't extracted email keys yet
        pass
    #Fetch Email Settings
    f_key = open(app_path + 'sql/key','r+')
    str_key = f_key.readline()
    str_key = str_key.rstrip('\n')
    f_key.close()
    print("Key: ", str_key)
    smtp_server = email_column[0]
    smtp_port = int(email_column[1])
    login_address = email_column[2]
    password_hash = email_column[3]
    to_address = email_column[4]
    email_password = AESdecrypt(str_key, password_hash)
    print("***********EMAIL PASSWORD: ",email_password)
    time.sleep(10)
    thread.start_new_thread( email_loop, (smtp_server, str(smtp_port), login_address, email_password, to_address))
    print ("email loop thread started.")

except:
   print ("Error: unable to start thread")

while 1:
   pass
