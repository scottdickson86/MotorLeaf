# -*- coding: utf-8 -*-
"""
Created on Fri Sep  9 10:51:07 2016

@author: scottwork
"""

import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
import os


localpath=os.path.dirname(os.path.realpath(__file__))

def sendEmail(smtp_server, smtp_port, login_address, email_password, to_address, message_alert, sensor_value, sensor_value_unit, email_footer_url):

#OLD VERSION
#    print ("Sending email...")
#    msg_header = 'From: MotorLeaf Alert <noreply@motorleaf.com>\n' \
#             'To: <'+to_address+'>\n' \
#             'MIME-Version: 1.0\n' \
#             'Content-type: text/html\n' \
#             'Subject: MotorLeaf Alert\n'
#    title = 'Attention!'
#    msg_content = '<h2>{title} > <font color="green">MotorLeaf has triggered an alert!' \
#            'Status: '+message_alert+'</font></h2>\n'.format(
#        title=title)
#    msg_full = (''.join([msg_header, msg_content])).encode()
    
    

    msg = MIMEMultipart()
    msg['From'] = login_address
    msg['To'] = to_address
    msg['Subject'] = "MotorLeaf Alert - {0}".format(message_alert)
     
    text = "Attention! MotorLeaf has triggered an alert."
    part1 = MIMEText(text, 'plain')
    f = open(localpath + "/templates/alert.txt")
    alert_email = f.read()
    f.close()
    html = alert_email.format(message_alert,sensor_value,sensor_value_unit,email_footer_url)
    part2 = MIMEText(html, 'html')

    msg.attach(part1)
    msg.attach(part2)
        
    try:
        server = smtplib.SMTP(smtp_server+':'+smtp_port)
        server.starttls()
        server.login(login_address, email_password)
        text = msg.as_string()
        server.sendmail(login_address,
                        [to_address],
                        text)
        server.quit()
        print ("Email sent.")
        return True
    except:
        print ("Email sending failed.")
        return False
    
    
    