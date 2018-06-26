import smtplib, os,codecs,sys
import argparse
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders

def send_mail(send_from, send_to, subject, text, server, port=25,files=[]):
	assert type(send_to)==list
	assert type(files)==list

	msg = MIMEMultipart()
	msg['From'] = send_from
	msg['To'] = COMMASPACE.join(send_to)
	msg['Date'] = formatdate(localtime=True)
	msg['Subject'] = subject

	#msg.attach( MIMEText(text) )
	msg.attach( MIMEText(text.encode('UTF-8'),'plain','UTF-8' ))

	for f in files:
		#part = MIMEBase('application', "octet-stream")
		part = MIMEBase('image', "png")
		part.set_payload( open(f,"rb").read() )
		Encoders.encode_base64(part)
		part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(f))
		msg.attach(part)

	smtp = smtplib.SMTP(server,port)
	smtp.sendmail(send_from, send_to, msg.as_string())
	smtp.close()
aparser=argparse.ArgumentParser()
aparser.add_argument('--recips',type=str,required=True)
aparser.add_argument('--subject',type=str,required=True)
aparser.add_argument('--body',type=str,required=True)
aparser.add_argument('--sender',type=str,required=True)
aparser.add_argument('--server',type=str,required=True)
aparser.add_argument('--port',type=str,required=True)
args=aparser.parse_args()
recips=args.recips
subject=args.subject
send_from=args.sender
srv=args.server
prt=args.port
body=args.body
send_to=recips.split(',')
fp=codecs.open(body,'r',encoding='utf-8')
text=fp.read()
fp.close()
send_mail(send_from,send_to,subject,text,server=srv,port=prt)
