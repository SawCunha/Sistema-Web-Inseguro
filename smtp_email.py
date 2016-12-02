#coding: utf-8

import smtplib

# Specifying the from and to addresses

fromaddr = 'meusite.labredes@gmail.com'
toaddrs  = 'samuelgonalves00@gmail.com'

# Gmail Login

username = 'meusite.labredes@gmail.com'
password = 'labredesmeusite'

# Writing the message (this message will appear in the email)

msg = 'Enter you message here'

froms = username  
to = ['samuelgonalves00@gmail.com', 'wdmeida@gmail.com']  
subject = 'OMG Super Important Message'  
body = 'Hey, whats up?\n\n- You'

email_text = """\  
From: %s  
To: %s  
Subject: %s

%s
""" % (froms, ", ".join(to), subject, body)





# Sending the mail  

server = smtplib.SMTP('smtp.gmail.com:587')
server.starttls()
server.login(username,password)
server.sendmail(froms, to, email_text)
server.quit()