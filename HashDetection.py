##############################################################
#              Hash Detection Program                        #
#                                Programmer : Raghav Bisht   #
##############################################################

import tkinter
from tkinter import *

window = Tk()
window.geometry('650x75')

def go():
    cypher = entry.get()

    if len(cypher) == 8 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == True:
        Output.set('Cypher Can Be : CRC-32 | ADLER-32 | CRC-32B | XOR-32')

    elif len(cypher) == 8 and cypher.isdigit() == True:
        Output.set('Cypher Can Be : GHash323 | GHash325')

    elif len(cypher) == 4 and cypher.isdigit() == True:
        Output.set('Cypher Is : CRC-16 ')

    elif len(cypher) == 4 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == True:
        Output.set('Cypher Can Be : CRC-16 | FCS16 | CRC-16-CCITT')

    elif len(cypher) == 13 and cypher.isdigit() == False and cypher.isalpha() == False:
        Output.set('Cypher Is : DESUnix')

    elif len(cypher) == 16 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == True:
        Output.set('Cypher Can Be : MD5Half | MD5Middle | MySQL')

    elif len(cypher) == 32 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == True:
        Output.set('Cypher Can Be : MD5 | NTLM | DomainCachedCredentials | Haval128 | Haval128HMAC | MD2 | MD2HMAC | MD4 | MD4HMAC | MD5HMAC | MD5HMACWordpress | RAdminv2x | RipeMD128 | RipeMD128HMAC | SNEFRU128 | SNEFRU128HMAC | Tiger128 | Tiger128HMAC | md5passsalt | md5saltmd5pass | md5saltpass | md5saltpasssalt | md5saltpassusername | md5saltmd5pass | md5saltmd5passsalt | md5saltmd5saltpass | md5saltmd5md5passsalt | md5username0pass | md5usernameLFpass | md5usernamemd5passsalt | md5md5pass | md5md5passsalt | md5md5passmd5salt | md5md5saltpass | md5md5saltmd5pass | md5md5usernamepasssalt | md5md5md5pass | md5md5md5md5pass | md5md5md5md5md5pass | md5sha1pass | md5sha1md5pass | md5sha1md5sha1pass | md5strtouppermd5pass')

    elif len(cypher) == 34 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == True and cypher[0:2].find('0x') == 0:
        Output.set('Cypher Is : LineageIIC4')

    elif len(cypher) == 34 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == False and cypher[0:3].find('$H$') == 0:
        Output.set('Cypher Is : MD5phpBB3')

    elif len(cypher) == 34 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == False and cypher[0:3].find('$1$') == 0:
        Output.set('Cypher Is : MD5Unix')

    elif len(cypher) == 34 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == False and cypher[0:3].find('$P$') == 0:
        Output.set('Cypher Is : MD5Wordpress')

    elif len(cypher) == 37 and cypher.isdigit() == False and cypher.isalpha() == False and cypher[0:4].find('$apr') == 0:
        Output.set('Cypher Is : MD5APR')

    elif len(cypher) == 40 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == False and cypher[0:1].find('*')==0:
        Output.set('Cypher Is : MySQL160bit')

    elif len(cypher) == 40 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum () == True:
        Output.set('Cypher Can Be : SHA1 | SHA1HMAC |sha1saltmd5passsalt | sha1saltsha1pass | sha1saltsha1saltsha1pass | SHA1MaNGOS | SHA1MaNGOS2 | sha1usernamepass | sha1sha1saltpass | sha1sha1sha1pass | sha1strtolowerusernamepass | sha1usernamepasssalt | sha1sha1passsubstrpass03 | sha1md5pass | sha1md5passsalt | sha1md5sha1pass | sha1sha1pass | sha1sha1passsalt | sha1saltmd5pass | Tiger160 | Tiger160HMAC | sha1passsalt | sha1saltpass | Haval160 | Haval160HMAC | MySQL5 | RipeMD160 | RipeMD160HMAC | ')
    
    elif len(cypher) == 48 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum () == True:
        Output.set('Cypher Can Be : Haval192 | Haval192HMAC | Tiger192 | Tiger192HMAC')

    elif len(cypher) == 49 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == False and cypher[32:33].find(':') == 0:
        Output.set('Cypher Is : MD5passsaltjoomla1')

    elif len(cypher) == 52 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == False and cypher[0:5].find('sha1$') == 0:
        Output.set('Cypher Is : SHA1Django')

    elif len(cypher) == 56 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum () == True:
        Output.set('Cypher Can Be : Haval224 | Haval224HMAC | SHA224 | SHA224HMAC')

    elif len(cypher) == 64 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum () == True:
        Output.set('Cypher Can Be : SHA256 | SHA256HMAC | Haval256 | Haval256HMAC | GOSTR341194 | RipeMD256 | RipeMD256HMAC | SNEFRU256 | SNEFRU256HMAC | SHA256md5pass | SHA256sha1pass')
    
    elif len(cypher) == 65 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum () == False and cypher[32:33].find(':') == 0:
        Output.set('Cypher Is : MD5passsaltjoomla2')
        
    elif len(cypher) == 65 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum () == False and cypher.islower() == False and cypher[32:33].find(':')==0:
        Output.set('Cypher Is : SAM')

    elif len(cypher) == 78 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == False and cypher[0:6].find('sha256') == 0:
        Output.set('Cypher Is : SHA256Django')

    elif len(cypher) == 80 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum () == True:
        Output.set('Cypher Can Be : RipeMD320 | RipeMD320HMAC')

    elif len(cypher) == 96 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum () == True:
        Output.set('Cypher Can Be : SHA384 | SHA384HMAC')

    elif len(cypher) == 98 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum () == False and cypher[0:3].find('$6$') == 0:
        Output.set('Cypher Is : SHA256s')

    elif len(cypher) == 110 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum() == False and cypher[0:6].find('sha384') == 0:
        Output.set('Cypher Is : SHA384Django')

    elif len(cypher) == 128 and cypher.isdigit() == False and cypher.isalpha() == False and cypher.isalnum () == True:
        Output.set('Cypher Can Be : SHA512 | SHA512HMAC | Whirlpool | WhirlpoolHMAC')

    else:
        Output.set('Invalid Hash Type Noob. Try Searching On Internet.')

def SetToZero():
    Cypher.set(0)

window.title('R - Security Hash Detector, By Raghav Bisht')

label2 = Label(window, text= 'Note : Paste The Cypher Text (Encrypted Text) In Text Box')
label2.place(x = 1, y = 1)

label = Label(window, text= 'Put Your Hash Noob :')
label.place(x = 1, y = 25)

label = Label(window, text= 'Your Output Noob :')
label.place(x = 1, y = 50)

Cypher = StringVar()
entry = Entry(window, textvariable = Cypher, width = 60)
entry.place(x = 120, y = 25)

Output = StringVar()
entry1 = Entry(window, textvariable = Output, width = 60)
entry1.place(x = 120, y = 50)

button1 = Button(window, text='Rock It', command = go)
button1.place(x = 500, y = 35)

button2 = Button(window, text = 'Quit It', command = window.destroy)
button2.place(x = 550, y = 35)

button3 = Button(window, text = 'Reset It', command = SetToZero).place(x=600, y=35)

window.mainloop()
