import os
import logging
import getpass
from twilio.rest import Client
import smtplib
import ssl
import requests
import time
import json
import subprocess
import argparse


def twilio():
    #from twilio.rest import Client
    #import getpass

    accountSID = getpass.getpass("SID: ")
    authToken = getpass.getpass("Token: ")

    twilioCli = Client(accountSID,authToken)

    myTwilioNumber = getpass.getpass("Remitente (tu número de Twilio): ")

    destCellPhone = getpass.getpass("Destinatario (agrega +52): ")
    msg=input("Coloca aqui el mensaje de Texto: ")
    message = twilioCli.messages.create(to = destCellPhone,
                                        from_ = myTwilioNumber,
                                        body = msg)
    #Información general
    print(message.to)
    print(message.from_)
    print(message.body)

    print(message.sid)
    print(message)
    print(type(message))
    print(message.status)
    print(message.date_created)
    print(message.date_sent)

def Correo():
    #import smtplib
    #import ssl
    #import getpass
    i=0
    port = 587  # For starttls
    smtpserver=('')
    correoEnvio=input('Ingresa tu correo electronico: ')
    correoReceptor=input('Ingresa el correo electronico a que se le enviara el mensaje: ')
    for caracter in correoEnvio:
        if i == 1:
            smtpserver=(smtpserver+caracter)
        if caracter == '@':
            i=1
    smtp_server = "smtp."+smtpserver
    password = getpass.getpass()
    asunto=input('Ingresa el asunto de correo: ')
    cuerpo=input('Ingresa el cuerpo de correo: ')
    mensaje = """\
    Subject: """+asunto+"""

    """+cuerpo+""" """

    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_server, port) as server:
        server.ehlo()  # Can be omitted
        server.starttls(context=context)
        server.ehlo()  # Can be omitted
        server.login(correoEnvio, password)
        server.sendmail(correoEnvio, correoReceptor, mensaje)

def VirusTotalPag():
    #import requests
    #import time
    #import json
    #import getpass
    indicators = []
    opcc="1"
    while opcc == "1":
        web=input("Ingresa el URL que quieres analizar: ")
        indicators.append(web)
        opcc=input("¿Quieres agregar otra URL?\n1.- SI\nCalquier caracter.- NO\nOpc:  ")
        os.system("cls")

    api_key = getpass.getpass("Ingresa API")
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    os.system("cls")
    print("......Tardara 15 segundos por cada sitio web......")
    for site in indicators:
        params = {'apikey':api_key, 'resource':site}
        response = requests.get(url, params=params)
        response_json = json.loads(response.content)

        if response_json['positives'] <= 0:
            with open('vt_result.txt', 'a') as vt:
                vt.write(site) and vt.write('\t'+"NOT MALICIOUS"+'\n')

        elif 1 >= response_json['positives'] >= 3:
            with open('vt_result.txt', 'a') as vt:
                vt.write(site) and vt.write('\t'+"MAYBE MALICIOUS"+'\n')
    
        elif response_json['positives'] >= 4:
            with open('vt_result.txt', 'a') as vt:
                vt.write(site) and vt.write('\t'+"MALICIOUS"+'\n')

        else:
            print('url not found')

        time.sleep(15)
        print("Revisa en la carpeta, y abre 'vt_result.txt' para ver los resultados.")

def PS():
    #import subprocess
    comando = "Get-Process"
    lineaPS = "powershell -Executionpolicy ByPass -Command "+ comando
    runningProcesses = subprocess.check_output(lineaPS)
    print(runningProcesses.decode())

def ScaneoPuertos():
    #import subprocess
    logging.warning('Si no se eligen la IP o Puertos. Se utilizaran las basicas')

    principal="scanner_puertos.py "
    puerto="-port"
    portT=""
    opc1=input("¿Quieres agregar una IP?\n 1. SI\nCualquier caracter. NO\nOpc: ")
    if opc1 == "1":
        ip=input("IP: ")
    else:
        ip="127.0.0.1"
    principal=principal+"-target "+ip+" "

    opc2=str(input("¿Quieres agregar puertos?\n 1. SI\nCualquier caracter. NO\nOpc: "))
    if opc2 != "1":
        puerto= " "
    principal = principal + puerto
    while opc2=="1": 
        port=input("Puerto: ")
        if portT == "":
            portT=portT+" "+port
        else:
            portT=portT+","+port
        opc3=str(input("¿Quieres agregar otro puerto?\n 1. SI\nCualquier caracter. NO\nOpc: "))
        if opc3 != "1":
            opc2= " "
    principal = principal + portT
    subprocess.Popen("scanner_puertos.py -target 127.0.0.1", shell=True)

def main():
    error=0
    os.system("cls")
    menu="""
    1. Mandar mensaje de SMS con Twilio (API)
    2. Mandar correo electronico
    3. Escanear URLS con VIRUSTOTAL (API)
    4. Ver procesos de Computadora (PowerShell)
    5. Escaneo de Puertos
    
    """
    print(menu)
    while error==0:
        opc=input("Opc: ")
        if(opc=="1"):
            twilio()
            error=1
        elif(opc=="2"):
            Correo()
            error=1
        elif(opc=="3"):
            VirusTotalPag()
            error=1
        elif(opc=="4"):
            PS()
            error=1
        elif(opc=="5"):
            ScaneoPuertos()
            error=1
        else:
            error=0
            print("Error en el caracter. Introducelo denuevo")
    
if __name__ == "__main__":
    #import argparse

    description = """ Ejemplos de uso DEFAULT:
            Poner un numero para elegir lo quieres hacer con el programa
            1. Mandar mensaje de SMS con Twilio (API)
            2. Mandar correo electronico
            3. Escanear URLS con VIRUSTOTAL (API)
            4. Ver procesos de Computadora (PowerShell)
            5. Escaneo de Puertos

            Ejemplo de uso con 'argparse':
            -p 1 o sms. Mandar mensaje de SMS con Twilio (API)
            -p 2 o correo. Mandar correo electronico
            -p 3 o vt. Escanear URLS con VIRUSTOTAL (API)
            -p 4 o procesos. Ver procesos de Computadora (PowerShell)
            -p 5 o puertos. Escaneo de Puertos

            Ejemplo:
            -p 1
            -p sms
            
            -p 2
            -p correo
            
            -p 3
            -p vt
            
            -p 4
            -p procesos
            
            -p 5
            -p puertos
            """
    parser = argparse.ArgumentParser(description='PIA', epilog=description,
                                    formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('-p',dest='proc',choices=['1','sms','2','correo','3','vt','4','procesos','5','puertos'])
    #, action='store_true'
    params = parser.parse_args()
    p = params.proc
    if p == ('1') or p ==('sms'):
        twilio()
    elif p == ('2') or p ==('correo'):
        Correo()
    elif p == ('3') or p ==('vt'):
        VirusTotalPag()
    elif p == ('4') or p ==('procesos'):
        PS()
    elif p == ('5') or p ==('puertos'):
        ScaneoPuertos()
    else:
        main()
input("'Presiona una Tecla para cerrar'")
