import os

def twilio():
    from twilio.rest import Client
    import getpass

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
    import smtplib
    import ssl
    import getpass
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
    import requests
    import time
    import json
    import getpass
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
    import subprocess
    comando = "Get-Process"
    lineaPS = "powershell -Executionpolicy ByPass -Command "+ comando
    runningProcesses = subprocess.check_output(lineaPS)
    print(runningProcesses.decode())
    input("'Presiona una Tecla para cerrar'")

def ScaneoPuertos():
    import subprocess
    subprocess.Popen("scanner_puertos.py -target 127.0.0.1", shell=True)

def main():
    menu="""
    1. Mandar mensaje de SMS con Twilio (API)
    2. Mandar correo electronico
    3. Escanear URLS con VIRUSTOTAL (API)
    4. Ver procesos de Computadora (PowerShell)
    5. Escaneo de Puertos

    0. Salir
    """
    print(menu)
    opc=input("Opc: ")
    if(opc=="1"):
        twilio()
    elif(opc=="2"):
        Correo()
    elif(opc=="3"):
        VirusTotalPag()
    elif(opc=="4"):
        PS()
    elif(opc=="5"):
        ScaneoPuertos()
    elif(opc=="0"):
        Correo()
    else:
        error=1

if __name__ == "__main__":
    import argparse
    description = """ Ejemplos de uso:
             + Escaneo basico:
             -target 127.0.0.1
              + Indica un puerto especifico:
             -target 127.0.0.1 -port 21
            + Indica una lista de puertos:
              -target 127.0.0.1 -port 21,22"""
    parser = argparse.ArgumentParser(description='PIA', epilog=description,
                                    formatter_class=argparse.RawDescriptionHelpFormatter)
    params = parser.parse_args()
    main()
