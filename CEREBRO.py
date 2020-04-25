from tkinter import *
from tkinter import ttk
from reportlab.platypus import Paragraph
from reportlab.platypus import Image
from reportlab.platypus import SimpleDocTemplate
from reportlab.platypus import Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from tkinter import scrolledtext
import webbrowser
import socket
import json
import requests
import dns
import dns.resolver
import dns.name
import dns.query
import dns.zone
import dns.reversename
import whois
import os
import datetime
import configparser

#APIs------------------------------------------------------------------------------------------------
cParser = configparser.RawConfigParser()
dirArchivo = os.path.abspath(os.path.dirname(sys.argv[0])) + '/Configuraciones.txt'
cParser.read(dirArchivo)

apiHunter = cParser.get('APIKeys', 'apiHunter')
apiShodan = cParser.get('APIKeys', 'apiShodan')
apiIpnfodb = cParser.get('APIKeys', 'apiIpnfodb')
apiVirusTotal = cParser.get('APIKeys', 'apiVirusTotal')
tokenSpy = cParser.get('APIKeys', 'tokenSpy')
apiBing = cParser.get('APIKeys', 'apiBing')
apiHIBP = cParser.get('APIKeys', 'apiHIBP')

#DiseñoVentana-----------------------------------------------------------------------------
ventPcpal=Tk()    
ventPcpal.title('CEREBRO v1.0 - AN OPEN SOURCE INTELLIGENCE TOOL')
ventPcpal.resizable(0,0)
ventPcpal.geometry("1330x700")
ventPcpal.iconbitmap("brain.ico");
ventPcpal.config(bg="#ffffff")

#PESTAÑAS--------------------------------------------------------------------
ctrlPestañas = ttk.Notebook()

pstMail=ttk.Frame(ctrlPestañas)
pstEnt=ttk.Frame(ctrlPestañas)
pstGH=ttk.Frame(ctrlPestañas)
pstConf=ttk.Frame(ctrlPestañas)

pstMail_image=PhotoImage(file="mail.png")
pstEnt_image=PhotoImage(file="web.png")
pstGH_image=PhotoImage(file="gh.png")
pstConf_image=PhotoImage(file="conf.png")

ctrlPestañas.add(pstMail, text="MailINT", image=pstMail_image, compound=LEFT)
ctrlPestañas.add(pstEnt, text="WebINT", image=pstEnt_image, compound=LEFT)
ctrlPestañas.add(pstGH, text="Google Hacking", image=pstGH_image, compound=LEFT)
ctrlPestañas.add(pstConf, text="Ajustes", image=pstConf_image, compound=LEFT)

ctrlPestañas.pack(expand=1, fill="both")

#FUNCIONES #

#FUNCIONES DE BUSQUEDA DE CORREOS ELECTRONICOS-----------------------------------------------------------U||
#INFORMACION DE CORREOS EN HAVE I BEEEN PWND
def mailHIBP(correo):
     urlHIBP = 'https://haveibeenpwned.com/api/v3/breachedaccount/' + correo + '?truncateResponse=false'
     rHIBP      =   requests.get(urlHIBP, headers={'hibp-api-key':apiHIBP})
     if rHIBP.status_code!=200:
         boxMailHIBP.insert(INSERT, "Bad request\n")
     if rHIBP.status_code==200:
         rHIBP_json=json.loads(rHIBP.text)
         cantHIBP = str(len(rHIBP_json))
         boxMailHIBP.insert(INSERT, "Se han encontrado "+cantHIBP+" coincidencias del correo "+correo+" en brechas de seguridad \n")
         c=0
         for elemHIBP in rHIBP_json:
             c=c+1
             varName=elemHIBP['Name']
             varTitle=elemHIBP['Title']
             varDomain=elemHIBP['Domain']
             varDate=elemHIBP['BreachDate']
             boxMailHIBP.insert(INSERT, c)
             boxMailHIBP.insert(INSERT," - "+varName+"\n")
             boxMailHIBP.insert(INSERT,"Titulo: "+varTitle+"\n")
             boxMailHIBP.insert(INSERT,"Dominio: "+varDomain+"\n")
             boxMailHIBP.insert(INSERT,"Fecha: "+varDate+"\n")
             boxMailHIBP.insert(INSERT,"\n")

#INFORMACION DE CORREOS EN PASTEDUMP
def mailPaste(correo):
     urlPaste = 'https://psbdmp.ws/api/search/email/' + correo
     rPaste = requests.get(urlPaste)
     if rPaste.status_code != 200:
          boxMailPastes.insert(INSERT, "Algo salió mal\n")
     if rPaste.status_code == 200:
          rPaste_json = json.loads(rPaste.text)
          cantPaste = str(rPaste_json['count'])
          boxMailPastes.insert(INSERT,"Se han encontrado " + cantPaste + " coincidencias del correo " + correo + " en Pastes \n")
          c = 0
          for elemPaste in rPaste_json['data']:
               c = c + 1
               ident = elemPaste['id']
               tags = elemPaste['tags']
               time = elemPaste['time']
               boxMailPastes.insert(INSERT, c)
               boxMailPastes.insert(INSERT, " - Encontrado en: http://pastebin.com/" + ident + "\n")
               boxMailPastes.insert(INSERT, "Tipo: " + tags + "\n")
               boxMailPastes.insert(INSERT, "Fecha: " + time + "\n")
               boxMailPastes.insert(INSERT, "\n")

#INFORMACION DE CORREOS EN EMAIL HUNTER
def mailHunter(correo):
     urlHunter = 'https://api.hunter.io/v2/email-verifier?email=' + correo + '&api_key=' + apiHunter
     rHunter = requests.get(urlHunter)
     if rHunter.status_code != 200:
          boxMailHunt.insert(INSERT, "No hay resultados en Email Hunter\n")
     if rHunter.status_code == 200:
          rHunter_json = json.loads(rHunter.text)
          cantHunter = str(len(rHunter_json['data']['sources']))
          boxMailHunt.insert(INSERT,"Se han encontrado " + cantHunter + " coincidencias del correo " + correo + " en la web \n")
          estado = rHunter_json['data']['result']
          puntuacion = str(rHunter_json['data']['score'])
          aceptaCorreos = str(rHunter_json['data']['accept_all'])
          estadoServer = str(rHunter_json['data']['mx_records'])
          tipoCorreo = str(rHunter_json['data']['webmail'])
          boxMailHunt.insert(INSERT, "Estado:" + estado + "\n")
          boxMailHunt.insert(INSERT, "Puntuación: " + puntuacion + "\n")
          boxMailHunt.insert(INSERT, "Acepta correos? " + aceptaCorreos + "\n")
          boxMailHunt.insert(INSERT, "Estado del servidor? " + estadoServer + "\n")
          boxMailHunt.insert(INSERT, "Tipo de correo: " + tipoCorreo + "\n")
          boxMailHunt.insert(INSERT, "\n")
          c = 0
          for elemHunter in rHunter_json['data']['sources']:
               c = c + 1
               dominio = elemHunter['domain']
               uri = elemHunter['uri']
               fVisto = elemHunter['last_seen_on']
               boxMailHunt.insert(INSERT, c)
               boxMailHunt.insert(INSERT, " - Dominio: " + dominio + "\n")
               boxMailHunt.insert(INSERT, "URL: " + uri + "\n")
               boxMailHunt.insert(INSERT, "Visto: " + fVisto + "\n")
               boxMailHunt.insert(INSERT, "\n")

#---------------------------------------------------------------------------------------------
#FUNCIONES DE BUSQUEDA DE ENTIDADES-----------------------------------------------------------U||
#BUSQUEDAS EN SHODAN
def entiShodan(ip, apiShodan):
     urlShodanInfo='https://api.shodan.io/shodan/host/'+ip+'?key='+apiShodan
     rShodan = requests.get(urlShodanInfo)
     if rShodan.status_code!=200:
          error="algo salio mal"
     if rShodan.status_code==200:
          rShodan_json=json.loads(rShodan.text)

          hostnames=rShodan_json['hostnames']
          boxHostname.insert(INSERT, hostnames)

          codigoPais=str(rShodan_json['country_code'])
          boxCodPais.insert(INSERT, codigoPais)

          Pais=str(rShodan_json['country_name'])
          boxPais.insert(INSERT, Pais)

          ciudad=str(rShodan_json['city'])
          boxCiudad.insert(INSERT, ciudad)

          ISP=str(rShodan_json['isp'])
          boxISP.insert(INSERT, ISP)

          org=str(rShodan_json['org'])
          boxOrganizacion.insert(INSERT, org)

          latitud=str(rShodan_json['latitude'])
          boxLatitud.insert(INSERT, latitud)

          longitud=str(rShodan_json['longitude'])
          boxLongitud.insert(INSERT,longitud)

          ultimaActualizacion=str(rShodan_json['last_update'])
          boxActualizado.insert(INSERT, ultimaActualizacion)

          SO=str(rShodan_json['os'])
          boxSO.insert(INSERT, SO)
          try:
               vulnerabilidades = rShodan_json['vulns']
               boxVulnerabilidades.insert(INSERT, vulnerabilidades)
          except:
               boxVulnerabilidades.insert(INSERT, "No hay vulnerabilidades")

          try:
               puertos = rShodan_json['ports']
               boxPuertos.insert(INSERT, puertos)
          except:
               boxPuertos.insert(INSERT, "No se detectan puertos abiertos")

#INFORMACION DE DNS CON DNSPYTHON
def entiDNS(dominio):
     SrvCorreos=dns.resolver.query(dominio, 'MX')
     SrvName=dns.resolver.query(dominio, 'NS')
     SrvIpv4=dns.resolver.query(dominio, 'A')

     boxDNSInfo.insert(INSERT,"Información de Correos: \n"+SrvCorreos.response.to_text())
     boxDNSInfo.insert(INSERT,"\nInformación de Servidor: \n"+SrvName.response.to_text())
     boxDNSInfo.insert(INSERT,"\nInformación de IPV4: \n"+SrvIpv4.response.to_text())

#INFORMACION DE HEADERS
def entiHeaders(dominio):
     rHeaders=requests.get("http://"+dominio, allow_redirects=False)
     if rHeaders.status_code!=301:
          boxHeaders.insert(INSERT,"No se pueden extraer los Headers")
     if rHeaders.status_code==301:
          boxHeaders.insert(INSERT, rHeaders.headers)

#INFORMACION DE PASTES
def entiPasteDump(dominio):
     urlPasteD='https://psbdmp.ws/api/search/domain/'+dominio
     rPasteD = requests.get(urlPasteD)
     if rPasteD.status_code!=200:
          error="algo salio mal"
     if rPasteD.status_code==200:
          rPasteD_json=json.loads(rPasteD.text)
          registros=str(rPasteD_json['count'])
          boxPastes.insert(INSERT,"Se ha encontrado: "+registros+" resultados en pastebin\n")
          c=0
          for data in rPasteD_json['data']:
               c=c+1
               ident=data['id']
               tags=data['tags']
               time=data['time']
               boxPastes.insert(INSERT,c)
               boxPastes.insert(INSERT,"-Paste: https://pastebin.com/"+ident+"\n")
               boxPastes.insert(INSERT,"Contiene: "+tags+"\n")
               boxPastes.insert(INSERT,"Fecha: "+time+"\n")

#INFORMACION CON EHUNTER
def entehunter(dominio, apiHunter):
     urlHunterEnti = 'https://api.hunter.io/v2/domain-search?domain=' + dominio + '&api_key=' + apiHunter + '&limit=100'
     rHunterEnti = requests.get(urlHunterEnti)
     if rHunterEnti.status_code == 200:
          rHunterEnti_json = json.loads(rHunterEnti.text)
          desechable = rHunterEnti_json['data']['disposable']
          tipoCorreo = rHunterEnti_json['data']['webmail']
          patronCorreos = rHunterEnti_json['data']['pattern']
          cantidadCorreos = len(rHunterEnti_json['data']['emails'])

          boxDisposable.insert(INSERT, desechable)
          boxWebmail.insert(INSERT,tipoCorreo)
          boxPatronCorreo.insert(INSERT, patronCorreos)

          c = 0
          for mail in rHunterEnti_json['data']['emails']:
               c = c + 1
               correo = mail['value']
               nombre = mail['first_name']
               apellido = mail['last_name']
               tipo = mail['type']
               area = mail['department']
               telefono = mail['phone_number']
               boxMails.insert(INSERT, c, correo, nombre, apellido, tipo, area, telefono)

#INFORMACION DE WHOIS
def entiWhois(dominio):
     try:
          varWhois = whois.whois(dominio)
          boxWHOIS.insert(INSERT, varWhois)
     except:
          boxWHOIS.insert(INSERT, "No se encuentra información de WHOIS")

#INFORMACION CON IPINFODB
def entiIpinfodb(ip, apiIpnfodb):
     urlIpInfodb = 'http://api.ipinfodb.com/v3/ip-city/?key=' + apiIpnfodb + '&ip=' + ip+ "&format=json"
     rIpInfodb = requests.get(urlIpInfodb)
     if rIpInfodb.status_code == 200:
          rIpInfodb_json = json.loads(rIpInfodb.text)

          dbRegion = rIpInfodb_json['regionName']
          dbZip = rIpInfodb_json['zipCode']
          dbtime = rIpInfodb_json['timeZone']

          boxRegion.insert(INSERT, dbRegion)
          boxZonaHoraria.insert(INSERT, dbtime)
          boxCodPostal.insert(INSERT, dbZip)

#INFORMACION CON VIRUSTOTAL
def entiVTInfo(dominio,apiVirusTotal):
     urlVTInfo = 'https://www.virustotal.com/vtapi/v2/url/report?apikey=' + apiVirusTotal + '&resource=' + dominio + '&allinfo=true'
     rVTInfo = requests.get(urlVTInfo)

     if rVTInfo.status_code != 200:
          print("algo salio mal")

     if rVTInfo.status_code == 200:
          rVTInfo_json = json.loads(rVTInfo.text)
          fecha_scan = rVTInfo_json['scan_date']
          enlace_scan = rVTInfo_json['permalink']
          positi_scan = rVTInfo_json['positives']
          t_scan = rVTInfo_json['total']

          boxFechaEscaneo.insert(INSERT, fecha_scan)
          boxEnlaceEscaneo.insert(INSERT, enlace_scan)
          boxPositivos.insert(INSERT, positi_scan)
          boxAntivirus.insert(INSERT, t_scan)

def entiVTDom(dominio,apiVirusTotal):
     urlVTDom = 'https://www.virustotal.com/vtapi/v2/domain/report?apikey='+apiVirusTotal+'&domain='+dominio
     rVTDom = requests.get(urlVTDom)
     if rVTDom.status_code == 200:
          rVTDom_json = json.loads(rVTDom.text)
          categoria=rVTDom_json['categories']
          webutation=rVTDom_json['Webutation domain info']['Verdict']
          subds=rVTDom_json['subdomains']
          for sb in subds:
               a = sb
               boxSubdominios.insert(INSERT, a+"\n")

          boxCategoria.insert(INSERT, categoria)
          boxReputacion.insert(INSERT, webutation)

#INFORMACION CON ROBTEX
def entiRobtex(ip):
     urlRobtex = 'https://freeapi.robtex.com/ipquery/' + ip
     imgRuta = 'https://gfx.robtex.com/gfx/graph.png?ip=' + ip
     rRobtex = requests.get(urlRobtex)
     if rRobtex.status_code != 200:
          error = "algo salio mal"

     if rRobtex.status_code == 200:
          rRobtex_json = json.loads(rRobtex.text)
          sistemaAutonomoBGP = rRobtex_json['as']
          asname = rRobtex_json['asname']
          bgproute = rRobtex_json['bgproute']

          boxAS.insert(INSERT, sistemaAutonomoBGP)
          boxASName.insert(INSERT, asname)
          boxBGP.insert(INSERT, bgproute)

#INFORMACION CON SPYONWEB
def entiSpy(ip, tokenSpy):
     urlTokenSpy = "https://api.spyonweb.com/v1/ip/" + ip + "?access_token=" + tokenSpy
     rSpy = requests.get(urlTokenSpy)
     if rSpy.status_code != 200:
          return
     if rSpy.status_code == 200:
          rSpy_json = json.loads(rSpy.text)
          if rSpy_json['status']=="not_found":
               a="no hay mas dominios"
               boxDominios.insert(INSERT, a)
          else:
               encontrados = rSpy_json['result']['ip'][ip]['found']
               c = 0
               for spy in rSpy_json['result']['ip'][ip]['items']:
                    c = c + 1
                    a = spy
                    boxDominios.insert(INSERT, c)
                    boxDominios.insert(INSERT, "-"+a+"\n")

#PESTAÑA DE CORREO------------------------------------------------------------
lblFramMail = LabelFrame(pstMail)
lblFramMail.config(bg="#ffffff", bd=0)
lblFramMail.pack( fill="x")

lblMail = Label(lblFramMail, text = "CORREO ELECTRONICO", font=20)
lblMail.config(foreground="#913535", bg="#ffffff")
lblMail.pack(pady=20)

boxMail = Entry(lblFramMail, width = 100, justify="center", font=20)
boxMail.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE)
boxMail.pack(padx=50)

def buscarCorreo():
     #borrar el contenido
     boxMailHunt.delete(0.0, 'end')
     boxMailPastes.delete(0.0, 'end')
     boxMailHIBP.delete(0.0, 'end')

     boxMailHunt.tag_add('highlightline', INSERT)
     boxMailHunt.tag_add('resultado', INSERT)

     boxMailHunt.tag_configure('highlightline', font='helvetica 14 bold')
     boxMailHunt.tag_configure('resultado', font='helvetica 10')

     correo=boxMail.get()
     try:
          mailHIBP(correo)
     except:
          print("HAY UN ERROR EN HAVEIBEENPWND")

     try:
          mailPaste(correo)
     except:
          print("HAY UN ERROR EN LOS PASTES")

     try:
          mailHunter(correo)
     except:
          print("HAY UN ERROR EN MAILHUNTER")

btnMail=Button(lblFramMail, text="Buscar", command=buscarCorreo)
btnMail.config(bg="#ff8b00", bd=0, activebackground="#1cb3c8", activeforeground="#ffffff", font=20)
btnMail.pack(pady=20)

lblFramMail2 = LabelFrame(pstMail)
lblFramMail2.config(bg="#FFFFFF", bd=0)
lblFramMail2.pack(expand=1, fill="both")

#COLUMNA 1
lblMailHunt = Label(lblFramMail2, text="INFORMACION", font=12)
lblMailHunt.config(foreground="#000000", bg="#ffffff")
lblMailHunt.grid(column=0, row=0, sticky='W', pady=5, padx=10)
boxMailHunt=scrolledtext.ScrolledText(lblFramMail2, width = 50)
boxMailHunt.config(bd=2, foreground="#3c415e", bg="#FFFFFF", relief=GROOVE, wrap=WORD)
boxMailHunt.grid(column=0, row=1, sticky='W', pady=5, padx=10)

#COLUMNA 2
lblMailHIBP = Label(lblFramMail2, text="BRECHAS DE SEGURIDAD", font=12)
lblMailHIBP.config(foreground="#000000", bg="#ffffff")
lblMailHIBP.grid(column=1, row=0, sticky='W', pady=5, padx=10)
boxMailHIBP=scrolledtext.ScrolledText(lblFramMail2, width = 50)
boxMailHIBP.config(bd=2, foreground="#3c415e", bg="#FFFFFF", relief=GROOVE, wrap=WORD)
boxMailHIBP.grid(column=1, row=1, sticky='W', pady=5, padx=10)

#COLUMNA 3
lblMailPastes = Label(lblFramMail2, text="PASTES", font=12)
lblMailPastes.config(foreground="#000000", bg="#ffffff")
lblMailPastes.grid(column=2, row=0, sticky='W', pady=5, padx=10)
boxMailPastes=scrolledtext.ScrolledText(lblFramMail2, width = 50)
boxMailPastes.config(bd=2, foreground="#3c415e", bg="#FFFFFF", relief=GROOVE, wrap=WORD)
boxMailPastes.grid(column=2, row=1, sticky='W', pady=5, padx=10)


#PESTAÑA DE ENTIDAD------------------------------------------------------------
lblFramEnti2 = LabelFrame(pstEnt)
lblFramEnti2.config(bg="#e8e8e8", bd=0)
lblFramEnti2.pack(fill="x")

lblEnti = Label(lblFramEnti2, text="DOMINIO OBJETIVO:", font=12)
lblEnti.config(foreground="#913535", bg="#e8e8e8")
lblEnti.pack(pady=20, padx=5, side=LEFT)

boxEnti = Entry(lblFramEnti2, justify="center", font=20)
boxEnti.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE)
boxEnti.pack(side=LEFT)

def busquedas():
     #limpiar campos
     boxDominios.delete(0.0, 'end')
     boxSubdominios.delete(0.0, 'end')
     boxReputacion.delete(0, 'end')
     boxCodPostal.delete(0, 'end')
     boxURL.delete(0, 'end')
     boxBGP.delete(0, 'end')
     boxASName.delete(0, 'end')
     boxAS.delete(0, 'end')
     boxCategoria.delete(0, 'end')
     boxAntivirus.delete(0, 'end')
     boxPositivos.delete(0, 'end')
     boxEnlaceEscaneo.delete(0, 'end')
     boxFechaEscaneo.delete(0, 'end')
     boxZonaHoraria.delete(0, 'end')
     boxRegion.delete(0, 'end')
     boxWHOIS.delete(0.0, 'end')
     boxPatronCorreo.delete(0, 'end')
     boxWebmail.delete(0, 'end')
     boxDisposable.delete(0, 'end')
     boxMails.delete(0.0, 'end')
     boxPastes.delete(0.0, 'end')
     boxHeaders.delete(0.0, 'end')
     boxDNSInfo.delete(0.0, 'end')
     boxPuertos.delete(0, 'end')
     boxVulnerabilidades.delete(0.0, 'end')
     boxSO.delete(0, 'end')
     boxActualizado.delete(0, 'end')
     boxLongitud.delete(0, 'end')
     boxLatitud.delete(0, 'end')
     boxOrganizacion.delete(0, 'end')
     boxCiudad.delete(0, 'end')
     boxPais.delete(0, 'end')
     boxCodPais.delete(0, 'end')
     boxHostname.delete(0, 'end')
     boxISP.delete(0, 'end')
     boxIP.delete(0, 'end')

     dominio=boxEnti.get()
     ip=socket.gethostbyname(dominio)

     boxURL.insert(INSERT, dominio)
     boxIP.insert(INSERT, ip)

     try:
          entiVTInfo(dominio, apiVirusTotal)
     except:
          print("HAY UN ERROR EN virustotal1")
     try:
          entiVTDom(dominio, apiVirusTotal)
     except:
          print("HAY UN ERROR EN virustotal2")
     try:
          entiShodan(ip, apiShodan)
     except:
          print("HAY UN ERROR EN SHODAN")
     try:
          entiDNS(dominio)
     except:
          print("HAY UN ERROR EN LOS DNS")
     try:
          entiHeaders(dominio)
     except:
          print("HAY UN ERROR EN LOS HEADERS")
     try:
          entiPasteDump(dominio)
     except:
          print("HAY UN ERROR EN LOS PASTES")
     try:
          entehunter(dominio, apiHunter)
     except:
          print("HAY UN ERROR EN EHUNTER")
     try:
          entiWhois(dominio)
     except:
          print("HAY UN ERROR EN WHOIS")
     try:
          entiIpinfodb(ip, apiIpnfodb)
     except:
          print("HAY UN ERROR EN LOS IPINFODB")
     try:
          entiRobtex(ip)
     except:
          print("HAY UN ERROR EN LOS ROBTEX")
     try:
          entiSpy(ip, tokenSpy)
     except:
          print("HAY UN ERROR EN LOS ENTISPY")

def generarReporte():
     RP_IP=boxIP.get()
     RP_Dominio=boxURL.get()
     RP_Dominios=boxDominios.get(1.0, END)
     RP_Subdominios=boxSubdominios.get(1.0, END)
     RP_Reputacion=boxReputacion.get()
     RP_CodPostal=boxCodPostal.get()
     RP_BGP=boxBGP.get()
     RP_ASName=boxASName.get()
     RP_AS=boxAS.get()
     RP_Categoria=boxCategoria.get()
     RP_Antivirus=boxAntivirus.get()
     RP_Positivos=boxPositivos.get()
     RP_EnlaceVT=boxEnlaceEscaneo.get()
     RP_FechaEscan=boxFechaEscaneo.get()
     RP_ZonaHora=boxZonaHoraria.get()
     RP_Region=boxRegion.get()
     RP_WHOIS=boxWHOIS.get(1.0, END)
     RP_Patron=boxPatronCorreo.get()
     RP_Webmail=boxWebmail.get()
     RP_Desechable=boxDisposable.get()
     RP_Correos=boxMails.get(1.0, END)
     RP_Pastes=boxPastes.get(1.0, END)
     RP_Headers=boxHeaders.get(1.0, END)
     RP_DNS=boxDNSInfo.get(1.0, END)
     RP_Puertos=boxPuertos.get()
     RP_Vulnerabilidades=boxVulnerabilidades.get(1.0, END)
     RP_SO=boxSO.get()
     RP_Actualizado=boxActualizado.get()
     RP_Longitud=boxLongitud.get()
     RP_Latitud=boxLatitud.get()
     RP_Org=boxOrganizacion.get()
     RP_Ciudad=boxCiudad.get()
     RP_Pais=boxPais.get()
     RP_CodPais=boxCodPais.get()
     RP_Hostname=boxHostname.get()
     RP_ISP=boxISP.get()
#--------------------------------------------------------------------------------------------------------------------------

     HojaStilo = getSampleStyleSheet()
     story = []

     #definicion de estilos de texto
     head1 = HojaStilo['Heading1']
     head1.pageBreakBefore=0
     head1.keepWithNext=0
     head2 = HojaStilo['Heading2']
     titulos = HojaStilo['Heading3']
     titulos.backColor="#f9f8eb"
     estiloTexto = HojaStilo['BodyText']

     #HORA
     x = datetime.datetime.now()
     horaActual=str(x.hour)+":"+str(x.minute)+":"+str(x.second)
     fechaActual=str(x.day)+"/"+str(x.month)+"/"+str(x.year)
     nomb_hora=str(x.hour)+str(x.minute)+str(x.second)+str(x.year)+str(x.month)+str(x.day)

     #NOMBRE DEL DOCUMENTO
     nombredoc=RP_Dominio+nomb_hora+".pdf"

     #ENCABEZADOS
     encReporte= Paragraph("Reporte de Inteligencia del sitio: "+RP_Dominio, head1)
     encFecha = Paragraph("Generado el "+fechaActual+" a las "+horaActual, head2)
     story.append(encReporte)
     story.append(encFecha)

     #GENERALIDADES
     titGeneralidades=Paragraph("GENERALIDADES", titulos)
     textIP = Paragraph("Direccion IP: "+RP_IP, estiloTexto)
     textCategoria=Paragraph("Categoria del sitio: "+RP_Categoria, estiloTexto)
     textReputacion=Paragraph("Reputación del sitio: "+RP_Reputacion, estiloTexto)
     textActualizacion=Paragraph("El sitio se actualizó la última vez el: "+RP_Actualizado, estiloTexto)
     textOrg=Paragraph("Organizacion: "+RP_Org, estiloTexto)
     story.append(titGeneralidades)
     story.append(textIP)
     story.append(textCategoria)
     story.append(textReputacion)
     story.append(textActualizacion)
     story.append(textOrg)

     #LOCALIZACION

     urlMapa = "https://dev.virtualearth.net/REST/v1/Imagery/Map/Road/" + RP_Latitud + "," + RP_Longitud + "/14?ms=530,250&od=1&c=es-XL&key=" + apiBing
     nImg2 = "geo_" + RP_Dominio + ".jpg"
     imgMapa = requests.get(urlMapa).content
     with open(nImg2, 'wb') as handler:
          handler.write(imgMapa)
     titLocalizacion=Paragraph("LOCALIZACION", titulos)
     imagenMapa = Image(("geo_"+RP_Dominio+".jpg"),width=530,height=250)
     textPais = Paragraph("Pais: "+RP_Pais, estiloTexto)
     textRegion = Paragraph("Región: "+RP_Region, estiloTexto)
     textCiudad = Paragraph("Ciudad: "+RP_Ciudad, estiloTexto)
     textCod = Paragraph("Codigo de Pais: "+RP_CodPais, estiloTexto)
     textPostal = Paragraph("Codigo Postal: "+RP_CodPostal, estiloTexto)
     textZona = Paragraph("Zona Horaria: "+RP_ZonaHora, estiloTexto)
     textLatitud = Paragraph("Latitud: "+RP_Latitud, estiloTexto)
     textLongitud = Paragraph("Longitud: "+RP_Longitud, estiloTexto)
     story.append(titLocalizacion)
     story.append(imagenMapa)
     story.append(textPais)
     story.append(textRegion)
     story.append(textCiudad)
     story.append(textCod)
     story.append(textPostal)
     story.append(textZona)
     story.append(textLatitud)
     story.append(textLongitud)

     #SEGURIDAD
     titSeguridad=Paragraph("SEGURIDAD", titulos)
     textPuertos = Paragraph("Puertos abiertos encontrados: "+RP_Puertos, estiloTexto)
     textEscaneado = Paragraph("El sitio web fue escaneado por "+RP_Antivirus+" antivirus el "+RP_FechaEscan+" y se encontraron "+RP_Positivos+" positivos", estiloTexto)
     textEnlaceVT = Paragraph("Detalles del Analisis: "+RP_EnlaceVT, estiloTexto)
     textVulnerabilidades = Paragraph("Vulnerabilidades encontradas: "+RP_Vulnerabilidades, estiloTexto)
     story.append(titSeguridad)
     story.append(textPuertos)
     story.append(textEscaneado)
     story.append(textEnlaceVT)
     story.append(textVulnerabilidades)

     #INFORMACION DE LA RED
     urlRed = "https://gfx.robtex.com/gfx/graph.png?dns=" + RP_Dominio
     nImg = "red_" + RP_Dominio + ".jpg"
     imgRed = requests.get(urlRed).content
     with open(nImg, 'wb') as handler:
          handler.write(imgRed)
     titInfoRed=Paragraph("INFORMACION DE RED", titulos)
     textSA = Paragraph("Sistema Autonomo: "+RP_AS, estiloTexto)
     textASName = Paragraph("Nombre del Sistema Autonomo: "+RP_ASName, estiloTexto)
     textISP = Paragraph("Proveedor de Servicios de Internet: "+RP_ISP, estiloTexto)
     textHostname = Paragraph("Hostname: "+RP_Hostname, estiloTexto)
     textBGP = Paragraph("BGP: "+RP_BGP, estiloTexto)
     imagenRed = Image(("red_"+RP_Dominio+".jpg"),width=530,height=250)
     story.append(titInfoRed)
     story.append(textSA)
     story.append(textASName)
     story.append(textISP)
     story.append(textHostname)
     story.append(textBGP)
     story.append(imagenRed)

     #INFORMACION DEL HOST
     titInfoHost=Paragraph("INFORMACION DE HOST", titulos)
     textSO = Paragraph("Sistema Operativo detectado: "+RP_SO, estiloTexto)
     textHeaders = Paragraph("Headers: "+RP_Headers, estiloTexto)
     story.append(titInfoHost)
     story.append(textSO)
     story.append(textHeaders)

     #INFORMACION DEL CORREO ELECTRONICO
     titInfoMail=Paragraph("CORREO ELECTRONICO", titulos)
     textPatron = Paragraph("Patrón utilizado para la creación de correos: "+RP_Patron, estiloTexto)
     textDesechable = Paragraph("Correo desechable: "+RP_Desechable, estiloTexto)
     textWebmail = Paragraph("webmail: "+RP_Webmail, estiloTexto)
     textCorreos = Paragraph("Correos encontrados: "+RP_Correos, estiloTexto)
     story.append(titInfoMail)
     story.append(textPatron)
     story.append(textDesechable)
     story.append(textWebmail)
     story.append(textCorreos)

     #WHOIS
     titInfoWHOIS=Paragraph("WHOIS", titulos)
     textWHOIS = Paragraph(RP_WHOIS, estiloTexto)
     story.append(titInfoWHOIS)
     story.append(textWHOIS)

     #DNS
     titInfoDNS=Paragraph("INFORMACION DE DNS", titulos)
     textDNS = Paragraph(RP_DNS, estiloTexto)
     story.append(titInfoDNS)
     story.append(textDNS)

     #PASTES
     titInfoPastes=Paragraph("PASTES ENCONTRADOS", titulos)
     textPASTES=Paragraph(RP_Pastes, estiloTexto)
     story.append(titInfoPastes)
     story.append(textPASTES)

     #MISMA IP
     titDominiosIP=Paragraph("DOMINIOS EN LA MISMA IP", titulos)
     textDominiosIP=Paragraph(RP_Dominios, estiloTexto)
     story.append(titDominiosIP)
     story.append(textDominiosIP)

     #SUBDOMINIOS
     titSubdominios=Paragraph("SUBDOMINIOS", titulos)
     textSubdominios=Paragraph(RP_Subdominios, estiloTexto)
     story.append(titSubdominios)
     story.append(textSubdominios)

     #Enlaces encontrados
     urlEnlaces = 'https://api.hackertarget.com/pagelinks/?q=https://www.' + RP_Dominio
     rEnlaces = requests.get(urlEnlaces)
     if rEnlaces.status_code != 200:
          print("algo salio mal")
     if rEnlaces.status_code == 200:
          enlaces=(rEnlaces.content)

          titEnlaces=Paragraph("ENLACES ENCONTRADOS", titulos)
          textEnlaces=Paragraph(enlaces, estiloTexto)
          story.append(titEnlaces)
          story.append(textEnlaces)

     # PIE
     corte = Paragraph("\n\n\n\n", estiloTexto)
     pie = Paragraph("Cerebro v1.0 - 2019 - Jerson Moises Garciaguirre Moreira", estiloTexto)
     story.append(corte)
     story.append(pie)

     story.append(Spacer(0,20))

     doc=SimpleDocTemplate(nombredoc, pagesize=A4, showBoundary=0, leftMargin=30, rightMargin=20, topMargin=30, bottomMargin=20, title="Reporte de Inteligencia")
     doc.build(story)
     os.system(nombredoc)

#------------------------------------------------------------------------------------------------------------------------------
btnEnti=Button(lblFramEnti2, text="Buscar", command=busquedas)
btnEnti.config(bg="#ff8b00", bd=0, activebackground="#1cb3c8", activeforeground="#ffffff", font=20)
btnEnti.pack(side=LEFT, pady=10, padx=20)

btnEntiPrint=Button(lblFramEnti2, text="Reporte", command=generarReporte)
btnEntiPrint.config(bg="#cc0000", bd=0, activebackground="#1cb3c8", activeforeground="#ffffff", font=20)
btnEntiPrint.pack(side=LEFT, pady=10, padx=20)

# frame de las opciones
lblFramEnti = LabelFrame(pstEnt)
lblFramEnti.config(bg="#ffffff", bd=0)
lblFramEnti.pack(expand=1, fill="both")

# COLUMNA1
lblGeneralidades = Label(lblFramEnti, text="GENERALIDADES")
lblGeneralidades.config(bg="#e8e8e8", font=('', 10, 'bold'))
lblGeneralidades.grid(column=0, row=0, sticky=W+E+N+S, pady=5, padx=5, rowspan=1, columnspan=2)

lblURL = Label(lblFramEnti, text="URL:")
lblURL.config(bg="#ffffff", font=('', 10, 'bold'))
lblURL.grid(column=0, row=1, sticky='W', pady=5, padx=5)
boxURL = Entry(lblFramEnti)
boxURL.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxURL.grid(column=1, row=1, sticky="ew")

lblIp = Label(lblFramEnti, text="IP:")
lblIp.config(bg="#ffffff", font=('', 10, 'bold'))
lblIp.grid(column=0, row=2, sticky='W', pady=5, padx=5)
boxIP = Entry(lblFramEnti)
boxIP.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxIP.grid(column=1, row=2, sticky="ew")

lblCategoria = Label(lblFramEnti, text="Categoria:")
lblCategoria.config(bg="#ffffff", font=('', 10, 'bold'))
lblCategoria.grid(column=0, row=3, sticky='W', pady=5, padx=5)
boxCategoria = Entry(lblFramEnti)
boxCategoria.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxCategoria.grid(column=1, row=3, sticky="ew")

lblReputacion = Label(lblFramEnti, text="Reputacion:")
lblReputacion.config(bg="#ffffff", font=('', 10, 'bold'))
lblReputacion.grid(column=0, row=4, sticky='W', pady=5, padx=5)
boxReputacion = Entry(lblFramEnti)
boxReputacion.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxReputacion.grid(column=1, row=4, sticky="ew")

lblActualizado = Label(lblFramEnti, text="Actualizado:")
lblActualizado.config(bg="#ffffff", font=('', 10, 'bold'))
lblActualizado.grid(column=0, row=5, sticky='W', pady=5, padx=5)
boxActualizado = Entry(lblFramEnti)
boxActualizado.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxActualizado.grid(column=1, row=5, sticky="ew")

lblOrganizacion = Label(lblFramEnti, text="Organizacion:")
lblOrganizacion.config(bg="#ffffff", font=('', 10, 'bold'))
lblOrganizacion.grid(column=0, row=6, sticky='W', pady=5, padx=5)
boxOrganizacion = Entry(lblFramEnti)
boxOrganizacion.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxOrganizacion.grid(column=1, row=6, sticky="ew")

lblSeguridad = Label(lblFramEnti, text="SEGURIDAD")
lblSeguridad.config(bg="#e8e8e8", font=('', 10, 'bold'))
lblSeguridad.grid(column=0, row=7, sticky=W+E+N+S, pady=5, padx=5, rowspan=1, columnspan=2)

lblPuertos = Label(lblFramEnti, text="Puertos:")
lblPuertos.config(bg="#ffffff", font=('', 10, 'bold'))
lblPuertos.grid(column=0, row=8, sticky='W', pady=5, padx=5)
boxPuertos = Entry(lblFramEnti)
boxPuertos.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxPuertos.grid(column=1, row=8, sticky="ew")

lblAntivirus = Label(lblFramEnti, text="Antivirus usados:")
lblAntivirus.config(bg="#ffffff", font=('', 10, 'bold'))
lblAntivirus.grid(column=0, row=9, sticky='W', pady=5, padx=5)
boxAntivirus = Entry(lblFramEnti)
boxAntivirus.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxAntivirus.grid(column=1, row=9, sticky="ew")

lblPositivos = Label(lblFramEnti, text="Positivos:")
lblPositivos.config(bg="#ffffff", font=('', 10, 'bold'))
lblPositivos.grid(column=0, row=10, sticky='W', pady=5, padx=5)
boxPositivos = Entry(lblFramEnti)
boxPositivos.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxPositivos.grid(column=1, row=10, sticky="ew")

lblFechaEscaneo = Label(lblFramEnti, text="Fecha Escaneo:")
lblFechaEscaneo.config(bg="#ffffff", font=('', 10, 'bold'))
lblFechaEscaneo.grid(column=0, row=11, sticky='W', pady=5, padx=5)
boxFechaEscaneo = Entry(lblFramEnti)
boxFechaEscaneo.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxFechaEscaneo.grid(column=1, row=11, sticky="ew")

lblEnlaceEscaneo= Label(lblFramEnti, text="Enlace Escaneo:")
lblEnlaceEscaneo.config(bg="#ffffff", font=('', 10, 'bold'))
lblEnlaceEscaneo.grid(column=0, row=12, sticky='W', pady=5, padx=5)
boxEnlaceEscaneo = Entry(lblFramEnti)
boxEnlaceEscaneo.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxEnlaceEscaneo.grid(column=1, row=12, sticky="ew")

lblVulnerabilidades = Label(lblFramEnti, text="Vulnerabilidades:")
lblVulnerabilidades.config(bg="#ffffff", font=('', 10, 'bold'))
lblVulnerabilidades.grid(column=0, row=13, sticky='W', pady=5, padx=5)
boxVulnerabilidades = scrolledtext.ScrolledText(lblFramEnti)
boxVulnerabilidades.config(bd=2, foreground="#3c415e", height=1, width=25, relief=GROOVE)
boxVulnerabilidades.grid(column=1, row=13, sticky="ew")

#SEGUNDA COLUMNA
lblLocalizacion = Label(lblFramEnti, text="LOCALIZACION")
lblLocalizacion.config(bg="#e8e8e8", font=('', 10, 'bold'))
lblLocalizacion.grid(column=2, row=0, sticky=W+E+N+S, pady=5, padx=5, rowspan=1, columnspan=2)

lblPais = Label(lblFramEnti, text="Pais:")
lblPais.config(bg="#ffffff", font=('', 10, 'bold'))
lblPais.grid(column=2, row=1, sticky='W', pady=5, padx=5)
boxPais = Entry(lblFramEnti)
boxPais.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxPais.grid(column=3, row=1, sticky="ew")

lblRegion = Label(lblFramEnti, text="Región:")
lblRegion.config(bg="#ffffff", font=('', 10, 'bold'))
lblRegion.grid(column=2, row=2, sticky='W', pady=5, padx=5)
boxRegion = Entry(lblFramEnti)
boxRegion.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxRegion.grid(column=3, row=2, sticky="ew")

lblCiudad = Label(lblFramEnti, text="Ciudad:")
lblCiudad.config(bg="#ffffff", font=('', 10, 'bold'))
lblCiudad.grid(column=2, row=3, sticky='W', pady=5, padx=5)
boxCiudad = Entry(lblFramEnti)
boxCiudad.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxCiudad.grid(column=3, row=3, sticky="ew")

lblCodPais = Label(lblFramEnti, text="Codigo del pais:")
lblCodPais.config(bg="#ffffff", font=('', 10, 'bold'))
lblCodPais.grid(column=2, row=4, sticky='W', pady=5, padx=5)
boxCodPais = Entry(lblFramEnti)
boxCodPais.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxCodPais.grid(column=3, row=4, sticky="ew")

lblCodPostal = Label(lblFramEnti, text="Codigo Postal:")
lblCodPostal.config(bg="#ffffff", font=('', 10, 'bold'))
lblCodPostal.grid(column=2, row=5, sticky='W', pady=5, padx=5)
boxCodPostal = Entry(lblFramEnti)
boxCodPostal.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxCodPostal.grid(column=3, row=5, sticky="ew")

lblLatitud = Label(lblFramEnti, text="Latitud:")
lblLatitud.config(bg="#ffffff", font=('', 10, 'bold'))
lblLatitud.grid(column=2, row=6, sticky='W', pady=5, padx=5)
boxLatitud = Entry(lblFramEnti)
boxLatitud.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxLatitud.grid(column=3, row=6, sticky="ew")

lblLongitud = Label(lblFramEnti, text="Longitud:")
lblLongitud.config(bg="#ffffff", font=('', 10, 'bold'))
lblLongitud.grid(column=2, row=7, sticky='W', pady=5, padx=5)
boxLongitud= Entry(lblFramEnti)
boxLongitud.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxLongitud.grid(column=3, row=7, sticky="ew")

lblZonaHoraria = Label(lblFramEnti, text="Zona Horaria:")
lblZonaHoraria.config(bg="#ffffff", font=('', 10, 'bold'))
lblZonaHoraria.grid(column=2, row=8, sticky='W', pady=5, padx=5)
boxZonaHoraria= Entry(lblFramEnti)
boxZonaHoraria.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxZonaHoraria.grid(column=3, row=8, sticky="ew")

lblSubdominios = Label(lblFramEnti, text="SUBDOMINIOS")
lblSubdominios.config(bg="#e8e8e8", font=('', 10, 'bold'))
lblSubdominios.grid(column=2, row=9, sticky=W+E+N+S, pady=5, padx=5, rowspan=1, columnspan=2)

lblSubdominios1 = Label(lblFramEnti, text="Subdominios:")
lblSubdominios1.config(bg="#ffffff", font=('', 10, 'bold'))
lblSubdominios1.grid(column=2, row=12, sticky='W', pady=5, padx=5)
boxSubdominios = scrolledtext.ScrolledText(lblFramEnti)
boxSubdominios.config(bd=2, foreground="#3c415e", height=9, width=25, relief=GROOVE)
boxSubdominios.grid(column=3, row=10, sticky="ew", rowspan=9, columnspan=1)


# TERCER COLUMNA

lblMailHead = Label(lblFramEnti, text="E-MAIL")
lblMailHead.config(bg="#e8e8e8", font=('', 10, 'bold'))
lblMailHead.grid(column=4, row=0, sticky=W+E+N+S, pady=5, padx=5, rowspan=1, columnspan=2)

lblPatronCorreo = Label(lblFramEnti, text="Patron:")
lblPatronCorreo.config(bg="#ffffff", font=('', 10, 'bold'))
lblPatronCorreo.grid(column=4, row=1, sticky='W', pady=5, padx=5)
boxPatronCorreo = Entry(lblFramEnti)
boxPatronCorreo.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxPatronCorreo.grid(column=5, row=1, sticky="ew")

lblDisposable = Label(lblFramEnti, text="Disposable:")
lblDisposable.config(bg="#ffffff", font=('', 10, 'bold'))
lblDisposable.grid(column=4, row=2, sticky='W', pady=5, padx=5)
boxDisposable = Entry(lblFramEnti)
boxDisposable.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxDisposable.grid(column=5, row=2, sticky="ew")

lblWebmail = Label(lblFramEnti, text="Webmail:")
lblWebmail.config(bg="#ffffff", font=('', 10, 'bold'))
lblWebmail.grid(column=4, row=3, sticky='W', pady=5, padx=5)
boxWebmail = Entry(lblFramEnti)
boxWebmail.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxWebmail.grid(column=5, row=3, sticky="ew")

lblWebmail = Label(lblFramEnti, text="Webmail:")
lblWebmail.config(bg="#ffffff", font=('', 10, 'bold'))
lblWebmail.grid(column=4, row=3, sticky='W', pady=5, padx=5)
boxWebmail = Entry(lblFramEnti)
boxWebmail.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxWebmail.grid(column=5, row=3, sticky="ew")

lblMails = Label(lblFramEnti, text="Emails:")
lblMails.config(bg="#ffffff", font=('', 10, 'bold'))
lblMails.grid(column=4, row=5, sticky='W', pady=5, padx=5)
boxMails = scrolledtext.ScrolledText(lblFramEnti)
boxMails.config(bd=2, foreground="#3c415e", height=5, width=25, relief=GROOVE)
boxMails.grid(column=5, row=3, sticky="ew", rowspan=5, columnspan=1)

lblPastes1 = Label(lblFramEnti, text="PASTES")
lblPastes1.config(bg="#e8e8e8", font=('', 10, 'bold'))
lblPastes1.grid(column=4, row=7, sticky=W+E+N+S, pady=5, padx=5, rowspan=1, columnspan=2)

lblPastes = Label(lblFramEnti, text="Pastes:")
lblPastes.config(bg="#ffffff", font=('', 10, 'bold'))
lblPastes.grid(column=4, row=9, sticky='W', pady=5, padx=5)
boxPastes = scrolledtext.ScrolledText(lblFramEnti)
boxPastes.config(bd=2, foreground="#3c415e", height=5, width=25, relief=GROOVE)
boxPastes.grid(column=5, row=7, sticky="ew",rowspan=5, columnspan=1)

lblHOST = Label(lblFramEnti, text="HOST INFO")
lblHOST.config(bg="#e8e8e8", font=('', 10, 'bold'))
lblHOST.grid(column=4, row=11, sticky=W+E+N+S, pady=5, padx=5, rowspan=1, columnspan=2)

lblSO = Label(lblFramEnti, text="S.O:")
lblSO.config(bg="#ffffff", font=('', 10, 'bold'))
lblSO.grid(column=4, row=12, sticky='W', pady=5, padx=5)
boxSO = Entry(lblFramEnti)
boxSO.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxSO.grid(column=5, row=12, sticky="ew")

lblHeaders = Label(lblFramEnti, text="Headers:")
lblHeaders.config(bg="#ffffff", font=('', 10, 'bold'))
lblHeaders.grid(column=4, row=13, sticky='W', pady=5, padx=5)
boxHeaders = scrolledtext.ScrolledText(lblFramEnti)
boxHeaders.config(bd=2, foreground="#3c415e", height=3, width=25, relief=GROOVE)
boxHeaders.grid(column=5, row=13, sticky="ew")


#CUARTA COLUMNA
lblRedInfo = Label(lblFramEnti, text="RED INFO")
lblRedInfo.config(bg="#e8e8e8", font=('', 10, 'bold'))
lblRedInfo.grid(column=6, row=0, sticky=W+E+N+S, pady=5, padx=5, rowspan=1, columnspan=2)

lblAS = Label(lblFramEnti, text="AS:")
lblAS.config(bg="#ffffff", font=('', 10, 'bold'))
lblAS.grid(column=6, row=1, sticky='W', pady=5, padx=5)
boxAS = Entry(lblFramEnti)
boxAS.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxAS.grid(column=7, row=1, sticky="ew")

lblASName = Label(lblFramEnti, text="AS Name:")
lblASName.config(bg="#ffffff", font=('', 10, 'bold'))
lblASName.grid(column=6, row=2, sticky='W', pady=5, padx=5)
boxASName = Entry(lblFramEnti)
boxASName.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxASName.grid(column=7, row=2, sticky="ew")

lblHostname = Label(lblFramEnti, text="Hostname:")
lblHostname.config(bg="#ffffff", font=('', 10, 'bold'))
lblHostname.grid(column=6, row=3, sticky='W', pady=5, padx=5)
boxHostname = Entry(lblFramEnti)
boxHostname.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxHostname.grid(column=7, row=3, sticky="ew")

lblISP = Label(lblFramEnti, text="ISP:")
lblISP.config(bg="#ffffff", font=('', 10, 'bold'))
lblISP.grid(column=6, row=4, sticky='W', pady=5, padx=5)
boxISP = Entry(lblFramEnti)
boxISP.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxISP.grid(column=7, row=4, sticky="ew")

lblBGP = Label(lblFramEnti, text="BGP route:")
lblBGP.config(bg="#ffffff", font=('', 10, 'bold'))
lblBGP.grid(column=6, row=5, sticky='W', pady=5, padx=5)
boxBGP = Entry(lblFramEnti)
boxBGP.config(bd=2, foreground="#3c415e", relief=GROOVE)
boxBGP.grid(column=7, row=5, sticky="ew")

lblWHOIS1 = Label(lblFramEnti, text="WHOIS INFO")
lblWHOIS1.config(bg="#e8e8e8", font=('', 10, 'bold'))
lblWHOIS1.grid(column=6, row=6, sticky=W+E+N+S, pady=5, padx=5, rowspan=1, columnspan=2)

lblWHOIS = Label(lblFramEnti, text="WHOIS:")
lblWHOIS.config(bg="#ffffff", font=('', 10, 'bold'))
lblWHOIS.grid(column=6, row=7,sticky='W', pady=5, padx=5)
boxWHOIS = scrolledtext.ScrolledText(lblFramEnti)
boxWHOIS.config(bd=2, foreground="#3c415e", height=3, width=25, relief=GROOVE)
boxWHOIS.grid(column=7, row=7, sticky="ew", rowspan=2, columnspan=1)

lblDNS = Label(lblFramEnti, text="DNS INFO")
lblDNS.config(bg="#e8e8e8", font=('', 10, 'bold'))
lblDNS.grid(column=6, row=9, sticky=W+E+N+S, pady=5, padx=5, rowspan=1, columnspan=2)

lblDNSInfo = Label(lblFramEnti, text="DNS Info:")
lblDNSInfo.config(bg="#ffffff", font=('', 10, 'bold'))
lblDNSInfo.grid(column=6, row=10, sticky='W', pady=5, padx=5)
boxDNSInfo = scrolledtext.ScrolledText(lblFramEnti)
boxDNSInfo.config(bd=2, foreground="#3c415e", height=3, width=25, relief=GROOVE)
boxDNSInfo.grid(column=7, row=10, sticky="ew", rowspan=2, columnspan=1)

lblSameIP = Label(lblFramEnti, text="SAME IP")
lblSameIP.config(bg="#e8e8e8", font=('', 10, 'bold'))
lblSameIP.grid(column=6, row=12, sticky=W+E+N+S, pady=5, padx=5, rowspan=1, columnspan=2)

lblDominios = Label(lblFramEnti, text="Dominios:")
lblDominios.config(bg="#ffffff", font=('', 10, 'bold'))
lblDominios.grid(column=6, row=13, sticky='W', pady=5, padx=5)
boxDominios = scrolledtext.ScrolledText(lblFramEnti)
boxDominios.config(bd=2, foreground="#3c415e", height=1, width=25, relief=GROOVE)
boxDominios.grid(column=7, row=13, sticky="ew", rowspan=2, columnspan=1)

#PESTAÑA DE GOOGLE HACKING------------------------------------------------------------
#titulo
lblFramGH1 = LabelFrame(pstGH)
lblFramGH1.config(bg="#e8e8e8", bd=0)
lblFramGH1.pack(fill="x")

lblGH1 = Label(lblFramGH1, text = "GOOGLE HACKING", font=12)
lblGH1.config(foreground="#913535", bg="#e8e8e8")
lblGH1.pack(pady=20, padx=5, side=LEFT)



#frame de las opciones
lblFramGH = LabelFrame(pstGH)
lblFramGH.config(bg="#ffffff", bd=0)
lblFramGH.pack(expand=1, fill="both")

#busqueda
lblBusquedaGH = Label(lblFramGH, text = "Busqueda:")
lblBusquedaGH.config(bg="#ffffff",font=('', 12, 'bold'))
lblBusquedaGH.grid(column = 0, row = 1, sticky='W', pady=10, padx=5)
boxBusquedaGH = Entry(lblFramGH)
boxBusquedaGH.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=25)
boxBusquedaGH.grid(column = 1, row = 1,sticky="ew")

#palabras exactas
lblPexactasGH = Label(lblFramGH, text = "Palabras exactas:")
lblPexactasGH.config(bg="#ffffff",font=('', 12, 'bold'))
lblPexactasGH.grid(column = 0, row = 2, sticky='W', pady=10, padx=5)
boxPexactasGH = Entry(lblFramGH)
boxPexactasGH.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=25)
boxPexactasGH.grid(column = 1, row = 2,sticky="ew")

#exceptuar palabras
lblPexceptuaGH = Label(lblFramGH, text = "Excepciones:")
lblPexceptuaGH.config(bg="#ffffff",font=('', 12, 'bold'))
lblPexceptuaGH.grid(column = 0, row = 3, sticky='W', pady=10, padx=5)
boxPexceptuaGH = Entry(lblFramGH)
boxPexceptuaGH.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=25)
boxPexceptuaGH.grid(column = 1, row = 3,sticky="ew")

#OPCIONES DE intitle, inul,intext,inanchor        
donde = StringVar(lblFramGH)
donde.set("Cualquier lugar") # initial value
lblDondeGH = Label(lblFramGH, text = "Donde Buscar:")
lblDondeGH.config(bg="#ffffff",font=('', 12, 'bold'))
lblDondeGH.grid(column = 2, row = 1, sticky='W', pady=5, padx=5) 
optDonde = OptionMenu(lblFramGH, donde, "Cualquier lugar", "En titulos", "En texto", "En dirección web", "En enlaces")
optDonde.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=27)
optDonde.grid(column = 3, row = 1,sticky="ew")

#ultima actualizacion   
ultima = StringVar(lblFramGH)
ultima.set("Cualquier fecha") # initial value
lblUltimaGH = Label(lblFramGH, text = "Ultima Actualización:")
lblUltimaGH.config(bg="#ffffff",font=('', 12, 'bold'))
lblUltimaGH.grid(column = 2, row = 2, sticky='W', pady=5, padx=5) 
optUltima = OptionMenu(lblFramGH, ultima, "Cualquier fecha", "Última hora", "Último día", "Última semana", "Último mes", "Último año")
optUltima.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=27)
optUltima.grid(column = 3, row = 2,sticky="ew")

#TIPO DE ARCHIVO   
lblTypeFileGH = Label(lblFramGH, text = "Tipo de Archivo:")
lblTypeFileGH.config(bg="#ffffff",font=('', 12, 'bold'))
lblTypeFileGH.grid(column = 2, row = 3, sticky='W', pady=5, padx=5)       
boxTypeFileGH = Entry(lblFramGH)
boxTypeFileGH.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=27)
boxTypeFileGH.grid(column = 3, row = 3,sticky="ew")

#dominio
lblDominioGH = Label(lblFramGH, text = "Sitio:")
lblDominioGH.config(bg="#ffffff",font=('', 12, 'bold'))
lblDominioGH.grid(column = 5, row = 1, sticky='W', pady=5, padx=5)       
boxDominioGH = Entry(lblFramGH)
boxDominioGH.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=25)
boxDominioGH.grid(column = 6, row = 1,sticky="ew")

#Rango
lblDesdeGH = Label(lblFramGH, text = "Desde:")
lblDesdeGH.config(bg="#ffffff",font=('', 12, 'bold'))
lblDesdeGH.grid(column = 5, row = 2, sticky='W', pady=5, padx=5)
boxDesdeGH = Entry(lblFramGH)
boxDesdeGH.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=25)
boxDesdeGH.grid(column = 6, row = 2, sticky="ew")
lblHastaGH = Label(lblFramGH, text = "Hasta:")
lblHastaGH.config(bg="#ffffff",font=('', 12, 'bold'))
lblHastaGH.grid(column = 5, row = 3, sticky='W', pady=5, padx=5)
boxHastaGH = Entry(lblFramGH)
boxHastaGH.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=25)
boxHastaGH.grid(column = 6, row = 3, sticky="ew")

def buscarGH():
     buscador="https://www.google.com/search?"
     busqueda=boxBusquedaGH.get()
     busquedaExacta=boxPexactasGH.get()
     palabraExcepcion=boxPexceptuaGH.get()
     rangoDesde=boxDesdeGH.get()
     rangoHasta=boxHastaGH.get()
     dominio=boxDominioGH.get()
     ultimaActualizacion=ultima.get()
     if ultimaActualizacion=="Cualquier fecha":
          ultimaActualizacion="all"
     if ultimaActualizacion=="Última hora":
          ultimaActualizacion="h"
     if ultimaActualizacion=="Último día":
          ultimaActualizacion="d"
     if ultimaActualizacion=="Última semana":
          ultimaActualizacion="w"
     if ultimaActualizacion=="Último mes":
          ultimaActualizacion="m"
     if ultimaActualizacion=="Último año":
          ultimaActualizacion="y"
           
     intittle=donde.get()
     if intittle=="Cualquier lugar":
          intittle="any"
     if intittle=="En titulos":
          intittle="title"
     if intittle=="En texto":
           intittle="body"
     if intittle=="En dirección web":
           intittle="url"
     if intittle=="En enlaces":
           intittle="links"
     tipoArchivo=boxTypeFileGH.get()
     queryBusqueda=buscador+"q="+busqueda+"&as_epq="+busquedaExacta+"&as_eq="+palabraExcepcion+"&as_nlo="+rangoDesde+"&as_nhi="+rangoHasta+"&as_qdr="+ultimaActualizacion+"&as_sitesearch="+dominio+"&as_occt="+intittle+"&as_filetype="+tipoArchivo
     webbrowser.open_new(queryBusqueda)

#boton buscar
btnGH=Button(lblFramGH, text="Buscar",command=buscarGH)
btnGH.config(bg="#ff8b00", bd=0, activebackground="#1cb3c8", activeforeground="#ffffff", font=20)
btnGH.grid(column = 3, row = 5, sticky='W', pady=20)

#PESTAÑA DE AJUSTES------------------------------------------------------------
#titulo
lblFramSet = LabelFrame(pstConf)
lblFramSet.config(bg="#e8e8e8", bd=0)
lblFramSet.pack(fill="x")

lblGH1 = Label(lblFramSet, text = "AJUSTES E INFORMACION", font=12)
lblGH1.config(foreground="#913535", bg="#e8e8e8")
lblGH1.pack(pady=20, padx=5, side=LEFT)

#frame de las opciones
lblFramSet2 = LabelFrame(pstConf)
lblFramSet2.config(bg="#ffffff", bd=0)
lblFramSet2.pack(expand=1, fill="both")

lblConf = Label(lblFramSet2, text = "Configuracion de API")
lblConf.config(bg="#e8e8e8",font=('', 12, 'bold'))
lblConf.grid(column = 0, row = 0, sticky=W+E+N+S, pady=5, padx=5, rowspan=1, columnspan=2)

lblAPIHunter = Label(lblFramSet2, text = "API hunter.io:")
lblAPIHunter.config(bg="#ffffff",font=('', 12, 'bold'))
lblAPIHunter.grid(column = 0, row = 2, sticky='W', pady=5, padx=5)
boxAPIHunter = Entry(lblFramSet2)
boxAPIHunter.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=40)
boxAPIHunter.grid(column = 1, row = 2,sticky="ew")
boxAPIHunter.insert(INSERT, apiHunter)

lblAPIShodan = Label(lblFramSet2, text = "API shodan.io:")
lblAPIShodan.config(bg="#ffffff",font=('', 12, 'bold'))
lblAPIShodan.grid(column = 0, row = 3, sticky='W', pady=5, padx=5)
boxAPIShodan = Entry(lblFramSet2)
boxAPIShodan.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=40)
boxAPIShodan.grid(column = 1, row = 3,sticky="ew")
boxAPIShodan.insert(INSERT, apiShodan)

lblIpnfodb = Label(lblFramSet2, text = "API IPInfoDB:")
lblIpnfodb.config(bg="#ffffff",font=('', 12, 'bold'))
lblIpnfodb.grid(column = 0, row = 4, sticky='W', pady=5, padx=5)
boxIpnfodb = Entry(lblFramSet2)
boxIpnfodb.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=40)
boxIpnfodb.grid(column = 1, row = 4,sticky="ew")
boxIpnfodb.insert(INSERT, apiIpnfodb)

lblVirusTotal = Label(lblFramSet2, text = "API Virus Total:")
lblVirusTotal.config(bg="#ffffff",font=('', 12, 'bold'))
lblVirusTotal.grid(column = 0, row = 5, sticky='W', pady=5, padx=5)
boxVirusTotal = Entry(lblFramSet2)
boxVirusTotal.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=40)
boxVirusTotal.grid(column = 1, row = 5,sticky="ew")
boxVirusTotal.insert(INSERT, apiVirusTotal)

lblSpy = Label(lblFramSet2, text = "TOKEN Spy:")
lblSpy.config(bg="#ffffff",font=('', 12, 'bold'))
lblSpy.grid(column = 0, row = 6, sticky='W', pady=5, padx=5)
boxSpy = Entry(lblFramSet2)
boxSpy.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=40)
boxSpy.grid(column = 1, row = 6,sticky="ew")
boxSpy.insert(INSERT, tokenSpy)

lblBing = Label(lblFramSet2, text = "API Bing:")
lblBing.config(bg="#ffffff",font=('', 12, 'bold'))
lblBing.grid(column = 0, row = 7, sticky='W', pady=5, padx=5)
boxBing = Entry(lblFramSet2)
boxBing.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=40)
boxBing.grid(column = 1, row = 7,sticky="ew")
boxBing.insert(INSERT, apiBing)

lblHibp = Label(lblFramSet2, text = "API HIBP:")
lblHibp.config(bg="#ffffff",font=('', 12, 'bold'))
lblHibp.grid(column = 0, row = 8, sticky='W', pady=5, padx=5)
boxHibp = Entry(lblFramSet2)
boxHibp.config(bd=2, foreground="#3c415e", bg="#feffdb", relief=GROOVE, font=12, width=40)
boxHibp.grid(column = 1, row = 8,sticky="ew")
boxHibp.insert(INSERT, apiHIBP)

def cambiarApi():
    inApiHunter= boxAPIHunter.get()
    inApiShodan = boxAPIShodan.get()
    inApiIpInfodb = boxIpnfodb.get()
    inApiVirusTotal = boxVirusTotal.get()
    inTokenSpy = boxSpy.get()
    inApiBing = boxBing.get()
    inApiHIBP = boxHibp.get()

    linea1='[APIKeys]'
    linea2 = 'apiHunter='+inApiHunter
    linea3 = 'apiShodan='+inApiShodan
    linea4 = 'apiIpnfodb='+inApiIpInfodb
    linea5 = 'apiVirusTotal='+inApiVirusTotal
    linea6 = 'tokenSpy='+inTokenSpy
    linea7 = 'apiBing='+inApiBing
    linea8 = 'apiHIBP='+inApiHIBP
    archivo = open('Configuraciones.txt','w')
    archivo.write(linea1+'\n'+linea2 + '\n'+ linea3 + '\n'+ linea4 + '\n' + linea5 + '\n' + linea6 + '\n' + linea7 + '\n' + linea8 + '\n')

btnMail=Button(lblFramSet2, text="Guardar", command=cambiarApi)
btnMail.config(bg="#ff8b00", bd=0, activebackground="#1cb3c8", activeforeground="#ffffff", font=20)
btnMail.grid(column = 1, row = 9, sticky="w", pady=20)

lblInf = Label(lblFramSet2, text = "INFORMACION")
lblInf.config(bg="#e8e8e8",font=('', 12, 'bold'))
lblInf.grid(column = 3, row = 0, sticky=W+E+N+S, pady=5, padx=25, rowspan=1)

lblDescripcion=Label(lblFramSet2, text="CEREBRO v1.0, es un proyecto orientado\na la obtención de información usando herramientas de\nOpen Source Intelligence desarrollado por\nJerson Moises Garciaguirre Moreira")
lblDescripcion.config(bg="#ffffff",font=('', 12, ''))
lblDescripcion.grid(column = 3, row = 1, sticky=W+E+N+S, pady=5, padx=25, rowspan=3)

def abrirManual():
     os.system("manual_cerebro.pdf")

btnManual=Button(lblFramSet2, text="->Manual de uso<-", command=abrirManual)
btnManual.config(bg="#ff8b00", bd=0, activebackground="#1cb3c8", activeforeground="#ffffff", font=20)
btnManual.grid(column = 3, row = 5, sticky=W+E+N+S,padx=25, rowspan=1)



ventPcpal.mainloop()
