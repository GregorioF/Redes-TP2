from scapy.all import *
import json
import numpy 

echoRequest = 8

timeExceed = 11

results = 0

mensajeEnviado = 0

mensajeRecibido = 1

modifiedThompsonT = {'3': 1.1511, '4':1.4250,'5':1.5712,'6':1.6563,'7':1.7110,'8':1.7491,'9':1.7770,'10':1.7984,'11':1.8153,'12':1.8290,'13':1.8403,'14':1.8498,'15':1.8579,'16':1.8649,'17':1.8710,'18':1.8764,'19':1.8811,'20':1.8853,'21':1.8891,'22':1.8926,'23':1.8957,'24':1.8985,'25':1.9011,'26':1.9035,'27':1.9057,'28':1.9078,'29':1.9096,'30':1.9114,'31':1.9130,'32':1.9146,'33':1.9160,'34':1.9174,'35':1.9186,'36':1.9198,'37':1.9209,'38':1.9220,'39':1.9230,'40':1.9240,'42':1.9257,'44':1.9273,'46':1.9288,'48':1.9301,'50':1.9314,'52':1.9325,'54':1.9335,'56':1.9345,'58':1.9354,'60':1.9362,'65':1.9381,'70':1.9397,'75':1.9411,'80':1.9423,'90':1.9443,'100':1.9459,'150':1.9506,'200':1.9530,'500':1.9572}

def ParseToModfiedThompsonIndex(n):
	if n >= 3 and n <= 40 : return n 
	if n >= 41 and n <= 60: return n - n%2
	if n >= 61 and n <= 80: return n - n%5
	if n >= 81 and n <= 100: return n - n%10
	if n >= 101 and n<= 200 : return n - n%50
	if n > 200 : return 200

def EsOutLayer(candidato, n, desvStandard):
	if n < 3 : return False

	n = ParseToModfiedThompsonIndex(n)
	return modifiedThompsonT[str(n)] * desvStandard < candidato


def RttPromedio(response):
	n = len(response[results])
	res = 0 
	for r in response[results]:
		res += ( r[mensajeRecibido][IP].time - r[mensajeEnviado][IP].sent_time)/n

	return res


def CincoPaquetesDeTipoEchoRequest(dst, ttl):
	packetesAEnviar = [] 
	for x in range(5):
		packetesAEnviar.append(IP(dst = dst, ttl = ttl) / ICMP( type = echoRequest))
	return packetesAEnviar


def TraceRouteConOutlayers(ipDst = "", url = ""):
	dst = url if ipDst == "" else ipDst
	ttl =  600

	res = sr(CincoPaquetesDeTipoEchoRequest(dst, ttl), timeout = 10)
 
	caminoRecorrido = []

	rutaMasProbableASeguir = []

	ultimoRtt = 0 

	while len(res[results]) == 0 or res[results][0][mensajeRecibido][ICMP].type == timeExceed :
		print ttl

		if(len(res[results]) == 0):
			caminoRecorrido.append({'rtt': -1, 'ip_adress': '0.0.0.0', 'salto_intercontinental': False, 'hop_num': ttl})
			ttl += 1
			res =sr(CincoPaquetesDeTipoEchoRequest(dst, ttl), timeout = 2)
	
		else:

			ipDevueltos = {}
			for r in res[results]:
				if r[mensajeRecibido][IP].src in ipDevueltos.keys():
					ipDevueltos[r[mensajeRecibido][IP].src] += 1
				else:
					ipDevueltos[r[mensajeRecibido][IP].src] = 1

			ipMasProbable = next(iter(ipDevueltos))

			for ip in ipDevueltos :
				if ipDevueltos[ip] > ipDevueltos[ipMasProbable] :
					ipMasProbable = ip


			rttPromedio = RttPromedio(res)
			caminoRecorrido.append({'rtt': rttPromedio - ultimoRtt, 'ip_adress': ipMasProbable, 'salto_intercontinental': False, 'hop_num': ttl})
			ultimoRtt = rttPromedio
			ttl += 1
			res =sr(CincoPaquetesDeTipoEchoRequest(dst, ttl), timeout = 2)
	


	caminoRecorrido.append({'rtt': RttPromedio(res) - ultimoRtt, 'ip_adress': dst, 'salto_intercontinental': False, 'hop_num': ttl})

	res = [[]]


	print "\n"
	print "\n"

	enlacesRegionales = caminoRecorrido[:]
	


	hayQueBuscarOutLayer = True
	while hayQueBuscarOutLayer :

		tiemposRespuestas =  []
		for c in enlacesRegionales :
			tiemposRespuestas.append(c['rtt'])
		medianaRtt = numpy.mean(tiemposRespuestas)
		desvStandard = numpy.std(tiemposRespuestas)

		candidatoASerOutLayer = {'ip_adress': '11', 'rtt': 0} 


		for c in enlacesRegionales:
			candidatoASerOutLayer = candidatoASerOutLayer if candidatoASerOutLayer['rtt'] > abs(c['rtt']-medianaRtt) else  c 

		esOutLayer = EsOutLayer(candidatoASerOutLayer['rtt'], len(tiemposRespuestas), desvStandard)

		if esOutLayer :
			for x in caminoRecorrido:
				if x['ip_adress'] == candidatoASerOutLayer['ip_adress']:
					x['salto_intercontinental'] = True

			enlacesRegionales.remove(candidatoASerOutLayer)

		hayQueBuscarOutLayer = esOutLayer




	for x in caminoRecorrido:
		print json.dumps(x)





#TraceRouteConOutlayers(ipDst = '188.42.141.244')
TraceRouteConOutlayers(url = 'www.facebook.com')
