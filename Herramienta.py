from scapy.all import *
import json
import numpy 

echoRequest = 8

timeExceed = 11

results = 0

mensajeEnviado = 0

mensajeRecibido = 1

modifiedThompsonT = {'3': 1.1511, '4':1.4250,'5':1.5712,'6':1.6563,'7':1.7110,'8':1.7491,'9':1.7770,'10':1.7984,'11':1.8153,'12':1.8290,'13':1.8403,'14':1.8498,'15':1.8579,'16':1.8649,'17':1.8710,'18':1.8764,'19':1.8811,'20':1.8853,'21':1.8891,'22':1.8926,'23':1.8957,'24':1.8985,'25':1.9011,'26':1.9035,'27':1.9057,'28':1.9078,'29':1.9096,'30':1.9114,'31':1.9130,'32':1.9146,'33':1.9160,'34':1.9174,'35':1.9186,'36':1.9198,'37':1.9209,'38':1.9220,'39':1.9230,'40':1.9240,'42':1.9257,'44':1.9273,'46':1.9288,'48':1.9301,'50':1.9314,'52':1.9325,'54':1.9335,'56':1.9345,'58':1.9354,'60':1.9362,'65':1.9381,'70':1.9397,'75':1.9411,'80':1.9423,'90':1.9443,'100':1.9459,'150':1.9506,'200':1.9530,'500':1.9572}


def avg (rtt1, rtt2,rtt3):
	return (rtt1 + rtt2 + rtt3) / 3

def TomarRttPromedio(res):
	return avg  (res[results][0][mensajeRecibido][IP].time - res[results][0][mensajeEnviado][IP].sent_time, 
						res[results][1][mensajeRecibido][IP].time - res[results][1][mensajeEnviado][IP].sent_time, 
						res[results][2][mensajeRecibido][IP].time - res[results][2][mensajeEnviado][IP].sent_time)


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
	print "VER SI ES INTERCONTINENTAL : " + str( modifiedThompsonT[str(n)] * desvStandard )+ " , " + str(candidato)

	return modifiedThompsonT[str(n)] * desvStandard < candidato



def TraceRouteConOutlayers(ipDst = "", url = ""):
	dst = url if ipDst == "" else ipDst
	ttl = 1

	packet1 = IP(dst = dst, ttl = ttl) / ICMP( type = echoRequest)
	packet2 = IP(dst = dst, ttl = ttl) / ICMP( type = echoRequest)
	packet3 = IP(dst = dst, ttl = ttl) / ICMP( type = echoRequest)


	res = sr([packet1,packet2,packet3])
 
	caminoRecorrido = []

	while res[results][0][mensajeRecibido][ICMP].type == timeExceed :

		rttPromedio = TomarRttPromedio(res)

		caminoRecorrido.append({'src' : res[results][0][mensajeRecibido][IP].src, 'rtt' : rttPromedio })

		ttl += 1
		packet1[IP].ttl  = ttl
		packet2[IP].ttl  = ttl
		packet3[IP].ttl  = ttl
		

		res = sr([packet1,packet2,packet3])


	#para tomar el rtt del ultimo mensaje que fue al destino elegido
	rttPromedio = TomarRttPromedio(res)

	caminoRecorrido.append({'src' : res[results][0][mensajeRecibido][IP].src, 'rtt' : rttPromedio })

	for x in caminoRecorrido:
		print json.dumps(x)

	print "\n"
	print "\n"

	enlacesRegionales = caminoRecorrido[:]
	enlacesIntercontinentales = []


	hayQueBuscarOutLayer = True
	while hayQueBuscarOutLayer :

		tiemposRespuestas =  []
		for c in enlacesRegionales :
			tiemposRespuestas.append(c['rtt'])
		medianaRtt = numpy.mean(tiemposRespuestas)
		desvStandard = numpy.std(tiemposRespuestas)

		candidatoASerOutLayer = {'src':0, 'rtt': 0} 


		for c in enlacesRegionales:
			candidatoASerOutLayer = candidatoASerOutLayer if candidatoASerOutLayer['rtt'] > abs(c['rtt']-medianaRtt) else  c 

		esOutLayer = EsOutLayer(candidatoASerOutLayer['rtt'], len(tiemposRespuestas), desvStandard)

		if esOutLayer :
			enlacesIntercontinentales.append(candidatoASerOutLayer)
			enlacesRegionales.remove(candidatoASerOutLayer)

		hayQueBuscarOutLayer = esOutLayer


	print "ENLACES REGIONALES: "
	for x in enlacesRegionales:
		print json.dumps(x)

	print "\n"

	print "ENLACES INTERCONTINENTALES: "
	for x in enlacesIntercontinentales:
		print json.dumps(x)





#TraceRouteConOutlayers(ipDst = '188.42.141.244')
TraceRouteConOutlayers(url = 'google.com')
